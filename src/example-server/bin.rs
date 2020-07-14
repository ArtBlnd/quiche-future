use quiche_future::*;

use async_std::prelude::*;
use async_std::*;
use async_std::sync::{ Mutex, Arc, Sender, Receiver, channel };
use async_std::task::JoinHandle;
use async_std::net::*;

use simplelog::*;
use std::collections::HashMap;

async fn fb_send_req(buf: Option<&[u8]>, req_type: u8, req_uuid: u16, tx: &mut QuicSendStream) {
    let buf_len = match buf {
        Some(v) => v.len(),
        None    => 0,
    };

    let mut payload = Vec::new();
    payload.resize(20 + buf_len, 0xFF);

    payload[0] = req_type;
    payload[1..3].copy_from_slice(&(buf_len as u16).to_le_bytes());
    payload[3..5].copy_from_slice(&req_uuid.to_le_bytes());
    if let Some(data) = buf {
        payload[20..].copy_from_slice(data);
    }

    log::info!("[out] vpn packet type = {}, dlen = {}, uuid = {} / packet len = {}", req_type, buf_len, req_uuid, payload.len());
    tx.write_all(&payload).await.expect("failed to write on stream");
}

async fn vpn_dispatch_s2c(mut socket: TcpStream, mut tx: QuicSendStream, uuid: u16) {
    let mut data_buf = [0u8; 4040];
    while let Ok(sz) = socket.read(&mut data_buf).await {
        if sz == 0 {
            break;
        }

        log::trace!("[server ==> client] sent sz = {} / uuid = {}", sz, uuid);
        fb_send_req(Some(&data_buf[..sz]), 1, uuid, &mut tx).await;
    }

    log::info!("[server ==> client] closed uuid = {}", uuid);
    fb_send_req(None, 2, uuid, &mut tx).await;
}

async fn vpn_dispatch_c2s(mut socket: TcpStream, rx: Receiver<Vec<u8>>, uuid: u16) {
    while let Ok(buf) = rx.recv().await {
        if let Err(e) = socket.write_all(&buf).await {
            log::warn!("failed to write on socket! err = {}", e);
            break;
        }

        log::trace!("[server <== client] recv sz = {} / uuid = {}", buf.len(), uuid);
    }

    log::info!("[server <== client] closed uuid = {}", uuid);
}

async fn vpn_dispatch_session(addr: SocketAddr, mut tx: QuicSendStream, rx: Receiver<Vec<u8>>, uuid: u16) {
    let socket = match TcpStream::connect(addr).await {
        Ok (v) => v,
        Err(_) => {
            // we've failed to connect on session.
            fb_send_req(None, 2, uuid, &mut tx).await;

            log::warn!("connection unreachable! uuid = {} / addr = {}", uuid, &addr);
            return;
        }
    };

    task::spawn(vpn_dispatch_s2c(socket.clone(), tx, uuid));
    vpn_dispatch_c2s(socket, rx, uuid).await;
}


fn fb_extract_type(header :&[u8; 20]) -> u8 {
    header[0]
}

fn fb_extract_dlen(header :&[u8; 20]) -> usize {
    u16::from_le_bytes([header[1], header[2]]) as usize
}

fn fb_extract_uuid(header :&[u8; 20]) -> u16 {
    u16::from_le_bytes([header[3], header[4]])
}

fn fb_extract_addr(header :&[u8; 20]) -> SocketAddr {
    let addr = Ipv4Addr::new(header[5], header[6], header[7], header[8]);
    SocketAddr::new(IpAddr::V4(addr), u16::from_le_bytes([header[0x09], header[0x0A]]))
}

async fn start_vpn_instance(send_stream: QuicSendStream, mut recv_stream: QuicRecvStream) {
    let connections: Arc<Mutex<HashMap<u16, (Sender<Vec<u8>>, JoinHandle<()>)>>> = Default::default();

    let mut header_buf = [0u8; 20];
    while let Ok(_) = recv_stream.read_exact(&mut header_buf).await {
        let mut conn_table = connections.lock().await;

        let fb_type = fb_extract_type(&header_buf);
        let fb_dlen = fb_extract_dlen(&header_buf);
        let fb_addr = fb_extract_addr(&header_buf);
        let fb_uuid = fb_extract_uuid(&header_buf);

        log::info!("[in] vpn packet type = {}, dlen = {}, uuid = {}", fb_type, fb_dlen, fb_uuid);
        
        if fb_type == 1 {
            if !conn_table.contains_key(&fb_uuid) {
                log::info!("created session uuid = {}", fb_uuid);
                let (tx, rx) = channel::<Vec<u8>>(16);

                let handle = task::spawn(vpn_dispatch_session(fb_addr, send_stream.clone(), rx, fb_uuid));
                conn_table.insert(fb_uuid, (tx, handle));
            }

            let mut data_buf: Vec<u8> = Vec::new();
            data_buf.resize(fb_dlen, 0);

            match recv_stream.read_exact(&mut data_buf).await {
                Ok (_) => {
                    let (sender, _) = conn_table.get_mut(&fb_uuid).expect("bad connection table!");
                    sender.send(data_buf).await;
                }
                Err(_) => {
                    log::error!("failed to read from stream!");
                    break;
                }
            }
            
            continue;
        }

        if fb_type == 2 {
            log::info!("closed session uuid = {}", fb_uuid);
            // cancel recv stream.

            if let Some((_, handle)) = conn_table.remove(&fb_uuid) {
                handle.cancel().await;
            }
            continue;
        }

        log::error!("bad fb_type detected! {}", fb_type);
    }

    log::info!("stream closed!");
}

fn main() {
    SimpleLogger::init(LevelFilter::Trace, Config::default())
        .expect("failed to init logger!");

    task::block_on(async {
        let mut conf = ServerConfig::default();
        conf.pl_init_max_bidi_sz = 100_000_000;
        conf.pl_init_max_sz      = 100_000_000;
        conf.pl_init_max_uni_sz  = 100_000_000;

        conf.pl_max_bidi_streams = 1000;
        conf.pl_max_uni_streams  = 1000;

        conf.conn_timeout        = 1000000;
        conf.conn_max_packet_sz  = 1024 * 10;

        conf.conn_alpn           = b"\x06fibers".to_vec();
        conf.ssl_cert_path       = "assets/server.pem".to_string();
        conf.ssl_key_path        = "assets/server.key".to_string();

        let server = establish_server("0.0.0.0:8888".parse().unwrap(), conf).await.unwrap();

        while let Some(mut conn) = server.listen().await {
            task::spawn(async move { 
                let (ss, rs) = match conn.listen_stream().await {
                    Some(v) => v,
                    None    => return
                };

                start_vpn_instance(ss, rs).await;
            });
        }
    });
}