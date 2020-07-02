use crate::*;

use async_std::*;
use async_std::prelude::*;
use async_std::sync::Arc;

use std::net::SocketAddr;
use std::pin::Pin;
use std::collections::{HashMap};
use std::time::Duration;

use anyhow;
use quiche;
use log;

pub struct QuicClient {
    incoming: sync::Receiver<(QuicSendStream, QuicRecvStream)>,
    tx: IoSendSink
}

impl QuicClient {
    pub async fn listen_stream(&mut self) -> (QuicSendStream, QuicRecvStream) {
        let (send_stream, recv_stream) = self.incoming.recv().await.unwrap();
        log::info!("established a new stream (stream_id = {}, listen)", send_stream.stream_id());

        return (send_stream, recv_stream);
    }
    
    pub async fn create_stream(&mut self, strm_id: u64) -> (QuicSendStream, QuicRecvStream) {
        let (rx_sink, rx_strm) = sync::channel::<IoRecvOps>(256);
        self.tx.send(IoSendOps::IoStreamOpen(strm_id, rx_sink)).await;

        log::info!("established a new stream (stream_id = {}, create)", strm_id);
        let send_stream = QuicSendStream {
            stream_id: strm_id,
            send_close: false,
            send_flush: false,
            tx_pending: Mutex::new(HashSet::new()),
            tx: self.tx.clone(), 
        };

        let recv_stream = QuicRecvStream {
            stream_id: strm_id,
            local_storage: None,
            rx: rx_strm
        };

        return (send_stream, recv_stream);
    }
}

struct QuicClientInternal {
    send_closed: bool,
    recv_closed: bool,

    quic_conn: Pin<Box<quiche::Connection>>,
    sock_conn: Arc<net::UdpSocket>, 

    strm_tx: sync::Sender<(QuicSendStream, QuicRecvStream)>,
    strm_table: HashMap<u64, IoRecvSink>,

    tx_sink: IoSendSink,
    tx_strm: IoSendStream,
}


async fn process_client_handshake(internal: &mut QuicClientInternal) -> Result<(), anyhow::Error> {
    while !internal.quic_conn.is_established() {
        let mut buf = [0u8; 4096];

        loop {
            match internal.quic_conn.send(&mut buf) {
                Ok (v)                   => internal.sock_conn.send(&buf[0..v]).await?,
                Err(quiche::Error::Done) => break,
                Err(_)                   => unreachable!(),
            };
        }

        match internal.sock_conn.recv(&mut buf).await {
            Ok (v) => internal.quic_conn.recv(&mut buf[0..v])?,
            Err(_) => unreachable!()
        };
    }

    Ok(())
}

async fn client_process_send(internal: &mut QuicClientInternal, req: IoSendOps) {
    let wk;

    match req { 
        IoSendOps::IoFlush(strm_id, waker) => {
            wk = waker; 
        }

        IoSendOps::IoClose(waker) => {
            wk = waker;

            internal.quic_conn.close(true, 0, b"");
            internal.send_closed = true;
        }

        IoSendOps::IoSend(strm_id, buf, waker) => {
            wk = waker;

            let mut tmp_buf = [0u8; 4096];

            internal.quic_conn.stream_send(strm_id, &buf, false)
                .expect("fatal error! failed to write buffer on bio!");

            log::info!("id = {} : sent {} bytes", strm_id, buf.len());
        }


        IoSendOps::IoStreamOpen(strm_id, sink) => {
            if !internal.strm_table.contains_key(&strm_id) {
                // should not be opend!
            }

            internal.strm_table.insert(strm_id, sink);

            log::info!("id = {} : stream opened", strm_id);
            return;
        }

        IoSendOps::IoStreamFree(strm_id, waker) => { 
            wk = waker;
            internal.quic_conn.stream_shutdown(strm_id, quiche::Shutdown::Write, 0).unwrap();

            log::info!("id = {} : stream closed", strm_id);
        }
    }

    wk.wake();
}

async fn client_process_recv(internal: &mut QuicClientInternal, req: IoRecvOps) {
    match req {
        IoRecvOps::IoRecv(mut buf) => { internal.quic_conn.recv(&mut buf).unwrap(); },
        IoRecvOps::IoEof() => {
            for (_, sender) in &internal.strm_table {
                sender.send(IoRecvOps::IoEof()).await;
            }

            internal.strm_table.clear();
            internal.recv_closed = true;
        }
    }

    assert!(internal.recv_closed, "socket is already closed with EOF!");

    let mut tmp_buf = [0u8; 4096];

    let strm_id_iter = internal.quic_conn.readable();
    for strm_id in strm_id_iter {
        if !internal.strm_table.contains_key(&strm_id) {
            let (rx_sink, rx_strm) = sync::channel::<IoRecvOps>(256);

            let send_stream = QuicSendStream {
                stream_id: strm_id,
                send_close: false,
                send_flush: false,
                tx_pending: Mutex::new(HashSet::new()),
                tx: internal.tx_sink.clone(), 
            };

            let recv_stream = QuicRecvStream {
                stream_id: strm_id,
                local_storage: None,
                rx: rx_strm
            };

            internal.strm_tx.send((send_stream, recv_stream)).await;
            internal.strm_table.insert(strm_id, rx_sink);
        }

        let sink = internal.strm_table.get_mut(&strm_id).unwrap();

        let mut is_fin = false;
        let mut wbuf = Vec::new();
        while let Ok((len, fin)) = internal.quic_conn.stream_recv(strm_id, &mut tmp_buf) {
            if len != 0 {
                wbuf.extend_from_slice(&tmp_buf[0..len]);
            }

            is_fin |= fin;
        }

        if wbuf.len() > 0 { sink.send(IoRecvOps::IoRecv(wbuf)).await; }
        if is_fin {
            sink.send(IoRecvOps::IoEof()).await;
            internal.strm_table.remove(&strm_id);
        }
    }
}

async fn client_process_timeout(internal: &mut QuicClientInternal) {
    internal.quic_conn.on_timeout();
}

enum InternalIoOps {
    IoTimeout(),
    IoSend(IoSendOps),
    IoRecv(IoRecvOps),
}

async fn client_dispatch_send(tx: sync::Sender<InternalIoOps>, strm: IoSendStream) {
    while let Ok(op) = strm.recv().await {
        tx.send(InternalIoOps::IoSend(op)).await;
    }
}

async fn client_dispatch_recv(tx: sync::Sender<InternalIoOps>, sock: Arc<net::UdpSocket>) {
    let mut buf = Vec::new();
    buf.reserve(1480);

    while let Ok(sz) = sock.recv(&mut buf).await {
        if sz == 0 {
            tx.send(InternalIoOps::IoRecv(IoRecvOps::IoEof())).await;
            break;
        }

        tx.send(InternalIoOps::IoRecv(IoRecvOps::IoRecv(buf))).await;
        
        buf = Vec::new();
        buf.reserve(1480);
    }
}

async fn client_dispatch_timeout(tx: sync::Sender<InternalIoOps>, time: Duration) {
    task::sleep(time).await;
    tx.send(InternalIoOps::IoTimeout()).await;
}

async fn start_client_dispatch(mut internal: QuicClientInternal) {
    let (internal_tx, internal_rx) = sync::channel::<InternalIoOps>(128);

    task::spawn(client_dispatch_send(internal_tx.clone(), internal.tx_strm.clone()));
    task::spawn(client_dispatch_recv(internal_tx.clone(), internal.sock_conn.clone()));

    // start process requests.
    let mut send_buf = [0u8; 1420];
    while let Ok(req_op) = internal_rx.recv().await {
        match req_op {
            InternalIoOps::IoTimeout() => client_process_timeout(&mut internal).await,
            InternalIoOps::IoSend(send_op) => client_process_send(&mut internal, send_op).await,
            InternalIoOps::IoRecv(recv_op) => client_process_recv(&mut internal, recv_op).await,
        };
        
        if internal.quic_conn.is_closed() {
            break;
        }

        if internal_rx.len() % 3 == 0 {
            while let Ok(sz) = internal.quic_conn.send(&mut send_buf) {
                internal.sock_conn.send(&send_buf[0..sz]).await
                    .expect("fatal error! failed to write buffer on socket!");
            }

            return;
        }

        if let Some(time) = internal.quic_conn.timeout() {
            task::spawn(client_dispatch_timeout(internal_tx.clone(), time));
        }
    };

    return;
}

pub async fn establish(addr: SocketAddr, conf: ClientConfig) -> Result<QuicClient, anyhow::Error> {
    let mut quic_conf = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    quic_conf.verify_peer(conf.ssl_verify);
    quic_conf.set_initial_max_data(conf.pl_init_max_sz as u64);
    quic_conf.set_initial_max_stream_data_bidi_local(conf.pl_init_max_bidi_sz as u64);
    quic_conf.set_initial_max_stream_data_bidi_remote(conf.pl_init_max_bidi_sz as u64);
    quic_conf.set_initial_max_streams_bidi(conf.pl_max_bidi_streams as u64);
    quic_conf.set_initial_max_stream_data_uni(conf.pl_init_max_uni_sz as u64);
    quic_conf.set_max_idle_timeout(conf.conn_timeout as u64);
    quic_conf.set_max_packet_size(conf.conn_max_udp_size as u64);
    quic_conf.set_disable_active_migration(true);
    quic_conf.set_application_protos(b"\x06fibers").unwrap();
    quic_conf.load_cert_chain_from_pem_file("assets/client.pem").unwrap();

    let (strm_tx, strm_rx) = sync::channel::<(QuicSendStream, QuicRecvStream)>(128);
    let (tx_sink, tx_strm) = sync::channel::<IoSendOps>(258);

    let socket = net::UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(addr).await?;
    
    let mut internal = QuicClientInternal { 
        send_closed: false,
        recv_closed: false,

        // initialize conenctions.
        quic_conn : quiche::connect(conf.ssl_sni.as_deref(), &conf.conn_scid, &mut quic_conf)?, 
        sock_conn : Arc::new(socket),

        // initialize stream helpers.
        strm_tx   : strm_tx,
        strm_table: HashMap::new(),

        // initialize sender channels.
        tx_sink   : tx_sink.clone(),
        tx_strm   : tx_strm.clone(),
    };

    // do client handshake.
    log::info!("connecting to addr = {}", addr);
    process_client_handshake(&mut internal).await?;
    log::info!("established addr = {}", addr);

    // spawn dispatcher and returns client.
    task::spawn(start_client_dispatch(internal));

    return Ok(QuicClient {incoming: strm_rx, tx: tx_sink});
}
