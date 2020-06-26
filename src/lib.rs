use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ Poll, Context, Waker};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::io::Error;
use std::io::ErrorKind;
use std::marker::PhantomData;

use anyhow;
use async_std::*;
use quiche;
use futures::{ select, ready, pin_mut};
use futures::{ FutureExt, AsyncReadExt, AsyncWriteExt };

#[derive(Default)]
pub struct ClientConfig {
    // SSL configurations.
    pub ssl_verify: bool,
    pub ssl_sni: Option<String>,
    pub ssl_key: Vec<u8>,
    pub ssl_ca_cert: Vec<u8>,

    // Payload configurations.
    pub pl_init_max_sz: usize,
    pub pl_init_max_bidi_sz: usize,
    pub pl_init_max_uni_sz: usize,
    pub pl_max_bidi_streams: usize,
    pub pl_max_uni_streams: usize,

    // Connection configurations.
    pub conn_timeout: usize,
    pub conn_max_udp_size: usize,
    pub conn_scid: [u8; 20],
}

#[derive(Default)]
pub struct ServerConfig {

}

pub enum IoNotifyType {
    
}

pub enum IoSendOps {
    IoSend(Vec<u8>, Waker),
    IoFlush(Waker),
    IoClose(Waker),
}

pub enum IoRecvOps {
    IoRecv(Vec<u8>)
}

type IoSendStream = sync::Sender<IoSendOps>;
type IoRecvStream = sync::Receiver<IoRecvOps>;

pub enum StreamOps {
    StreamOpen(u64),
    StreamOpened(u64, QuicStream),
    StreamClose(u64),
}

pub struct QuicConnection {
    incoming: sync::Receiver<QuicStream>,
    tx: sync::Sender<Vec<u8>>
}

impl QuicConnection {
    pub async fn wait_stream(&mut self) -> QuicStream {
        self.incoming.recv().await.unwrap()
    }
}

unsafe impl Sync for QuicStream { }
unsafe impl Send for QuicStream { }

pub struct QuicStream {
    recv_close: bool,
    recv_flush: bool,

    local_storage: Option<Vec<u8>>,

    tx_pending: Mutex<HashSet<usize>>,
    tx: IoSendStream,
    rx: IoRecvStream,
}

impl futures::AsyncRead for QuicStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, wbuf: &mut [u8]) -> Poll<Result<usize, Error>> {
        let self_mut = self.get_mut();

        // check do that stream has more 
        if let Some(rbuf) = self_mut.local_storage.take() {
            let len = rbuf.len().max(wbuf.len());

            wbuf[..len].copy_from_slice(&rbuf[..len]);
            if rbuf.len() > len {
                let mut new_storage = Vec::new();
                new_storage.extend_from_slice(&rbuf[len..]);

                self_mut.local_storage = Some(new_storage);
            }

            return Poll::Ready(Ok(len));
        }

        let future = self_mut.rx.recv();
        pin_mut!(future);

        match ready!(future.poll_unpin(cx)) {
            Ok (v) => {
                match v {
                    IoRecvOps::IoRecv(buf) => {
                        // Check its EOF
                        if buf.len() == 0 {
                            return Poll::Ready(Ok(0));
                        }

                        // We have buffer to read
                        self_mut.local_storage = Some(buf);
                        cx.waker().wake_by_ref();
                    }
                };
            },
            Err(_) => {
                return Poll::Ready(Err(Error::new(ErrorKind::UnexpectedEof, "channel has been distroyed!")));
            }
        };

        return Poll::Pending;
    }
}

impl futures::AsyncWrite for QuicStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, rbuf: &[u8]) -> Poll<Result<usize, Error>> {
        let self_mut = self.get_mut();

        if self_mut.tx_pending.lock().unwrap().contains(&(rbuf.as_ptr() as usize)) {
            return Poll::Ready(Ok(rbuf.len()));
        }

        if self_mut.recv_close {
            return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "stream already closed!")));
        }

        task::block_on(async {
            let mut buf = Vec::new();
            buf.extend_from_slice(&rbuf);

            self_mut.tx.send(IoSendOps::IoSend(buf, cx.waker().clone())).await;
        });

        return Poll::Pending;
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        let self_mut = self.get_mut();

        if self_mut.recv_flush {
            self_mut.recv_flush = false;
            return Poll::Ready(Ok(()));
        }
        
        task::block_on( async { 
            self_mut.tx.send(IoSendOps::IoClose(cx.waker().clone())).await;
            self_mut.recv_flush = true;
        });

        return Poll::Pending;
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        let self_mut = self.get_mut();

        if self_mut.recv_close {
            return Poll::Ready(Ok(()));
        }

        task::block_on( async { 
            self_mut.tx.send(IoSendOps::IoClose(cx.waker().clone())).await;
            self_mut.recv_close = true;
        });

        return Poll::Pending;
    }
}

pub async fn connect(addr: SocketAddr, conf: ClientConfig) -> Result<QuicConnection, anyhow::Error> {
    let mut quic_conn = task::spawn_blocking(move || {
        let mut quic_conf = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        quic_conf.verify_peer(conf.ssl_verify);
        quic_conf.set_initial_max_data(conf.pl_init_max_sz as u64);
        quic_conf.set_initial_max_stream_data_bidi_local(conf.pl_init_max_bidi_sz as u64);
        quic_conf.set_initial_max_stream_data_bidi_remote(conf.pl_init_max_bidi_sz as u64);
        quic_conf.set_initial_max_streams_bidi(conf.pl_max_bidi_streams as u64);
        quic_conf.set_initial_max_stream_data_uni(conf.pl_init_max_uni_sz as u64);
        quic_conf.set_max_idle_timeout(conf.conn_timeout as u64);
        quic_conf.set_max_packet_size(conf.conn_max_udp_size as u64);

        Ok::<Pin<Box<quiche::Connection>>, anyhow::Error>(
            quiche::connect(conf.ssl_sni.as_deref(), &conf.conn_scid, &mut quic_conf)?
        )
    }).await?;

    let (conn_tx, conn_rx) = sync::channel::<QuicStream>(128);
    let (send_tx, send_rx) = sync::channel::<Vec<u8>>(128);

    task::spawn(async move {
        let socket = net::UdpSocket::bind(addr).await.expect("failed to bind socket!");
        
        // keep communication with server to establish.
        while quic_conn.is_established() {
            let mut buf = [0u8; 4096];

            loop {
                match quic_conn.send(&mut buf) {
                    Ok (v)                   => socket.send(&buf).await.unwrap(),
                    Err(quiche::Error::Done) => break,
                    Err(_)                   => unreachable!(),
                };
            }

            match socket.recv(&mut buf).await {
                Ok (v) => quic_conn.recv(&mut buf[0..v]).expect("failed to process buffer!"),
                Err(_) => unreachable!()
            };
        }

        // Seems connection has been established.
        loop {
            let mut tmp_buf = [0u8; 4096];
            select! {
                // process send io ops
                req = async { send_rx.recv().await.unwrap() }.fuse()
                    => {
                        
                    }

                // process recv io ops
                req = socket.recv(&mut tmp_buf).fuse()
                    => {
                        quic_conn.recv(&mut tmp_buf).unwrap();
                    }
            }
        }
    });

    Ok(QuicConnection {incoming: conn_rx, tx: send_tx})
}
