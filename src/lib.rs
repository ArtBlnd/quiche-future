mod client;
mod server;

use std::pin::Pin;
use std::task::{ Poll, Context, Waker};
use std::collections::{HashSet};
use std::sync::{Mutex};
use std::io::Error;
use std::io::ErrorKind;

use async_std::*;
use futures::{ ready, pin_mut };
use futures::FutureExt;

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

pub type IoSendStream = sync::Receiver<IoSendOps>;
pub type IoSendSink = sync::Sender<IoSendOps>;
pub type IoRecvStream = sync::Receiver<IoRecvOps>;
pub type IoRecvSink = sync::Sender<IoRecvOps>;

pub enum IoSendOps {
    IoSend(u64, Vec<u8>, Waker),
    IoFlush(u64, Waker),
    IoClose(u64, Waker),
    IoStreamOpen(u64, IoRecvSink)
}

pub enum IoRecvOps {
    IoRecv(Vec<u8>),
    IoEof()
}

pub enum StreamOps {
    StreamOpen(u64),
    StreamOpened(u64, QuicStream),
    StreamClose(u64),
}

unsafe impl Sync for QuicStream { }
unsafe impl Send for QuicStream { }

pub struct QuicStream {
    stream_id: u64,

    recv_close: bool,
    recv_flush: bool,

    local_storage: Option<Vec<u8>>,

    tx_pending: Mutex<HashSet<usize>>,
    tx: IoSendSink,
    rx: IoRecvStream,
}

impl QuicStream { 
    pub fn stream_id(&self) -> u64 {
        return self.stream_id;
    }
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
                        // We have buffer to read
                        self_mut.local_storage = Some(buf);
                        cx.waker().wake_by_ref();
                    }

                    IoRecvOps::IoEof() => {
                        return Poll::Ready(Ok(0));
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

            self_mut.tx.send(IoSendOps::IoSend(self_mut.stream_id, buf, cx.waker().clone())).await;
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
            self_mut.tx.send(IoSendOps::IoClose(self_mut.stream_id, cx.waker().clone())).await;
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
            self_mut.tx.send(IoSendOps::IoClose(self_mut.stream_id, cx.waker().clone())).await;
            self_mut.recv_close = true;
        });

        return Poll::Pending;
    }
}
