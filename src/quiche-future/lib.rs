use std::pin::Pin;
use std::task::{ Poll, Context, Waker  };
use std::collections::{ HashSet };
use std::io::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::collections::{HashMap};
use std::time::Duration;

use async_std::*;
use async_std::io::{ Read, Write };
use async_std::sync::{ channel, Receiver, Sender, Arc, Mutex };
use async_std::task::JoinHandle;
use async_std::stream::Stream;

use anyhow;
use quiche;

#[derive(Default)]
pub struct ClientConfig {
    // SSL configurations.
    pub ssl_verify: bool,
    pub ssl_sni: Option<String>,
    pub ssl_ca_cert: String,

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
    pub conn_alpn: Vec<u8>
}

#[derive(Default)]
pub struct ServerConfig {
    // SSL configurations.
    pub ssl_key_path: String,
    pub ssl_cert_path: String,

    // Payload configurations.
    pub pl_init_max_sz: usize,
    pub pl_init_max_bidi_sz: usize,
    pub pl_init_max_uni_sz: usize,
    pub pl_max_bidi_streams: usize,
    pub pl_max_uni_streams: usize,

    // Connection configurations.
    pub conn_timeout: usize,
    pub conn_max_packet_sz: usize,
    pub conn_scid: [u8; 20],
    pub conn_alpn: Vec<u8>
}

pub type IoSendStream = Receiver<IoSendOps>;
pub type IoSendSink = Sender<IoSendOps>;
pub type IoRecvStream = Receiver<IoRecvOps>;
pub type IoRecvSink = Sender<IoRecvOps>;

pub enum IoSendOps {
    IoSend(u64, Vec<u8>, Waker),
    IoClose(),
    IoFlush(u64, Waker),
    IoStreamFree(u64, Waker),
    IoStreamOpen(u64, IoRecvSink)
}

pub enum IoRecvOps {
    IoRecv(Vec<u8>),
    IoEof()
}

pub enum StreamOps {
    StreamOpen(u64),
    StreamOpened(u64, (QuicSendStream, QuicRecvStream)),
    StreamClose(u64),
}

unsafe impl Sync for QuicRecvStream { }
unsafe impl Send for QuicRecvStream { }

pub struct QuicRecvStream {
    stream_id: u64,

    local_storage: Option<Vec<u8>>,
    rx: Pin<Box<IoRecvStream>>
}

impl QuicRecvStream {
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

impl Read for QuicRecvStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, wbuf: &mut [u8]) -> Poll<Result<usize, Error>> {
        let self_mut = self.get_mut();

        // check do that stream has more 
        if let Some(rbuf) = self_mut.local_storage.take() {
            let len = rbuf.len().min(wbuf.len());

            wbuf[..len].copy_from_slice(&rbuf[..len]);
            if rbuf.len() > len {
                self_mut.local_storage = Some(rbuf[len..].to_vec().clone());
            }

            return Poll::Ready(Ok(len));
        }

        match self_mut.rx.as_mut().poll_next(cx) {
            Poll::Ready(None) => {
                return Poll::Ready(Err(Error::new(ErrorKind::UnexpectedEof, "channel has been distroyed!")));
            }

            Poll::Ready(Some(v)) => {
                match v {
                    IoRecvOps::IoRecv(buf) => {
                        self_mut.local_storage = Some(buf);
                        cx.waker().wake_by_ref();
                    }
                    IoRecvOps::IoEof() => {
                        return Poll::Ready(Ok(0));
                    }
                }
            }

            Poll::Pending => { }
        }

        return Poll::Pending;
    }
}

unsafe impl Sync for QuicSendStream { }
unsafe impl Send for QuicSendStream { }

pub struct QuicSendStream {
    stream_id: u64,

    send_close: bool,
    send_flush: bool,

    tx_pending: std::sync::Mutex<HashSet<usize>>,
    tx: IoSendSink,
}

impl QuicSendStream {
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

impl Write for QuicSendStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, rbuf: &[u8]) -> Poll<Result<usize, Error>> {
        let self_mut = self.get_mut();

        {
            let mut pendings = self_mut.tx_pending.lock().unwrap();
            let key = rbuf.as_ptr() as usize;

            if pendings.contains(&key) {
                pendings.remove(&key);
                return Poll::Ready(Ok(rbuf.len()));
            }

            pendings.insert(key);
        }
        
        if self_mut.send_close {
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

        if self_mut.send_flush {
            self_mut.send_flush = false;
            return Poll::Ready(Ok(()));
        }
        
        task::block_on( async { 
            self_mut.tx.send(IoSendOps::IoStreamFree(self_mut.stream_id, cx.waker().clone())).await;
            self_mut.send_flush = true;
        });

        return Poll::Pending;
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        let self_mut = self.get_mut();

        if self_mut.send_close {
            return Poll::Ready(Ok(()));
        }

        task::block_on( async {
            self_mut.tx.send(IoSendOps::IoStreamFree(self_mut.stream_id, cx.waker().clone())).await;
            self_mut.send_close = true;
        });

        return Poll::Pending;
    }
}

impl Clone for QuicSendStream { 
    fn clone(&self) -> Self {
        QuicSendStream { 
            stream_id: self.stream_id,

            send_close: false,
            send_flush: false,

            tx_pending: Default::default(),
            tx: self.tx.clone()
        }
    }
}

pub struct QuicConn {
    incoming: Receiver<(QuicSendStream, QuicRecvStream)>,
    tx: IoSendSink
}

struct QuicClientInternal {
    send_closed: bool,
    recv_closed: bool,

    quic_conn: Pin<Box<quiche::Connection>>,
    sock_conn: Arc<net::UdpSocket>, 

    strm_sink: Sender<(QuicSendStream, QuicRecvStream)>,
    strm_table: HashMap<u64, IoRecvSink>,
    strm_frags: HashMap<u64, (Vec<u8>, Waker)>,

    send_sink: IoSendSink,
    send_strm: IoSendStream,
}

impl QuicConn {
    pub async fn listen_stream(&mut self) -> Option<(QuicSendStream, QuicRecvStream)> {
        let (send_stream, recv_stream) = match self.incoming.recv().await {
            Ok (v) => v,
            Err(_) => return None
        };

        log::info!("created a new stream (stream_id = {}, listen)", send_stream.stream_id());
        return Some((send_stream, recv_stream));
    }
    
    pub async fn create_stream(&mut self, strm_id: u64) -> (QuicSendStream, QuicRecvStream) {
        let (rx_sink, rx_strm) = channel::<IoRecvOps>(128);
        self.tx.send(IoSendOps::IoStreamOpen(strm_id, rx_sink)).await;

        log::info!("created a new stream (stream_id = {}, create)", strm_id);
        let send_stream = QuicSendStream {
            stream_id: strm_id,
            send_close: false,
            send_flush: false,
            tx_pending: Default::default(),
            tx: self.tx.clone(), 
        };

        let recv_stream = QuicRecvStream {
            stream_id: strm_id,
            local_storage: None,
            rx: Box::pin(rx_strm),
        };

        return (send_stream, recv_stream);
    }

    pub async fn close(&mut self) {
        self.tx.send(IoSendOps::IoClose()).await;
    }
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

async fn process_client_send(internal: &mut QuicClientInternal, req: IoSendOps) {
    match req { 
        IoSendOps::IoFlush(_, waker) => {
            waker.wake();
        }

        IoSendOps::IoClose() => {
            if let Err(_) = internal.quic_conn.close(true, 0, b"") {
                log::error!("[+] quic-trace | closed connection twice!");
            }

            internal.send_closed = true;
        }

        IoSendOps::IoSend(strm_id, buf, waker) => {
            if let Ok(sz) = internal.quic_conn.stream_send(strm_id, &buf, false) {
                if sz != buf.len() {
                    internal.strm_frags.insert(strm_id, (buf[sz..].to_vec(), waker));
                    return;
                }
            }

            waker.wake();
        }

        IoSendOps::IoStreamOpen(strm_id, sink) => {
            if !internal.strm_table.contains_key(&strm_id) {
                // should not be opend!
            }

            if internal.quic_conn.stream_send(strm_id, b"", false).is_ok() {
                log::info!("[+] stream-trace | stream opened id = {}", strm_id);
                internal.strm_table.insert(strm_id, sink);
            }
        }

        IoSendOps::IoStreamFree(strm_id, waker) => { 
            internal.quic_conn.stream_shutdown(strm_id, quiche::Shutdown::Write, 0).unwrap();

            log::info!("[+] stream-trace | stream closed id = {} type = write", strm_id);
            waker.wake();
        }
    }
}

async fn process_client_recv(internal: &mut QuicClientInternal, req: IoRecvOps) {
    
    match req {
        IoRecvOps::IoRecv(mut buf) => {
            log::trace!("[+] socket | len = {}", buf.len());
            internal.quic_conn.recv(&mut buf).unwrap();
        },
        IoRecvOps::IoEof() => {
            log::trace!("[+] socket | EOF reached!");
            for (_, sender) in &internal.strm_table {
                sender.send(IoRecvOps::IoEof()).await;
            }

            internal.strm_table.clear();
            internal.recv_closed = true;
        }
    }

    assert!(internal.recv_closed == false, "socket is already closed with EOF!");

    let mut tmp_buf = [0u8; 4096];

    let strm_id_iter = internal.quic_conn.readable();
    for strm_id in strm_id_iter {
        if !internal.strm_table.contains_key(&strm_id) {
            let (rx_sink, rx_strm) = channel::<IoRecvOps>(128);

            let send_stream = QuicSendStream {
                stream_id: strm_id,
                send_close: false,
                send_flush: false,
                tx_pending: Default::default(),
                tx: internal.send_sink.clone(), 
            };

            let recv_stream = QuicRecvStream {
                stream_id: strm_id,
                local_storage: None,
                rx: Box::pin(rx_strm),
            };

            internal.strm_sink.send((send_stream, recv_stream)).await;
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

            log::info!("[+] stream-trace | stream closed id = {} type = read", strm_id);
        }
    }
}

async fn process_client_timeout(internal: &mut QuicClientInternal) {
    internal.quic_conn.on_timeout();
}

enum InternalIoOps {
    IoTimeout(),
    IoSend(IoSendOps),
    IoRecv(IoRecvOps),
}

async fn dispatch_client_send(tx: Sender<InternalIoOps>, strm: IoSendStream) {
    while let Ok(op) = strm.recv().await {
        tx.send(InternalIoOps::IoSend(op)).await;
    }
}

async fn dispatch_client_recv(tx: Sender<InternalIoOps>, sock: Arc<net::UdpSocket>) {
    let mut buf = [0u8; 4096];

    while let Ok(sz) = sock.recv(&mut buf).await {
        if sz == 0 {
            tx.send(InternalIoOps::IoRecv(IoRecvOps::IoEof())).await;
            break;
        }

        tx.send(InternalIoOps::IoRecv(IoRecvOps::IoRecv(buf[..sz].to_vec().clone()))).await;
    }
}

async fn dispatch_client_timeout(tx: Sender<InternalIoOps>, time: Duration) {
    task::sleep(time).await;
    tx.send(InternalIoOps::IoTimeout()).await;
}

async fn dispatch_client_connection(mut internal: QuicClientInternal) {
    let (internal_tx, internal_rx) = channel::<InternalIoOps>(128);

    let h1 = task::spawn(dispatch_client_send(internal_tx.clone(), internal.send_strm.clone()));
    let h2 = task::spawn(dispatch_client_recv(internal_tx.clone(), internal.sock_conn.clone()));

    // start process requests.
    let mut send_buf = [0u8; 1420];
    while let Ok(req_op) = internal_rx.recv().await {
        match req_op {
            InternalIoOps::IoTimeout() => process_client_timeout(&mut internal).await,
            InternalIoOps::IoSend(send_op) => process_client_send(&mut internal, send_op).await,
            InternalIoOps::IoRecv(recv_op) => process_client_recv(&mut internal, recv_op).await,
        };

        while let Ok(sz) = internal.quic_conn.send(&mut send_buf) {
            if internal.sock_conn.send(&send_buf[..sz]).await.is_err() {
                log::error!("[+] socket-send | failed to send packet");
                break;
            }

            log::trace!("[+] socket | sent len = {}", sz);
        }

        let writable_streams = internal.quic_conn.writable();
        for strm_id in writable_streams {
            if let Some((b, w)) = internal.strm_frags.remove(&strm_id) {
                internal.send_sink.send(IoSendOps::IoSend(strm_id, b, w)).await;
            }
        }

        if let Some(time) = internal.quic_conn.timeout() {
            task::spawn(dispatch_client_timeout(internal_tx.clone(), time));
        }

        if internal.quic_conn.is_closed() {
            log::info!("[+] quic-trace | connection closed! = {}", &internal.quic_conn.trace_id());
            break;
        }
    };

    h1.cancel().await;
    h2.cancel().await;
}

pub async fn establish_client(bind_addr: SocketAddr, conn_addr: SocketAddr, conf: ClientConfig) -> Result<QuicConn, anyhow::Error> {
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
    quic_conf.set_application_protos(&conf.conn_alpn).expect("bad apln value!");
    quic_conf.load_cert_chain_from_pem_file(&conf.ssl_ca_cert).expect("failed to load cert chain!");

    let (strm_sink, strm_strm) = channel::<(QuicSendStream, QuicRecvStream)>(128);
    let (send_sink, send_strm) = channel::<IoSendOps>(128);

    let socket = net::UdpSocket::bind(bind_addr).await?;
    socket.connect(conn_addr).await?;
    
    let mut internal = QuicClientInternal { 
        send_closed: false,
        recv_closed: false,

        // initialize conenctions.
        quic_conn : quiche::connect(conf.ssl_sni.as_deref(), &conf.conn_scid, &mut quic_conf)?, 
        sock_conn : Arc::new(socket),

        // initialize stream helpers.
        strm_sink : strm_sink,
        strm_table: HashMap::new(),
        strm_frags: HashMap::new(),

        // initialize sender channels.
        send_sink : send_sink.clone(),
        send_strm : send_strm.clone(),
    };

    // do client handshake.
    log::info!("[+] quic-trace | connecting to addr = {}", conn_addr);
    process_client_handshake(&mut internal).await?;
    log::info!("[+] quic-trace | established addr = {}", conn_addr);

    // spawn dispatcher and returns client.
    task::spawn(dispatch_client_connection(internal));

    return Ok(QuicConn {incoming: strm_strm, tx: send_sink});
}


pub struct QuicServer {
    rx: Receiver<QuicConn>
}

impl QuicServer {
    pub async fn listen(&self) -> Option<QuicConn> {
        match self.rx.recv().await {
            Ok (s) => Some(s),
            Err(_) => None,
        }
    }
}


struct QuicServerInternal {
    send_closed: bool,
    recv_closed: bool,

    quic_conn: Pin<Box<quiche::Connection>>,
    sock_conn: Arc<net::UdpSocket>, 
    sock_addr: SocketAddr,

    strm_sink: Sender<(QuicSendStream, QuicRecvStream)>,
    strm_table: HashMap<u64, IoRecvSink>, 
    strm_frags: HashMap<u64, (Vec<u8>, Waker)>,

    recv_strm: IoRecvStream,

    send_sink: IoSendSink,
    send_strm: IoSendStream,
}

async fn process_server_send(internal: &mut QuicServerInternal, req: IoSendOps) {
    match req { 
        IoSendOps::IoFlush(_, waker) => {
            waker.wake();
        }

        IoSendOps::IoClose() => {
            if let Err(_) = internal.quic_conn.close(true, 0, b"") {
                log::error!("[+] quic-trace | closed connection twice!");
            }

            internal.send_closed = true;
        }

        IoSendOps::IoSend(strm_id, buf, waker) => {
            if let Ok(sz) = internal.quic_conn.stream_send(strm_id, &buf, false) {
                if sz != buf.len() {
                    internal.strm_frags.insert(strm_id, (buf[sz..].to_vec(), waker));
                    return;
                }
            }

            waker.wake();
        }

        IoSendOps::IoStreamOpen(strm_id, sink) => {
            if !internal.strm_table.contains_key(&strm_id) {
                // should not be opend!
            }

            if internal.quic_conn.stream_send(strm_id, b"", false).is_ok() {
                log::info!("[+] stream-trace | stream opened id = {}", strm_id);
                internal.strm_table.insert(strm_id, sink.to_owned());
            }

        }

        IoSendOps::IoStreamFree(strm_id, waker) => { 
            internal.quic_conn.stream_shutdown(strm_id, quiche::Shutdown::Write, 0).unwrap();

            log::info!("[+] stream-trace | stream closed id = {} type = write", strm_id);

            waker.wake();
        }
    }
}

async fn process_server_recv(internal: &mut QuicServerInternal, req: IoRecvOps) {
    match req {
        IoRecvOps::IoRecv(mut buf) => {
            match internal.quic_conn.recv(&mut buf) {
                Ok (_) => {
                    log::trace!("[+] socket | parsed packet len = {}", buf.len());
                },
                Err(e) => {
                    log::error!("[+] socket | error while process packet! {}", e);
                }
            }
        },
        IoRecvOps::IoEof() => {
            log::trace!("[+] socket | EOF reached!");
            for (_, sender) in &internal.strm_table {
                sender.send(IoRecvOps::IoEof()).await;
            }

            internal.strm_table.clear();
            internal.recv_closed = true;

            return;
        }
    }

    assert!(internal.recv_closed == false, "socket is already closed with EOF!");

    let mut tmp_buf = [0u8; 4096];

    let strm_id_iter = internal.quic_conn.readable();
    for strm_id in strm_id_iter {
        log::trace!("[+] stream-trace | reading stream id = {}", strm_id);
        if !internal.strm_table.contains_key(&strm_id) {
            let (rx_sink, rx_strm) = channel::<IoRecvOps>(128);

            let send_stream = QuicSendStream {
                stream_id: strm_id,
                send_close: false,
                send_flush: false,
                tx_pending: Default::default(),
                tx: internal.send_sink.clone(), 
            };

            let recv_stream = QuicRecvStream {
                stream_id: strm_id,
                local_storage: None,
                rx: Box::pin(rx_strm),
            };

            internal.strm_sink.send((send_stream, recv_stream)).await;
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
            log::info!("[+] quic-trace | connection closed! = {}", &internal.quic_conn.trace_id());
            sink.send(IoRecvOps::IoEof()).await;
            internal.strm_table.remove(&strm_id);
        }
    }
}

async fn process_server_timeout(internal: &mut QuicServerInternal) {
    internal.quic_conn.on_timeout();
}

async fn dispatch_server_send(tx: Sender<InternalIoOps>, strm: IoSendStream) {
    while let Ok(op) = strm.recv().await {
        tx.send(InternalIoOps::IoSend(op)).await;
    }
}

async fn dispatch_server_recv(tx: Sender<InternalIoOps>, strm: IoRecvStream) {
    while let Ok(op) = strm.recv().await {
        tx.send(InternalIoOps::IoRecv(op)).await;
    }
}

async fn dispatch_server_connection(mut internal: QuicServerInternal) {
    let (internal_tx, internal_rx) = channel::<InternalIoOps>(128);

    let h1 = task::spawn(dispatch_server_send(internal_tx.clone(), internal.send_strm.clone()));
    let h2 = task::spawn(dispatch_server_recv(internal_tx.clone(), internal.recv_strm.clone()));

    // start process requests.
    let mut buf = [0u8; 1460];

    while let Ok(req_op) = internal_rx.recv().await {
        match req_op {
            InternalIoOps::IoTimeout() => process_server_timeout(&mut internal).await,
            InternalIoOps::IoSend(send_op) => process_server_send(&mut internal, send_op).await,
            InternalIoOps::IoRecv(recv_op) => process_server_recv(&mut internal, recv_op).await,
        };

        while let Ok(sz) = internal.quic_conn.send(&mut buf) {
            if internal.sock_conn.send_to(&buf[..sz], &internal.sock_addr).await.is_err() {
                log::error!("[+] socket-send | failed to send packet to = {:?}", &internal.sock_addr);
                break;
            }

            log::trace!("[+] socket | sent len = {}", sz);
        }

        let writable_streams = internal.quic_conn.writable();
        for strm_id in writable_streams {
            if let Some((b, w)) = internal.strm_frags.remove(&strm_id) {
                internal.send_sink.send(IoSendOps::IoSend(strm_id, b, w)).await;
            }
        }

        if let Some(time) = internal.quic_conn.timeout() {
            task::spawn(dispatch_client_timeout(internal_tx.clone(), time));
        }

        if internal.quic_conn.is_closed() {
            log::info!("[+] quic-trace | connection closed! = {}", &internal.quic_conn.trace_id());
            break;
        }
    };

    h1.cancel().await;
    h2.cancel().await;

    log::info!("[+] quic-trace | event worker clsoed! = {}", &internal.quic_conn.trace_id());
}

async fn wait_and_remove(table: Arc<Mutex<HashMap<Vec<u8>, IoRecvSink>>>, id: Vec<u8>, handle: JoinHandle<()>) {
    handle.await;
    table.lock().await.remove(&id);

    log::info!("[+] quic-trace | connection dropped! id = {:?}", &id);
}

pub async fn dispatch_server_packets(conn_tx: Sender<QuicConn>, sock_conn: Arc<net::UdpSocket>, mut quic_conf: quiche::Config) {
    let client_table: Arc<Mutex<HashMap<Vec<u8>, IoRecvSink>>> = Default::default();

    let mut buf = [0u8; 4096];
    while let Ok((len, src)) = sock_conn.recv_from(&mut buf).await {
        let mut table = client_table.lock().await;

        if len == 0 {
            // EOF found.
            for (_, tx) in table.iter_mut() {
                tx.send(IoRecvOps::IoEof()).await
            }
        }

        let quic_header = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
            Ok (v) => v,
            Err(_) => continue
        };

        log::trace!("[+] socket | global recv src = {} / len = {} / \n\t scid = {:?} / \n\t dcid = {:?}", &src, len, quic_header.scid, quic_header.dcid);

        // check its begin of connection
        if !table.contains_key(&quic_header.dcid) {
            if quic_header.ty != quiche::Type::Initial {
                log::error!("[+] socket | found bad packet!");
                // bad quic packet arrived.
                continue;
            }

            if !quiche::version_is_supported(quic_header.version) {
                // invalid version, we need to negotiate version.
                let neg_len = quiche::negotiate_version(&quic_header.scid, &quic_header.dcid, &mut buf)
                    .expect("failed to create negotiate packet!");
                sock_conn.send_to(&buf[..neg_len], src).await.unwrap();

                continue;
            }

            let quic_conn = match quiche::accept(&quic_header.dcid, None, &mut quic_conf) {
                Ok (v) => v,
                Err(_) => continue
            };
            
            let (strm_sink, strm_strm) = channel::<(QuicSendStream, QuicRecvStream)>(128);
            let (recv_sink, recv_strm) = channel::<IoRecvOps>(128);
            let (send_sink, send_strm) = channel::<IoSendOps>(128);

            table.insert(quic_header.dcid.clone(), recv_sink);
            conn_tx.send(QuicConn { incoming: strm_strm, tx: send_sink.clone() }).await;

            let internal = QuicServerInternal {
                send_closed: false,
                recv_closed: false,
        
                // initialize conenctions.
                quic_conn : quic_conn, 
                sock_conn : sock_conn.clone(),
                sock_addr : src.clone(),
        
                // initialize stream helpers.
                strm_sink,
                strm_table: HashMap::new(),
                strm_frags: HashMap::new(),

                recv_strm : recv_strm,
        
                // initialize sender channels.
                send_sink : send_sink.clone(),
                send_strm : send_strm.clone(),
            };

            // start dispatching.
            log::info!("[+] quic-trace | connection established! = {}", internal.quic_conn.trace_id());
            let handle = task::spawn(dispatch_server_connection(internal));
            task::spawn(wait_and_remove(client_table.clone(), quic_header.dcid.clone(), handle));
        }

        let tx = table.get_mut(&quic_header.dcid).unwrap();
        tx.send(IoRecvOps::IoRecv(buf[..len].to_vec().clone())).await;
    }
}

pub async fn establish_server(bind_addr: SocketAddr, conf: ServerConfig) -> Result<QuicServer, anyhow::Error> {
    let mut quic_conf = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    
    quic_conf.set_initial_max_data(conf.pl_init_max_sz as u64);
    quic_conf.set_initial_max_stream_data_bidi_local(conf.pl_init_max_bidi_sz as u64);
    quic_conf.set_initial_max_stream_data_bidi_remote(conf.pl_init_max_bidi_sz as u64);
    quic_conf.set_initial_max_stream_data_uni(conf.pl_init_max_uni_sz as u64);
    quic_conf.set_initial_max_streams_uni(conf.pl_max_uni_streams as u64);
    quic_conf.set_initial_max_streams_bidi(conf.pl_max_bidi_streams as u64);
    quic_conf.set_max_idle_timeout(conf.conn_timeout as u64);
    quic_conf.set_max_packet_size(conf.conn_max_packet_sz as u64);
    quic_conf.set_application_protos(&conf.conn_alpn).expect("bad protos");
    quic_conf.load_cert_chain_from_pem_file(&conf.ssl_cert_path).expect("bad certificate");
    quic_conf.load_priv_key_from_pem_file(&conf.ssl_key_path).expect("bad keychain");
    quic_conf.set_disable_active_migration(true);
    quic_conf.enable_early_data();

    let (tx, rx) = channel::<QuicConn>(128);
    task::spawn(dispatch_server_packets(tx, Arc::new(net::UdpSocket::bind(bind_addr).await?), quic_conf));

    return Ok(QuicServer { rx });
}