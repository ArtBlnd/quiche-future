use std::net::{ SocketAddr };
use std::ffi::{ CStr, CString };

use futures::prelude::*;
use async_std::*;
use rand::*;
use quiche_future::*;

pub struct ClientInst {
    conn: QuicConn,

    tx: QuicSendStream,
    rx: QuicRecvStream,
}

#[no_mangle]
pub unsafe extern fn quic_send(p_inst: &mut ClientInst, buf: *mut u8, len: usize) -> usize {
    let op = p_inst.tx.write(std::slice::from_raw_parts_mut(buf, len));
    return task::block_on(async {
        return match op.await {
            Ok (s) => s,
            Err(_) => 0
        }
    });
}

#[no_mangle]
pub unsafe extern fn quic_send_exact(p_inst: &mut ClientInst, buf: *mut u8, len: usize) {
    let op = p_inst.tx.write_all(std::slice::from_raw_parts_mut(buf, len));
    task::block_on(async {
        op.await.unwrap();
    });
}

#[no_mangle]
pub unsafe extern fn quic_recv(p_inst: &mut ClientInst, buf: *mut u8, len: usize) -> usize {
    let op = p_inst.rx.read(std::slice::from_raw_parts_mut(buf, len));
    return task::block_on(async {
        return match op.await {
            Ok (s) => s,
            Err(_) => 0,
        };
    });
}

#[no_mangle]
pub unsafe extern fn quic_recv_exact(p_inst: &mut ClientInst, buf: *mut u8, len: usize) {
    let op = p_inst.rx.read_exact(std::slice::from_raw_parts_mut(buf, len));
    task::block_on(async {
        op.await.unwrap();
    });
}


#[no_mangle]
pub unsafe extern fn quic_connect(bind_addr: *mut i8, conn_addr: *mut i8) -> Box<ClientInst> {
    let mut conf = ClientConfig::default();
    conf.pl_init_max_bidi_sz = 100_000_000;
    conf.pl_init_max_sz      = 100_000_000;
    conf.pl_init_max_uni_sz  = 100_000_000;

    conf.pl_max_bidi_streams = 1000;
    conf.pl_max_uni_streams  = 1000;

    conf.conn_timeout        = 1000000;
    conf.conn_scid           = [random(); 20];
    conf.conn_max_packet_sz  = 1460;

    conf.conn_alpn           = b"\x06fibers".to_vec();
    conf.ssl_verify          = false;

    let parsed_baddr = CStr::from_ptr(bind_addr).to_str().unwrap().to_owned();
    let parsed_caddr = CStr::from_ptr(conn_addr).to_str().unwrap().to_owned();

    let mut conn_inst = task::block_on(establish_client(parsed_baddr.parse().unwrap(), parsed_caddr.parse().unwrap(), conf)).unwrap();
    let (tx, rx) = task::block_on(conn_inst.create_stream(0));

    Box::new(ClientInst{ conn: conn_inst, tx, rx })
}