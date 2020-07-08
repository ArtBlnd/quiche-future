
use rand::*;
use quiche_future::*;

use async_std::*;
use async_std::prelude::*;

fn main() {
    task::block_on(async {
        let mut conn_conf = ClientConfig::default();
        conn_conf.ssl_verify = false;
        conn_conf.conn_scid = [random(); 20];
        conn_conf.pl_init_max_bidi_sz = 100_000_000;
        conn_conf.pl_init_max_sz = 100_000_000;
        conn_conf.pl_init_max_uni_sz = 100_000_00;
        conn_conf.pl_max_bidi_streams = 1000;
        conn_conf.pl_max_uni_streams = 1000;

        let bind_addr = "127.0.0.1:0   ".parse().unwrap();
        let conn_addr = "127.0.0.1:5056".parse().unwrap();

        let mut conn_inst = establish_client(bind_addr, conn_addr, conn_conf).await.unwrap();
        let (mut send_stream, mut recv_stream) = conn_inst.create_stream(0).await;

        let mut buf = [0u8; 4096];


        loop {
            let sz = recv_stream.read(&mut buf).await.unwrap();
            std::println!("{} = {}", String::from_utf8_lossy(&buf[0..sz]), sz);
        }
    });
}