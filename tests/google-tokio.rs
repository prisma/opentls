#![warn(rust_2018_idioms)]

use std::net::ToSocketAddrs;

use env_logger;
use opentls;
use opentls::async_io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

macro_rules! t {
    ($e:expr) => {
        match $e {
            Ok(e) => e,
            Err(e) => panic!("{} failed with {:?}", stringify!($e), e),
        }
    };
}

#[tokio::test]
async fn fetch_google() {
    drop(env_logger::try_init());

    // First up, resolve google.com
    let addr = t!("google.com:443".to_socket_addrs()).next().unwrap();

    let socket = TcpStream::connect(&addr).await.unwrap();

    // Send off the request by first negotiating an SSL handshake, then writing
    // of our request, then flushing, then finally read off the response.
    let connector = async_io::TlsConnector::new();
    let mut socket = t!(connector.connect("google.com", socket).await);
    t!(socket.write_all(b"GET / HTTP/1.0\r\n\r\n").await);
    let mut data = Vec::new();
    t!(socket.read_to_end(&mut data).await);

    // any response code is fine
    assert!(dbg!(&data).starts_with(b"HTTP/1.0 "));

    let data = String::from_utf8_lossy(&data);
    let data = data.trim_end();
    assert!(data.ends_with("</html>") || data.ends_with("</HTML>"));
}
