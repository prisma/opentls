// #![warn(rust_2018_idioms)]

use async_std::net::TcpStream;
use env_logger;
use opentls::async_io::TlsConnector;
use std::{
    io::{self, Error},
    net::ToSocketAddrs,
};

macro_rules! t {
    ($e:expr) => {
        match $e {
            Ok(e) => e,
            Err(e) => panic!("{} failed with {:?}", stringify!($e), e),
        }
    };
}
async fn get_host(host: &'static str) -> Error {
    drop(env_logger::try_init());

    let addr = format!("{}:443", host);
    let addr = t!(addr.to_socket_addrs()).next().unwrap();

    let socket = t!(TcpStream::connect(&addr).await);
    let cx = TlsConnector::new();
    let res = cx
        .connect(host, socket)
        .await
        .map_err(|e| Error::new(io::ErrorKind::Other, e));

    assert!(res.is_err());
    res.err().unwrap()
}

#[async_std::test]
async fn expired() {
    let err = get_host("expired.badssl.com").await;
    assert!(format!("{}", err).contains("certificate verify failed"))
}

#[async_std::test]
async fn wrong_host() {
    let err = get_host("wrong.host.badssl.com").await;
    assert!(format!("{}", err).contains("certificate verify failed"))
}

#[async_std::test]
async fn self_signed() {
    let err = get_host("self-signed.badssl.com").await;
    assert!(format!("{}", err).contains("certificate verify failed"))
}

#[async_std::test]
async fn untrusted_root() {
    let err = get_host("untrusted-root.badssl.com").await;
    assert!(format!("{}", err).contains("certificate verify failed"))
}
