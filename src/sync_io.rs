//! A synchronous TLS implementation using OpenSSL.
//!
//! # Supported features
//!
//! This crate supports the following features out of the box:
//!
//! * TLS/SSL client communication
//! * TLS/SSL server communication
//! * PKCS#12 encoded identities
//! * Secure-by-default for client and server
//!     * Includes hostname verification for clients
//! * Supports asynchronous I/O for both the server and the client
//!
//! # Examples
//!
//! To connect as a client to a remote server:
//!
//! ```rust
//! use opentls::sync_io::TlsConnector;
//! use std::io::{Read, Write};
//! use std::net::TcpStream;
//!
//! let connector = TlsConnector::new().unwrap();
//!
//! let stream = TcpStream::connect("google.com:443").unwrap();
//! let mut stream = connector.connect("google.com", stream).unwrap();
//!
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut res = vec![];
//! stream.read_to_end(&mut res).unwrap();
//! println!("{}", String::from_utf8_lossy(&res));
//! ```
//!
//! To accept connections as a server from remote clients:
//!
//! ```rust,no_run
//! use opentls::{Identity, sync_io::{TlsAcceptor, TlsStream}};
//! use std::fs::File;
//! use std::io::{Read};
//! use std::net::{TcpListener, TcpStream};
//! use std::sync::Arc;
//! use std::thread;
//!
//! let mut file = File::open("identity.pfx").unwrap();
//! let mut identity = vec![];
//! file.read_to_end(&mut identity).unwrap();
//! let identity = Identity::from_pkcs12(&identity, "hunter2").unwrap();
//!
//! let listener = TcpListener::bind("0.0.0.0:8443").unwrap();
//! let acceptor = TlsAcceptor::new(identity).unwrap();
//! let acceptor = Arc::new(acceptor);
//!
//! fn handle_client(stream: TlsStream<TcpStream>) {
//!     // ...
//! }
//!
//! for stream in listener.incoming() {
//!     match stream {
//!         Ok(stream) => {
//!             let acceptor = acceptor.clone();
//!             thread::spawn(move || {
//!                 let stream = acceptor.accept(stream).unwrap();
//!                 handle_client(stream);
//!             });
//!         }
//!         Err(e) => { /* connection failed */ }
//!     }
//! }
//! ```
mod acceptor;
mod connector;
mod stream;

#[cfg(test)]
mod test;

pub use acceptor::{TlsAcceptor, TlsAcceptorBuilder};
pub use connector::{TlsConnector, TlsConnectorBuilder};
pub use stream::TlsStream;

#[cfg(target_os = "android")]
fn load_android_root_certs(connector: &mut SslContextBuilder) -> crate::Result<()> {
    use openssl::x509::X509;
    use std::fs;

    if let Ok(dir) = fs::read_dir("/system/etc/security/cacerts") {
        let certs = dir
            .filter_map(|r| r.ok())
            .filter_map(|e| fs::read(e.path()).ok())
            .filter_map(|b| X509::from_pem(&b).ok());
        for cert in certs {
            if let Err(err) = connector.cert_store_mut().add_cert(cert) {
                debug!("load_android_root_certs error: {:?}", err);
            }
        }
    }

    Ok(())
}
