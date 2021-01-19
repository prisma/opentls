mod builder;

pub use builder::TlsConnectorBuilder;

use crate::{sync_io::TlsStream, HandshakeError, Protocol};
use openssl::ssl::{SslConnector, SslVerifyMode};
use std::{fmt, io};

/// A builder for client-side TLS connections.
///
/// # Examples
///
/// ```rust
/// use opentls::sync_io::TlsConnector;
/// use std::io::{Read, Write};
/// use std::net::TcpStream;
///
/// let connector = TlsConnector::new().unwrap();
///
/// let stream = TcpStream::connect("google.com:443").unwrap();
/// let mut stream = connector.connect("google.com", stream).unwrap();
///
/// stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
/// let mut res = vec![];
/// stream.read_to_end(&mut res).unwrap();
/// println!("{}", String::from_utf8_lossy(&res));
/// ```
#[derive(Clone)]
pub struct TlsConnector {
    connector: SslConnector,
    use_sni: bool,
    accept_invalid_hostnames: bool,
    accept_invalid_certs: bool,
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("TlsConnector")
            // n.b. SslConnector is a newtype on SslContext which implements a noop Debug so it's omitted
            .field("use_sni", &self.use_sni)
            .field("accept_invalid_hostnames", &self.accept_invalid_hostnames)
            .field("accept_invalid_certs", &self.accept_invalid_certs)
            .finish()
    }
}

impl TlsConnector {
    /// Returns a new connector with default settings.
    pub fn new() -> crate::Result<Self> {
        Self::builder().build()
    }

    /// Returns a new builder for a `TlsConnector`.
    pub fn builder() -> TlsConnectorBuilder {
        TlsConnectorBuilder {
            identity: None,
            min_protocol: Some(Protocol::Tlsv10),
            max_protocol: None,
            root_certificates: vec![],
            use_sni: true,
            accept_invalid_certs: false,
            accept_invalid_hostnames: false,
            disable_built_in_roots: false,
        }
    }

    /// Initiates a TLS handshake.
    ///
    /// The provided domain will be used for both SNI and certificate hostname
    /// validation.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::WouldBlock` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    ///
    /// The domain is ignored if both SNI and hostname verification are
    /// disabled.
    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let mut ssl = self
            .connector
            .configure()?
            .use_server_name_indication(self.use_sni)
            .verify_hostname(!self.accept_invalid_hostnames);

        if self.accept_invalid_certs {
            ssl.set_verify(SslVerifyMode::NONE);
        }

        Ok(TlsStream(ssl.connect(domain, stream)?))
    }
}
