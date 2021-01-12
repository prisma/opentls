mod builder;

use std::{fmt, io};

pub use builder::TlsAcceptorBuilder;
use openssl::ssl::SslAcceptor;

use crate::{sync_io::TlsStream, HandshakeError, Identity, Protocol};

/// A builder for server-side TLS connections.
///
/// # Examples
///
/// ```rust,no_run
/// use opentls::{Identity, sync_io::{TlsAcceptor, TlsStream}};
/// use std::fs::File;
/// use std::io::Read;
/// use std::net::{TcpListener, TcpStream};
/// use std::sync::Arc;
/// use std::thread;
///
/// let mut file = File::open("identity.pfx").unwrap();
/// let mut identity = vec![];
/// file.read_to_end(&mut identity).unwrap();
/// let identity = Identity::from_pkcs12(&identity, "hunter2").unwrap();
///
/// let listener = TcpListener::bind("0.0.0.0:8443").unwrap();
/// let acceptor = TlsAcceptor::new(identity).unwrap();
/// let acceptor = Arc::new(acceptor);
///
/// fn handle_client(stream: TlsStream<TcpStream>) {
///     // ...
/// }
///
/// for stream in listener.incoming() {
///     match stream {
///         Ok(stream) => {
///             let acceptor = acceptor.clone();
///             thread::spawn(move || {
///                 let stream = acceptor.accept(stream).unwrap();
///                 handle_client(stream);
///             });
///         }
///         Err(e) => { /* connection failed */ }
///     }
/// }
/// ```
#[derive(Clone)]
pub struct TlsAcceptor(pub(crate) SslAcceptor);

impl fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptor").finish()
    }
}

impl TlsAcceptor {
    /// Creates a acceptor with default settings.
    ///
    /// The identity acts as the server's private key/certificate chain.
    pub fn new(identity: Identity) -> crate::Result<TlsAcceptor> {
        Self::builder(identity).build()
    }

    /// Returns a new builder for a `TlsAcceptor`.
    ///
    /// The identity acts as the server's private key/certificate chain.
    pub fn builder(identity: Identity) -> TlsAcceptorBuilder {
        TlsAcceptorBuilder {
            identity,
            min_protocol: Some(Protocol::Tlsv10),
            max_protocol: None,
        }
    }

    /// Initiates a TLS handshake.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::WouldBlock` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let s = self.0.accept(stream)?;
        Ok(TlsStream(s))
    }
}
