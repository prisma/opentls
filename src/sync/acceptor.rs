mod builder;

use std::io;

pub use builder::TlsAcceptorBuilder;
use openssl::ssl::SslAcceptor;

use crate::{sync::TlsStream, HandshakeError, Identity, Protocol};

/// A builder for server-side TLS connections.
///
/// # Examples
///
/// ```rust,no_run
/// use opentls::{Identity, sync::{TlsAcceptor, TlsStream}};
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

    pub fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let s = self.0.accept(stream)?;
        Ok(TlsStream(s))
    }
}
