use std::fmt;
use std::marker::Unpin;

use crate::{
    async_io::{
        handshake::handshake,
        runtime::{AsyncRead, AsyncReadExt, AsyncWrite},
        TlsStream,
    },
    sync_io, Identity,
};

/// A wrapper around a `native_tls::TlsAcceptor`, providing an async `accept`
/// method.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "io-async-std")]
/// # fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> { async_std::task::block_on(async {
/// #
/// use async_std::prelude::*;
/// use async_std::net::TcpListener;
/// use async_std::fs::File;
/// use opentls::async_io::TlsAcceptor;
///
/// let key = File::open("tests/identity.pfx").await?;
/// let acceptor = TlsAcceptor::new(key, "hello").await?;
/// let listener = TcpListener::bind("127.0.0.1:8443").await?;
/// let mut incoming = listener.incoming();
///
/// while let Some(stream) = incoming.next().await {
///     let acceptor = acceptor.clone();
///     let stream = stream?;
///     async_std::task::spawn(async move {
///         let stream = acceptor.accept(stream).await.unwrap();
///         // handle stream here
///     });
/// }
/// #
/// # Ok(()) }) }
/// # #[cfg(feature = "io-tokio")]
/// # fn main() {}
/// ```
#[derive(Clone)]
pub struct TlsAcceptor(sync_io::TlsAcceptor);

impl TlsAcceptor {
    /// Create a new TlsAcceptor based on an identity file and matching password.
    pub async fn new<R, S>(mut file: R, password: S) -> crate::Result<Self>
    where
        R: AsyncRead + Unpin,
        S: AsRef<str>,
    {
        let mut identity = vec![];
        file.read_to_end(&mut identity).await?;

        let identity = Identity::from_pkcs12(&identity, password.as_ref())?;
        Ok(TlsAcceptor(sync_io::TlsAcceptor::new(identity)?))
    }

    /// Accepts a new client connection with the provided stream.
    ///
    /// This function will internally call `TlsAcceptor::accept` to connect
    /// the stream and returns a future representing the resolution of the
    /// connection operation. The returned future will resolve to either
    /// `TlsStream<S>` or `Error` depending if it's successful or not.
    ///
    /// This is typically used after a new socket has been accepted from a
    /// `TcpListener`. That socket is then passed to this function to perform
    /// the server half of accepting a client connection.
    pub async fn accept<S>(&self, stream: S) -> crate::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let stream = handshake(move |s| self.0.accept(s), stream).await?;
        Ok(stream)
    }
}

impl fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptor").finish()
    }
}

impl From<sync_io::TlsAcceptor> for TlsAcceptor {
    fn from(inner: sync_io::TlsAcceptor) -> TlsAcceptor {
        TlsAcceptor(inner)
    }
}

#[cfg(all(test, feature = "io-async-std"))]
mod tests {
    use super::*;
    use crate::async_io::{runtime::AsyncWriteExt, TlsConnector};
    use async_std::{
        fs::File,
        net::{TcpListener, TcpStream},
        stream::StreamExt,
    };

    #[async_std::test]
    async fn test_acceptor() {
        let key = File::open("tests/identity.pfx").await.unwrap();
        let acceptor = TlsAcceptor::new(key, "hello").await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:8443").await.unwrap();
        async_std::task::spawn(async move {
            let mut incoming = listener.incoming();

            while let Some(stream) = incoming.next().await {
                let acceptor = acceptor.clone();
                let stream = stream.unwrap();
                async_std::task::spawn(async move {
                    let mut stream = acceptor.accept(stream).await.unwrap();
                    stream.write_all(b"hello").await.unwrap();
                });
            }
        });

        let stream = TcpStream::connect("127.0.01:8443").await.unwrap();
        let connector = TlsConnector::new().danger_accept_invalid_certs(true);

        let mut stream = connector.connect("127.0.0.1", stream).await.unwrap();
        let mut res = Vec::new();
        stream.read_to_end(&mut res).await.unwrap();
        assert_eq!(res, b"hello");
    }
}
