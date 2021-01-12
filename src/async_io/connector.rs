use crate::{
    async_io::{
        handshake::handshake,
        runtime::{AsyncRead, AsyncWrite},
        TlsStream,
    },
    sync_io, Error,
};
use std::{fmt, marker::Unpin};

/// A wrapper around a `sync_io::TlsConnector`, providing an async `connect`
/// method.
#[derive(Clone)]
pub(crate) struct TlsConnector(sync_io::TlsConnector);

impl TlsConnector {
    /// Connects the provided stream with this connector, assuming the provided domain.
    pub(crate) async fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        handshake(move |s| self.0.connect(domain, s), stream).await
    }
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector").finish()
    }
}

impl From<sync_io::TlsConnector> for TlsConnector {
    fn from(inner: sync_io::TlsConnector) -> TlsConnector {
        TlsConnector(inner)
    }
}
