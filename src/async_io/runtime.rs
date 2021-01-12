#[cfg(feature = "io-async-std")]
pub(crate) use futures_util::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "io-async-std")]
#[allow(unused_imports)]
pub(crate) use futures_util::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "io-tokio")]
pub(crate) use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
