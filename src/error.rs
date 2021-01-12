use openssl::{error::ErrorStack, ssl, x509::X509VerifyResult};
use std::{error, fmt, io};

/// An error returned from the TLS implementation.
#[derive(Debug)]
pub enum Error {
    /// Collection of [`Error`]s from OpenSSL.
    Normal(ErrorStack),
    /// An SSL error.
    Ssl(ssl::Error, X509VerifyResult),
    /// An I/O error.
    Io(io::Error),
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::Normal(ref e) => error::Error::source(e),
            Error::Ssl(ref e, _) => error::Error::source(e),
            Error::Io(ref e) => error::Error::source(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Normal(ref e) => fmt::Display::fmt(e, fmt),
            Error::Io(ref e) => fmt::Display::fmt(e, fmt),
            Error::Ssl(ref e, X509VerifyResult::OK) => fmt::Display::fmt(e, fmt),
            Error::Ssl(ref e, v) => write!(fmt, "{} ({})", e, v),
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Error {
        Error::Normal(err)
    }
}

impl From<io::Error> for Error {
    fn from(inner: io::Error) -> Self {
        Self::Io(inner)
    }
}

/// An error returned from `ClientBuilder::handshake`.
#[derive(Debug)]
pub enum HandshakeError<S> {
    /// A fatal error.
    Failure(Error),
    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    ///
    /// Note that this is not a fatal error and it should be safe to call
    /// `handshake` at a later time once the stream is ready to perform I/O
    /// again.
    WouldBlock(ssl::MidHandshakeSslStream<S>),
}

impl<S> From<ssl::HandshakeError<S>> for HandshakeError<S> {
    fn from(e: ssl::HandshakeError<S>) -> HandshakeError<S> {
        match e {
            ssl::HandshakeError::SetupFailure(e) => HandshakeError::Failure(e.into()),
            ssl::HandshakeError::Failure(e) => {
                let v = e.ssl().verify_result();
                HandshakeError::Failure(crate::Error::Ssl(e.into_error(), v))
            }
            ssl::HandshakeError::WouldBlock(s) => HandshakeError::WouldBlock(s),
        }
    }
}

impl<S> From<ErrorStack> for HandshakeError<S> {
    fn from(e: ErrorStack) -> HandshakeError<S> {
        HandshakeError::Failure(e.into())
    }
}
