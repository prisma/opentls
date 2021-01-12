use crate::Certificate;
use openssl::{hash::MessageDigest, nid::Nid, ssl};
use std::{fmt, io};

/// A stream managing a TLS session.
pub struct TlsStream<S>(pub(crate) ssl::SslStream<S>);

impl<S: fmt::Debug> fmt::Debug for TlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> TlsStream<S> {
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S: io::Read + io::Write> TlsStream<S> {
    /// Returns the number of bytes that can be read without resulting in any
    /// network calls.
    pub fn buffered_read_size(&self) -> crate::Result<usize> {
        Ok(self.0.ssl().pending())
    }

    /// Returns the peer's leaf certificate, if available.
    pub fn peer_certificate(&self) -> crate::Result<Option<Certificate>> {
        Ok(self.0.ssl().peer_certificate().map(Certificate::from))
    }

    /// Returns the tls-server-end-point channel binding data as defined in [RFC 5929].
    ///
    /// [RFC 5929]: https://tools.ietf.org/html/rfc5929
    pub fn tls_server_end_point(&self) -> crate::Result<Option<Vec<u8>>> {
        let cert = if self.0.ssl().is_server() {
            self.0.ssl().certificate().map(|x| x.to_owned())
        } else {
            self.0.ssl().peer_certificate()
        };

        let cert = match cert {
            Some(cert) => cert,
            None => return Ok(None),
        };

        let algo_nid = cert.signature_algorithm().object().nid();
        let signature_algorithms = match algo_nid.signature_algorithms() {
            Some(algs) => algs,
            None => return Ok(None),
        };

        let md = match signature_algorithms.digest {
            Nid::MD5 | Nid::SHA1 => MessageDigest::sha256(),
            nid => match MessageDigest::from_nid(nid) {
                Some(md) => md,
                None => return Ok(None),
            },
        };

        let digest = cert.digest(md)?;

        Ok(Some(digest.to_vec()))
    }

    /// Shuts down the TLS session.
    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.0.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == ssl::ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(e
                .into_io_error()
                .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e))),
        }
    }
}

impl<S: io::Read + io::Write> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
