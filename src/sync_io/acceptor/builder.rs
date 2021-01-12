use super::{Identity, Protocol, TlsAcceptor};
use openssl::ssl::{SslAcceptor, SslMethod};

/// A builder for `TlsAcceptor`s.
#[derive(Debug)]
pub struct TlsAcceptorBuilder {
    pub(crate) identity: Identity,
    pub(crate) min_protocol: Option<Protocol>,
    pub(crate) max_protocol: Option<Protocol>,
}

impl TlsAcceptorBuilder {
    /// Sets the minimum supported protocol version.
    ///
    /// A value of `None` enables support for the oldest protocols supported by the implementation.
    ///
    /// Defaults to `Some(Protocol::Tlsv10)`.
    pub fn min_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut Self {
        self.min_protocol = protocol;
        self
    }

    /// Sets the maximum supported protocol version.
    ///
    /// A value of `None` enables support for the newest protocols supported by the implementation.
    ///
    /// Defaults to `None`.
    pub fn max_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut Self {
        self.max_protocol = protocol;
        self
    }

    /// Creates a new `TlsAcceptor`.
    pub fn build(&self) -> crate::Result<TlsAcceptor> {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        acceptor.set_private_key(&self.identity.pkey)?;
        acceptor.set_certificate(&self.identity.cert)?;

        for cert in self.identity.chain.iter().rev() {
            acceptor.add_extra_chain_cert(cert.to_owned())?;
        }

        crate::supported_protocols(self.min_protocol, self.max_protocol, &mut acceptor)?;

        Ok(TlsAcceptor(acceptor.build()))
    }
}
