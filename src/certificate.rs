use openssl::x509::X509;

/// An X509 certificate.
#[derive(Clone, Debug)]
pub struct Certificate(pub(crate) X509);

impl Certificate {
    /// Parses a DER-formatted X509 certificate.
    pub fn from_der(buf: &[u8]) -> crate::Result<Certificate> {
        let cert = X509::from_der(buf)?;
        Ok(Certificate(cert))
    }

    /// Parses a PEM-formatted X509 certificate.
    pub fn from_pem(buf: &[u8]) -> crate::Result<Certificate> {
        let cert = X509::from_pem(buf)?;
        Ok(Certificate(cert))
    }

    /// Returns the DER-encoded representation of this certificate.
    pub fn to_der(&self) -> crate::Result<Vec<u8>> {
        let der = self.0.to_der()?;
        Ok(der)
    }
}

impl From<X509> for Certificate {
    fn from(inner: X509) -> Self {
        Self(inner)
    }
}
