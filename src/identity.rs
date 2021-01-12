use std::fmt;

use openssl::{
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    x509::X509,
};

/// A cryptographic identity.
///
/// An identity is an X509 certificate along with its corresponding private key and chain of certificates to a trusted
/// root.
#[derive(Clone)]
pub struct Identity {
    pub(crate) pkey: PKey<Private>,
    pub(crate) cert: X509,
    pub(crate) chain: Vec<X509>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity").finish()
    }
}

impl Identity {
    /// Parses a DER-formatted PKCS #12 archive, using the specified password to decrypt the key.
    ///
    /// The archive should contain a leaf certificate and its private key, as well any intermediate
    /// certificates that should be sent to clients to allow them to build a chain to a trusted
    /// root. The chain certificates should be in order from the leaf certificate towards the root.
    ///
    /// PKCS #12 archives typically have the file extension `.p12` or `.pfx`, and can be created
    /// with the OpenSSL `pkcs12` tool:
    ///
    /// ```bash
    /// openssl pkcs12 -export -out identity.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
    /// ```
    pub fn from_pkcs12(buf: &[u8], pass: &str) -> crate::Result<Self> {
        let pkcs12 = Pkcs12::from_der(buf)?;
        let parsed = pkcs12.parse(pass)?;

        Ok(Identity {
            pkey: parsed.pkey,
            cert: parsed.cert,
            chain: parsed.chain.into_iter().flatten().collect(),
        })
    }
}
