use openssl::{
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    x509::X509,
};

#[derive(Clone)]
pub struct Identity {
    pub(crate) pkey: PKey<Private>,
    pub(crate) cert: X509,
    pub(crate) chain: Vec<X509>,
}

impl Identity {
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
