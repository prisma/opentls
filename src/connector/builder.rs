use openssl::{
    ssl::{SslConnector, SslMethod},
    x509::store::X509StoreBuilder,
};

use crate::{supported_protocols, Certificate, Identity, Protocol, TlsConnector};

/// A builder for `TlsConnector`s.
pub struct TlsConnectorBuilder {
    pub(crate) identity: Option<Identity>,
    pub(crate) min_protocol: Option<Protocol>,
    pub(crate) max_protocol: Option<Protocol>,
    pub(crate) root_certificates: Vec<Certificate>,
    pub(crate) accept_invalid_certs: bool,
    pub(crate) accept_invalid_hostnames: bool,
    pub(crate) use_sni: bool,
    pub(crate) disable_built_in_roots: bool,
}

impl TlsConnectorBuilder {
    /// Sets the identity to be used for client certificate authentication.
    pub fn identity(&mut self, identity: Identity) -> &mut TlsConnectorBuilder {
        self.identity = Some(identity);
        self
    }

    /// Sets the minimum supported protocol version.
    ///
    /// A value of `None` enables support for the oldest protocols supported by the implementation.
    ///
    /// Defaults to `Some(Protocol::Tlsv10)`.
    pub fn min_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut TlsConnectorBuilder {
        self.min_protocol = protocol;
        self
    }

    /// Sets the maximum supported protocol version.
    ///
    /// A value of `None` enables support for the newest protocols supported by the implementation.
    ///
    /// Defaults to `None`.
    pub fn max_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut TlsConnectorBuilder {
        self.max_protocol = protocol;
        self
    }

    /// Adds a certificate to the set of roots that the connector will trust.
    ///
    /// The connector will use the system's trust root by default. This method can be used to add
    /// to that set when communicating with servers not trusted by the system.
    ///
    /// Defaults to an empty set.
    pub fn add_root_certificate(&mut self, cert: Certificate) -> &mut TlsConnectorBuilder {
        self.root_certificates.push(cert);
        self
    }

    /// Controls the use of built-in system certificates during certificate validation.
    ///
    /// Defaults to `false` -- built-in system certs will be used.
    pub fn disable_built_in_roots(&mut self, disable: bool) -> &mut TlsConnectorBuilder {
        self.disable_built_in_roots = disable;
        self
    }

    /// Controls the use of certificate validation.
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If invalid certificates are trusted, *any*
    /// certificate for *any* site will be trusted for use. This includes expired certificates. This introduces
    /// significant vulnerabilities, and should only be used as a last resort.
    pub fn danger_accept_invalid_certs(&mut self, accept_invalid_certs: bool) -> &mut TlsConnectorBuilder {
        self.accept_invalid_certs = accept_invalid_certs;
        self
    }

    /// Controls the use of Server Name Indication (SNI).
    ///
    /// Defaults to `true`.
    pub fn use_sni(&mut self, use_sni: bool) -> &mut TlsConnectorBuilder {
        self.use_sni = use_sni;
        self
    }

    /// Controls the use of hostname verification.
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If invalid hostnames are trusted, *any* valid
    /// certificate for *any* site will be trusted for use. This introduces significant vulnerabilities, and should
    /// only be used as a last resort.
    pub fn danger_accept_invalid_hostnames(&mut self, accept_invalid_hostnames: bool) -> &mut TlsConnectorBuilder {
        self.accept_invalid_hostnames = accept_invalid_hostnames;
        self
    }

    /// Creates a new `TlsConnector`.
    pub fn build(&self) -> crate::Result<TlsConnector> {
        let mut connector = SslConnector::builder(SslMethod::tls())?;

        if let Some(ref identity) = self.identity {
            connector.set_certificate(&identity.cert)?;
            connector.set_private_key(&identity.pkey)?;

            for cert in identity.chain.iter().rev() {
                connector.add_extra_chain_cert(cert.to_owned())?;
            }
        }

        supported_protocols(self.min_protocol, self.max_protocol, &mut connector)?;

        if self.disable_built_in_roots {
            connector.set_cert_store(X509StoreBuilder::new()?.build());
        }

        for cert in &self.root_certificates {
            if let Err(err) = connector.cert_store_mut().add_cert(cert.0.clone()) {
                debug!("add_cert error: {:?}", err);
            }
        }

        #[cfg(target_os = "android")]
        crate::load_android_root_certs(&mut connector)?;

        Ok(TlsConnector {
            connector: connector.build(),
            use_sni: self.use_sni,
            accept_invalid_hostnames: self.accept_invalid_hostnames,
            accept_invalid_certs: self.accept_invalid_certs,
        })
    }
}
