mod acceptor;
mod connector;
mod stream;

#[cfg(test)]
mod test;

pub use acceptor::{TlsAcceptor, TlsAcceptorBuilder};
pub use connector::{TlsConnector, TlsConnectorBuilder};
pub use stream::TlsStream;

#[cfg(target_os = "android")]
fn load_android_root_certs(connector: &mut SslContextBuilder) -> crate::Result<()> {
    use openssl::x509::X509;
    use std::fs;

    if let Ok(dir) = fs::read_dir("/system/etc/security/cacerts") {
        let certs = dir
            .filter_map(|r| r.ok())
            .filter_map(|e| fs::read(e.path()).ok())
            .filter_map(|b| X509::from_pem(&b).ok());
        for cert in certs {
            if let Err(err) = connector.cert_store_mut().add_cert(cert) {
                debug!("load_android_root_certs error: {:?}", err);
            }
        }
    }

    Ok(())
}
