mod acceptor;
mod certificate;
mod connector;
mod error;
mod identity;
mod stream;

#[cfg(test)]
mod test;

pub use acceptor::{TlsAcceptor, TlsAcceptorBuilder};
pub use certificate::Certificate;
pub use connector::{TlsConnector, TlsConnectorBuilder};
pub use error::{Error, HandshakeError};
pub use identity::Identity;
use openssl::{error::ErrorStack, ssl::SslContextBuilder};
use std::result;
pub use stream::TlsStream;

#[macro_use]
extern crate log;

/// A typedef of the result-type returned by many methods.
pub type Result<T> = result::Result<T, Error>;

/// SSL/TLS protocol versions.
#[derive(Debug, Copy, Clone)]
pub enum Protocol {
    /// The SSL 3.0 protocol.
    ///
    /// # Warning
    ///
    /// SSL 3.0 has severe security flaws, and should not be used unless absolutely necessary. If
    /// you are not sure if you need to enable this protocol, you should not.
    Sslv3,
    /// The TLS 1.0 protocol.
    Tlsv10,
    /// The TLS 1.1 protocol.
    Tlsv11,
    /// The TLS 1.2 protocol.
    Tlsv12,
    #[doc(hidden)]
    __NonExhaustive,
}

fn _check_kinds() {
    use std::net::TcpStream;

    fn is_sync<T: Sync>() {}
    fn is_send<T: Send>() {}
    is_sync::<Error>();
    is_send::<Error>();
    is_sync::<TlsConnectorBuilder>();
    is_send::<TlsConnectorBuilder>();
    is_sync::<TlsConnector>();
    is_send::<TlsConnector>();
    is_sync::<TlsAcceptorBuilder>();
    is_send::<TlsAcceptorBuilder>();
    is_sync::<TlsAcceptor>();
    is_send::<TlsAcceptor>();
    is_sync::<TlsStream<TcpStream>>();
    is_send::<TlsStream<TcpStream>>();
}

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

#[cfg(have_min_max_version)]
fn supported_protocols(
    min: Option<Protocol>,
    max: Option<Protocol>,
    ctx: &mut SslContextBuilder,
) -> std::result::Result<(), ErrorStack> {
    use openssl::ssl::SslVersion;

    fn cvt(p: Protocol) -> SslVersion {
        match p {
            Protocol::Sslv3 => SslVersion::SSL3,
            Protocol::Tlsv10 => SslVersion::TLS1,
            Protocol::Tlsv11 => SslVersion::TLS1_1,
            Protocol::Tlsv12 => SslVersion::TLS1_2,
            Protocol::__NonExhaustive => unreachable!(),
        }
    }

    ctx.set_min_proto_version(min.map(cvt))?;
    ctx.set_max_proto_version(max.map(cvt))?;

    Ok(())
}

#[cfg(not(have_min_max_version))]
fn supported_protocols(
    min: Option<Protocol>,
    max: Option<Protocol>,
    ctx: &mut SslContextBuilder,
) -> std::result::Result<(), ErrorStack> {
    use openssl::ssl::SslOptions;

    let no_ssl_mask = SslOptions::NO_SSLV2
        | SslOptions::NO_SSLV3
        | SslOptions::NO_TLSV1
        | SslOptions::NO_TLSV1_1
        | SslOptions::NO_TLSV1_2;

    ctx.clear_options(no_ssl_mask);
    let mut options = SslOptions::empty();
    options |= match min {
        None => SslOptions::empty(),
        Some(Protocol::Sslv3) => SslOptions::NO_SSLV2,
        Some(Protocol::Tlsv10) => SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3,
        Some(Protocol::Tlsv11) => {
            SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1
        }
        Some(Protocol::Tlsv12) => {
            SslOptions::NO_SSLV2
                | SslOptions::NO_SSLV3
                | SslOptions::NO_TLSV1
                | SslOptions::NO_TLSV1_1
        }
        Some(Protocol::__NonExhaustive) => unreachable!(),
    };
    options |= match max {
        None | Some(Protocol::Tlsv12) => SslOptions::empty(),
        Some(Protocol::Tlsv11) => SslOptions::NO_TLSV1_2,
        Some(Protocol::Tlsv10) => SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2,
        Some(Protocol::Sslv3) => {
            SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2
        }
        Some(Protocol::__NonExhaustive) => unreachable!(),
    };

    ctx.set_options(options);

    Ok(())
}
