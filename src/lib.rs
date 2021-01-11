#[macro_use]
extern crate log;

pub mod sync;

mod certificate;
mod error;
mod identity;

pub use certificate::Certificate;
pub use error::{Error, HandshakeError};
pub use identity::Identity;

use openssl::{error::ErrorStack, ssl::SslContextBuilder};
use std::result;

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
        Some(Protocol::Tlsv11) => SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1,
        Some(Protocol::Tlsv12) => {
            SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1
        }
        Some(Protocol::__NonExhaustive) => unreachable!(),
    };
    options |= match max {
        None | Some(Protocol::Tlsv12) => SslOptions::empty(),
        Some(Protocol::Tlsv11) => SslOptions::NO_TLSV1_2,
        Some(Protocol::Tlsv10) => SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2,
        Some(Protocol::Sslv3) => SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2,
        Some(Protocol::__NonExhaustive) => unreachable!(),
    };

    ctx.set_options(options);

    Ok(())
}
