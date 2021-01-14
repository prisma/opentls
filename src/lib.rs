//! TLS streams using OpenSSL.
//!
//! This crate is meant for cases when it is important to use OpenSSL for the
//! TLS implementation, allowing vendoring on platforms other than Linux. In
//! many cases it is recommended to use the TLS facilities of the platform, and
//! using either [native-tls](https://crates.io/crates/native-tls) for sync or
//! [async-native-tls](https://crates.io/crates/async-native-tls) for async
//! transport.
//!
//! If system TLS cannot be used, this crate provides the same api as the crates
//! mentioned above, but links always with OpenSSL.
//!
//! # Cargo Features
//!
//! * `vendored` - If enabled, the crate will compile and statically link to a
//!   vendored copy of OpenSSL.
//! * `io-tokio` - Enables asynchronous IO with Tokio runtime.
//! * `io-async-std` - Enables asynchronous IO with async-std runtime.
#![cfg_attr(feature = "docs", feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(missing_debug_implementations, rust_2018_idioms)]
#![doc(test(attr(deny(rust_2018_idioms, warnings))))]
#![doc(test(attr(allow(unused_extern_crates, unused_variables))))]

#[macro_use]
extern crate log;

#[cfg(all(feature = "io-tokio", feature = "io-async-std"))]
compile_error!("only one of 'async-std' or 'async-tokio' features must be enabled");

#[cfg(any(feature = "io-tokio", feature = "io-async-std"))]
#[cfg_attr(feature = "docs", doc(cfg(any(feature = "io-tokio", feature = "io-async-std"))))]
pub mod async_io;
pub mod sync_io;

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
#[non_exhaustive]
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
    };
    options |= match max {
        None | Some(Protocol::Tlsv12) => SslOptions::empty(),
        Some(Protocol::Tlsv11) => SslOptions::NO_TLSV1_2,
        Some(Protocol::Tlsv10) => SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2,
        Some(Protocol::Sslv3) => SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1 | SslOptions::NO_TLSV1_2,
    };

    ctx.set_options(options);

    Ok(())
}
