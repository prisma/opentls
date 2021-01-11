# OpenTLS for Rust

Implementing TLS with OpenSSL either asynchronously or as a synchronous version. If looking for a good TLS implementation, it's highly recommended using either [native-tls](https://crates.io/crates/native-tls) for synchronous connections or [async-native-tls](https://crates.io/crates/async-native-tls). Use this crate only if you cannot rely on the libraries provided by the operating system, and have some special needs such as always linking to OpenSSL statically. In general, you probably should not use this crate.
