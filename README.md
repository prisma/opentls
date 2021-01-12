<h1 align="center">opentls</h1>
<div align="center">
  <strong>
  Sync and async TLS streams using OpenSSL
  </strong>
</div>

<br />

<div align="center">
  <!-- Crates version -->
  <a href="https://crates.io/crates/opentls">
    <img src="https://img.shields.io/crates/v/opentls.svg?style=flat-square"
    alt="Crates.io version" />
  </a>
  <!-- Downloads -->
  <a href="https://crates.io/crates/opentls">
    <img src="https://img.shields.io/crates/d/opentls.svg?style=flat-square"
      alt="Download" />
  </a>
  <!-- docs.rs docs -->
  <a href="https://docs.rs/opentls">
    <img src="https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square"
      alt="docs.rs docs" />
  </a>
</div>

<div align="center">
  <h3>
    <a href="https://docs.rs/opentls">
      API Docs
    </a>
    <span> | </span>
    <a href="https://github.com/prisma/opentls/releases">
      Releases
    </a>
    <span> | </span>
    <a href="https://github.com/prisma/opentls/blob/main/.github/CONTRIBUTING.md">
      Contributing
    </a>
  </h3>
</div>

## About

Implementing TLS with OpenSSL either asynchronously or as a synchronous version.
If looking for a good TLS implementation, it is highly recommended to use either
[native-tls](https://crates.io/crates/native-tls) for synchronous connections or
[async-native-tls](https://crates.io/crates/async-native-tls). Use this crate
only if you cannot rely on the libraries provided by the operating system, and
have some special needs such as always linking to OpenSSL statically. In
general, you probably should not use this crate.

## Installation for Rust

```sh
$ cargo add opentls
```

## Security

If you have a security issue to report, please contact us at [security@prisma.io](mailto:security@prisma.io?subject=[GitHub]%20Prisma%202%20Security%20Report%20Tiberius)
