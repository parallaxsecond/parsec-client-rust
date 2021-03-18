# Parsec Rust Client

<p align="center">
  <a href="https://crates.io/crates/parsec-client"><img alt="Crates.io" src="https://img.shields.io/crates/v/parsec-client"></a>
  <a href="https://docs.rs/parsec-client"><img src="https://docs.rs/parsec-client/badge.svg" alt="Code documentation"/></a>
  <a href="https://codecov.io/gh/parallaxsecond/parsec-client-rust"><img src="https://codecov.io/gh/parallaxsecond/parsec-client-rust/branch/master/graph/badge.svg?token=PTSZ6HS2FF"/></a>
</p>

This repository contains a Rust client for consuming the API provided by the [Parsec service](https://github.com/parallaxsecond/parsec).
The low-level functionality that this library uses for IPC is implemented in the [interface crate](https://github.com/parallaxsecond/parsec-interface-rs).

Check out the `spiffe` branch for JWT SVID authentication feature.

## Locating the Parsec endpoint

The Rust client follows the [service discovery](https://parallaxsecond.github.io/parsec-book/parsec_client/api_overview.html#service-discovery) policy
to find the Parsec endpoint.

## License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

## Contributing

Please check the [**Contribution Guidelines**](https://parallaxsecond.github.io/parsec-book/contributing/index.html)
to know more about the contribution process.

*Copyright 2020 Contributors to the Parsec project.*
