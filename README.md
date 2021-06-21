# Parsec Rust Client

<p align="center">
  <a href="https://crates.io/crates/parsec-client"><img alt="Crates.io" src="https://img.shields.io/crates/v/parsec-client"></a>
  <a href="https://docs.rs/parsec-client"><img src="https://docs.rs/parsec-client/badge.svg" alt="Code documentation"/></a>
  <a href="https://codecov.io/gh/parallaxsecond/parsec-client-rust"><img src="https://codecov.io/gh/parallaxsecond/parsec-client-rust/branch/master/graph/badge.svg?token=PTSZ6HS2FF"/></a>
</p>

This repository contains a Rust client for consuming the API provided by the [Parsec service](https://github.com/parallaxsecond/parsec).
The low-level functionality that this library uses for IPC is implemented in the [interface crate](https://github.com/parallaxsecond/parsec-interface-rs).

When using the JWT-SVID authentication method, the client will expect the `SPIFFE_ENDPOINT_SOCKET` environment variable to contain the path of the Workload API endpoint.
See the [SPIFFE Workload Endpoint](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Workload_Endpoint.md#4-locating-the-endpoint) for more information.

## Locating the Parsec endpoint

The Rust client follows the [service discovery](https://parallaxsecond.github.io/parsec-book/parsec_client/api_overview.html#service-discovery) policy
to find the Parsec endpoint.

## License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

## Contributing

Please check the [**Contribution Guidelines**](https://parallaxsecond.github.io/parsec-book/contributing/index.html)
to know more about the contribution process.

*Copyright 2020 Contributors to the Parsec project.*
