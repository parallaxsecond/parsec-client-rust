<!--
  -- Copyright 2020 Contributors to the Parsec project. 
  -- SPDX-License-Identifier: Apache-2.0
--->
# Parsec Rust Client

This repository contains a Rust client for consuming the API provided by the [Parsec service](https://github.com/parallaxsecond/parsec).
The low-level functionality that this library uses for IPC is implemented in the [interface crate](https://github.com/parallaxsecond/parsec-interface-rs).

When using the JWT-SVID authentication method, the client will expect the `SPIFFE_ENDPOINT_SOCKET` environment variable to contain the path of the Workload API endpoint.
See the [SPIFFE Workload Endpoint](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Workload_Endpoint.md#4-locating-the-endpoint) for more information.

## License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

## Contributing

Please check the [**Contribution Guidelines**](https://parallaxsecond.github.io/parsec-book/contributing.html)
to know more about the contribution process.
