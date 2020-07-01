<!--
  -- Copyright 2020 Contributors to the Parsec project. 
  -- SPDX-License-Identifier: Apache-2.0
--->
# Parsec Rust Client

This repository contains a Rust client for consuming the API provided by the [Parsec service](https://github.com/parallaxsecond/parsec).
The low-level functionality that this library uses for IPC is implemented in the [interface crate](https://github.com/parallaxsecond/parsec-interface-rs).

## Filesystem permission check

To make sure that the client is communicating with a trusted Parsec service, some permission checks
are done on the socket location. Please see the
[Recommendations for Secure Deployment](https://parallaxsecond.github.io/parsec-book/threat_model/secure_deployment.html)
for more information.
This feature is activated by default but, knowing the risks, you can remove it with:
```
cargo build --features no-fs-permission-check
```
It is also desactivated for testing.

## License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

This project uses the following third party crates:
* num (MIT and Apache-2.0)
* rand (Apache-2.0)
* log (Apache-2.0)
* derivative (MIT and Apache-2.0)
* mockstream (MIT)
* uuid (MIT and Apache-2.0)
* users (MIT)

## Contributing

Please check the [**Contribution Guidelines**](https://parallaxsecond.github.io/parsec-book/contributing.html)
to know more about the contribution process.
