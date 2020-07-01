// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Core helpers for integration with the Parsec service
//!
//! The `interface` module is a version of the [`parsec-interface`](https://crates.io/crates/parsec-interface)
//! crate and is meant to be used in conjuction with the [basic](basic_client/struct.BasicClient.html),
//! [operation](operation_client/struct.OperationClient.html) and [request](request_client/struct.RequestClient.html)
//! structures.
pub mod basic_client;
pub mod ipc_handler;
pub mod operation_client;
pub mod request_client;
mod testing;

/// Resurfacing of the Secrecy library used by the client.
pub use interface::secrecy;
/// Resurfacing of the Parsec interface library used by the client.
pub use parsec_interface as interface;
