// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Client library for integration with the Parsec service
// #![doc(html_logo_url = "https://www.rust-lang.org/logos/rust-logo-128x128-blk-v2.png")] TODO: Set to Parsec logo
#![deny(
    nonstandard_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]
// This one is hard to avoid.
#![allow(clippy::multiple_crate_versions)]

//! Currently this crate allows interaction with the PARSEC service through
//! [`CoreClient`](core/struct.CoreClient.html), a low-level client that allows all supported operations to
//! be performed, requiring all operation parameters to be provided explicitly.

pub mod auth;
pub mod core;
pub mod error;

pub use crate::core::ipc_client;
pub use crate::core::CoreClient;
