// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Types implementing an abstraction over IPC channels
use crate::error::Result;
use std::io::{Read, Write};

pub mod unix_socket;

/// This trait is created to allow the iterator returned by incoming to iterate over a trait object
/// that implements both Read and Write.
pub trait ReadWrite: Read + Write {}
// Automatically implements ReadWrite for all types that implement Read and Write.
impl<T: Read + Write> ReadWrite for T {}

/// Trait that must be implemented by any IPC client
///
/// The trait is used by the request handler for obtaining a stream to the service.
pub trait Connect {
    /// Connect to underlying IPC and return a readable and writeable stream
    fn connect(&self) -> Result<Box<dyn ReadWrite>>;
}
