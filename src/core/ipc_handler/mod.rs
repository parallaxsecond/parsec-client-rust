// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Types implementing an abstraction over IPC channels
use crate::error::{ClientErrorKind, Error, Result};
use std::io::{Read, Write};
use std::time::Duration;
use url::Url;

pub mod unix_socket;

/// Default timeout for client IPC requests.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

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

    /// Set timeout for all produced streams.
    fn set_timeout(&mut self, timeout: Option<Duration>);
}

/// Create an implementation of `Connect` from the socket URL
pub fn connector_from_url(socket_url: Url) -> Result<Box<dyn Connect + Send + Sync>> {
    match socket_url.scheme() {
        "unix" => Ok(Box::from(unix_socket::Handler::new(
            socket_url.path().into(),
            Some(DEFAULT_TIMEOUT),
        )?)),
        _ => Err(Error::Client(ClientErrorKind::InvalidSocketUrl)),
    }
}
