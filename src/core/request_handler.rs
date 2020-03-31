// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use crate::error::{ClientErrorKind, Result};
#[cfg(test)]
use mockstream::SyncMockStream;
use parsec_interface::requests::{Request, Response};
use std::io::{Read, Write};
#[cfg(not(test))]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_MAX_BODY_SIZE: usize = usize::max_value();
const DEFAULT_SOCKET_PATH: &str = "/tmp/security-daemon-socket";

/// Low level client structure to send a `Request` and get a `Response`.
#[derive(Clone)]
#[cfg_attr(not(test), derive(Debug))]
pub struct RequestHandler {
    pub max_body_size: usize,
    pub timeout: Option<Duration>,
    pub socket_path: PathBuf,
    #[cfg(test)]
    pub mock_stream: SyncMockStream,
}

impl RequestHandler {
    /// Send a request and get a response.
    pub fn process_request(&self, request: Request) -> Result<Response> {
        // Try to connect once, wait for a timeout until trying again.
        let mut stream = self.connect_to_socket()?;

        request
            .write_to_stream(&mut stream)
            .map_err(ClientErrorKind::Interface)?;
        Ok(Response::read_from_stream(&mut stream, self.max_body_size)
            .map_err(ClientErrorKind::Interface)?)
    }

    #[cfg(test)]
    fn connect_to_socket(&self) -> Result<impl Read + Write> {
        Ok(self.mock_stream.clone())
    }

    #[cfg(not(test))]
    fn connect_to_socket(&self) -> Result<impl Read + Write> {
        let stream = UnixStream::connect(&self.socket_path).map_err(ClientErrorKind::Ipc)?;

        stream
            .set_read_timeout(self.timeout)
            .map_err(ClientErrorKind::Ipc)?;
        stream
            .set_write_timeout(self.timeout)
            .map_err(ClientErrorKind::Ipc)?;

        Ok(stream)
    }
}

impl Default for RequestHandler {
    fn default() -> Self {
        RequestHandler {
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            timeout: None,
            socket_path: DEFAULT_SOCKET_PATH.into(),
            #[cfg(test)]
            mock_stream: SyncMockStream::new(),
        }
    }
}

impl crate::CoreClient {
    /// Set the maximum body size allowed for requests
    pub fn set_max_body_size(&mut self, max_body_size: usize) {
        self.op_handler.request_handler.max_body_size = max_body_size;
    }

    /// Set the timeout allowed for operations on the IPC used for communicating with the service.
    ///
    /// A value of `None` represents "no timeout"
    pub fn set_ipc_timeout(&mut self, timeout: Option<Duration>) {
        self.op_handler.request_handler.timeout = timeout;
    }

    /// Set the location of the Unix Socket path where the service socket can be found
    pub fn set_socket_path(&mut self, socket_path: PathBuf) {
        self.op_handler.request_handler.socket_path = socket_path;
    }

    /// Test helper used to set the data to be returned from the mock stream
    #[cfg(test)]
    pub fn set_mock_read(&mut self, data: &[u8]) {
        self.op_handler
            .request_handler
            .mock_stream
            .push_bytes_to_read(data);
    }

    /// Test helper used to verify the data written to the mock stream
    #[cfg(test)]
    pub fn get_mock_write(&mut self) -> Vec<u8> {
        self.op_handler
            .request_handler
            .mock_stream
            .pop_bytes_written()
    }
}
