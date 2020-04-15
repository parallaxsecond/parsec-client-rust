// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Request-level client
use super::ipc_handler::{unix_socket, Connect};
use crate::error::{ClientErrorKind, Result};
use derivative::Derivative;
use parsec_interface::requests::{Request, Response};

const DEFAULT_MAX_BODY_SIZE: usize = usize::max_value();

/// Low level client structure optimised for communicating with the service
/// at a request level of abstraction.
///
/// Usage is recommended when fine control over the request header and IPC handler
/// is needed.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct RequestClient {
    /// Max size for response bodies
    ///
    /// Defaults to the max value of `usize` on the current platform
    pub max_body_size: usize,
    /// Handler for IPC-related functionality
    ///
    /// Defaults to using Unix domain sockets
    #[derivative(Debug = "ignore")]
    pub ipc_handler: Box<dyn Connect>,
}

impl RequestClient {
    /// Send a request and get a response.
    pub fn process_request(&self, request: Request) -> Result<Response> {
        // Try to connect once, wait for a timeout until trying again.
        let mut stream = self.ipc_handler.connect()?;

        request
            .write_to_stream(&mut stream)
            .map_err(ClientErrorKind::Interface)?;
        Ok(Response::read_from_stream(&mut stream, self.max_body_size)
            .map_err(ClientErrorKind::Interface)?)
    }
}

impl Default for RequestClient {
    fn default() -> Self {
        RequestClient {
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            ipc_handler: Box::from(unix_socket::Handler::default()),
        }
    }
}

/// Configuration methods for controlling IPC-level options.
impl crate::BasicClient {
    /// Set the maximum body size allowed for requests.
    ///
    /// Defaults to the maximum value of `usize`.
    pub fn set_max_body_size(&mut self, max_body_size: usize) {
        self.op_client.request_client.max_body_size = max_body_size;
    }

    /// Set the IPC handler used for communication with the service.
    ///
    /// By default the [Unix domain socket client](../ipc_handler/unix_socket/struct.Client.html) is used.
    pub fn set_ipc_handler(&mut self, ipc_handler: Box<dyn Connect>) {
        self.op_client.request_client.ipc_handler = ipc_handler;
    }
}
