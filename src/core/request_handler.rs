// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::ipc_client::{unix_socket, Connect};
use crate::error::{ClientErrorKind, Result};
use derivative::Derivative;
use parsec_interface::requests::{Request, Response};

const DEFAULT_MAX_BODY_SIZE: usize = usize::max_value();

/// Low level client structure to send a `Request` and get a `Response`.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct RequestHandler {
    pub max_body_size: usize,
    #[derivative(Debug = "ignore")]
    pub ipc_client: Box<dyn Connect>,
}

impl RequestHandler {
    /// Send a request and get a response.
    pub fn process_request(&self, request: Request) -> Result<Response> {
        // Try to connect once, wait for a timeout until trying again.
        let mut stream = self.ipc_client.connect()?;

        request
            .write_to_stream(&mut stream)
            .map_err(ClientErrorKind::Interface)?;
        Ok(Response::read_from_stream(&mut stream, self.max_body_size)
            .map_err(ClientErrorKind::Interface)?)
    }
}

impl Default for RequestHandler {
    fn default() -> Self {
        RequestHandler {
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            ipc_client: Box::from(unix_socket::Client::default()),
        }
    }
}

impl crate::CoreClient {
    /// Set the maximum body size allowed for requests
    pub fn set_max_body_size(&mut self, max_body_size: usize) {
        self.op_handler.request_handler.max_body_size = max_body_size;
    }

    /// Set the IPC handler used for communication with the service
    pub fn set_ipc_client(&mut self, ipc_client: Box<dyn Connect>) {
        self.op_handler.request_handler.ipc_client = ipc_client;
    }
}
