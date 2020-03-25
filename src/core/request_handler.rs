// Copyright (c) 2020, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![allow(dead_code)]

use crate::error::{ClientErrorKind, Error, Result};
use parsec_interface::requests::{Request, Response};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_MAX_BODY_SIZE: usize = 1 << 31;
const DEFAULT_SOCKET_PATH: &str = "/tmp/security-daemon-socket";

/// Low level client structure to send a `Request` and get a `Response`.
#[derive(Clone, Debug)]
pub struct RequestHandler {
    pub max_body_size: usize,
    pub timeout: Option<Duration>,
    pub socket_path: PathBuf,
}

impl RequestHandler {
    /// Send a request and get a response.
    pub fn process_request(&self, request: Request) -> Result<Response> {
        // Try to connect once, wait for a timeout until trying again.
        let mut stream = UnixStream::connect(&self.socket_path).map_err(ClientErrorKind::Ipc)?;

        stream
            .set_read_timeout(self.timeout)
            .map_err(ClientErrorKind::Ipc)?;
        stream
            .set_write_timeout(self.timeout)
            .map_err(ClientErrorKind::Ipc)?;

        request
            .write_to_stream(&mut stream)
            .map_err(ClientErrorKind::Interface)?;
        Ok(Response::read_from_stream(&mut stream, self.max_body_size).map_err(Error::Service)?)
    }
}

impl Default for RequestHandler {
    fn default() -> Self {
        RequestHandler {
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            timeout: None,
            socket_path: DEFAULT_SOCKET_PATH.into(),
        }
    }
}
