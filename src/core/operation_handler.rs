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

use super::request_handler::RequestHandler;
use crate::auth::AuthenticationData;
use derivative::Derivative;
use parsec_interface::operations::{Convert, NativeOperation, NativeResult};
use parsec_interface::operations_protobuf::ProtobufConverter;
use parsec_interface::requests::{
    request::RequestHeader, BodyType, ProviderID, Request, Response, ResponseStatus, Result,
};

/// OperationHandler structure to send a `NativeOperation` and get a `NativeResult`.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct OperationHandler {
    #[derivative(Debug = "ignore")]
    converter: Box<dyn Convert>,
    version_maj: u8,
    version_min: u8,
    content_type: BodyType,
    accept_type: BodyType,
    request_client: RequestHandler,
}

#[allow(clippy::new_without_default)]
impl OperationHandler {
    /// Creates a OperationHandler instance. The request handler uses a timeout of 5 seconds on reads
    /// and writes on the socket. It uses the version 1.0 to form request, the direct
    /// authentication method and protobuf format as content type.
    pub fn new() -> OperationHandler {
        Default::default()
    }

    fn operation_to_request(
        &self,
        operation: NativeOperation,
        provider: ProviderID,
        auth: &AuthenticationData,
    ) -> Result<Request> {
        let opcode = operation.opcode();
        let body = self.converter.operation_to_body(operation)?;
        let header = RequestHeader {
            version_maj: self.version_maj,
            version_min: self.version_min,
            provider,
            session: 0, // no provisioning of sessions yet
            content_type: self.content_type,
            accept_type: self.accept_type,
            auth_type: auth.auth_type(),
            opcode,
        };

        Ok(Request {
            header,
            body,
            auth: auth.into(),
        })
    }

    fn response_to_result(&self, response: Response) -> Result<NativeResult> {
        let status = response.header.status;
        if status != ResponseStatus::Success {
            return Err(status);
        }
        let opcode = response.header.opcode;
        self.converter.body_to_result(response.body, opcode)
    }

    /// Send an operation to a specific provider and get a result.
    ///
    /// # Errors
    ///
    /// If the conversions between operation to request or between response to result fail, returns
    /// a serializing or deserializing error. Returns an error if the operation itself failed.
    pub fn process_operation(
        &self,
        operation: NativeOperation,
        provider: ProviderID,
        auth: &AuthenticationData,
    ) -> Result<NativeResult> {
        let request = self.operation_to_request(operation, provider, auth)?;

        let response = self.request_client.process_request(request)?;
        self.response_to_result(response)
    }
}

impl Default for OperationHandler {
    fn default() -> Self {
        OperationHandler {
            converter: Box::from(ProtobufConverter {}),
            version_maj: 1,
            version_min: 0,
            content_type: BodyType::Protobuf,
            accept_type: BodyType::Protobuf,
            request_client: Default::default(),
        }
    }
}
