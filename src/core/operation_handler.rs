// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use super::request_handler::RequestHandler;
use crate::auth::AuthenticationData;
use crate::error::{ClientErrorKind, Error, Result};
use derivative::Derivative;
use parsec_interface::operations::{Convert, NativeOperation, NativeResult};
use parsec_interface::operations_protobuf::ProtobufConverter;
use parsec_interface::requests::{
    request::RequestHeader, BodyType, Opcode, ProviderID, Request, Response, ResponseStatus,
};

/// OperationHandler structure to send a `NativeOperation` and get a `NativeResult`.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct OperationHandler {
    #[derivative(Debug = "ignore")]
    pub converter: Box<dyn Convert>,
    pub wire_protocol_version_maj: u8,
    pub wire_protocol_version_min: u8,
    pub content_type: BodyType,
    pub accept_type: BodyType,
    #[cfg_attr(test, derivative(Debug = "ignore"))]
    pub request_handler: RequestHandler,
}

#[allow(clippy::new_without_default)]
impl OperationHandler {
    /// Creates an OperationHandler instance. The request handler uses a timeout of 5 seconds on reads
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
        let body = self
            .converter
            .operation_to_body(operation)
            .map_err(ClientErrorKind::Interface)?;
        let header = RequestHeader {
            version_maj: self.wire_protocol_version_maj,
            version_min: self.wire_protocol_version_min,
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

    fn response_to_result(
        &self,
        response: Response,
        expected_opcode: Opcode,
    ) -> Result<NativeResult> {
        let status = response.header.status;
        if status != ResponseStatus::Success {
            return Err(Error::Service(status));
        }
        let opcode = response.header.opcode;
        if opcode != expected_opcode {
            return Err(Error::Client(ClientErrorKind::InvalidServiceResponseType));
        }
        Ok(self
            .converter
            .body_to_result(response.body, opcode)
            .map_err(ClientErrorKind::Interface)?)
    }

    /// Send an operation to a specific provider and get a result.
    ///
    /// # Errors
    ///
    /// If the conversions between operation to request or between response to result fail, returns
    /// a serializing or deserializing error. Returns an error if the operation itself failed. If the
    /// opcode is different between request and response, `InvalidServiceResponseType` is returned.
    pub fn process_operation(
        &self,
        operation: NativeOperation,
        provider: ProviderID,
        auth: &AuthenticationData,
    ) -> Result<NativeResult> {
        let req_opcode = operation.opcode();
        let request = self.operation_to_request(operation, provider, auth)?;

        let response = self.request_handler.process_request(request)?;
        self.response_to_result(response, req_opcode)
    }
}

impl Default for OperationHandler {
    fn default() -> Self {
        OperationHandler {
            converter: Box::from(ProtobufConverter {}),
            wire_protocol_version_maj: 1,
            wire_protocol_version_min: 0,
            content_type: BodyType::Protobuf,
            accept_type: BodyType::Protobuf,
            request_handler: Default::default(),
        }
    }
}

impl crate::CoreClient {
    /// Set the content type for requests and responses handled by this client
    pub fn set_request_content_type(&mut self, content_type: BodyType) {
        self.op_handler.content_type = content_type;
        self.op_handler.accept_type = content_type;
        match content_type {
            BodyType::Protobuf => self.op_handler.converter = Box::from(ProtobufConverter {}),
        }
    }

    /// Set the wire protocol version numbers to be used by the client
    pub fn set_wire_protocol_version(&mut self, version_maj: u8, version_min: u8) {
        self.op_handler.wire_protocol_version_maj = version_maj;
        self.op_handler.wire_protocol_version_min = version_min;
    }
}
