// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Operation-level client
#![allow(dead_code)]

use super::request_client::RequestClient;
use crate::auth::AuthenticationData;
use crate::error::{ClientErrorKind, Error, Result};
use derivative::Derivative;
use parsec_interface::operations::{Convert, NativeOperation, NativeResult};
use parsec_interface::operations_protobuf::ProtobufConverter;
use parsec_interface::requests::{
    request::RequestHeader, Opcode, ProviderID, Request, Response, ResponseStatus,
};

/// Low-level client optimised for communicating with the Parsec service at an operation level.
///
/// Usage is recommended when fine control over how operations are wrapped and processed is needed.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct OperationClient {
    /// Converter that manages request body conversions
    ///
    /// Defaults to a Protobuf converter
    #[derivative(Debug = "ignore")]
    pub content_converter: Box<dyn Convert + Send + Sync>,
    /// Converter that manages response body conversions
    ///
    /// Defaults to a Protobuf converter
    #[derivative(Debug = "ignore")]
    pub accept_converter: Box<dyn Convert + Send + Sync>,
    /// Client for request and response objects
    pub request_client: RequestClient,
}

#[allow(clippy::new_without_default)]
impl OperationClient {
    /// Creates an OperationClient instance. The request client uses a timeout of 5
    /// seconds on reads and writes on the socket. It uses the version 1.0 wire protocol
    /// to form requests, the direct authentication method and protobuf format as
    /// content type.
    pub fn new() -> OperationClient {
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
            .content_converter
            .operation_to_body(operation)
            .map_err(ClientErrorKind::Interface)?;
        let header = RequestHeader {
            provider,
            session: 0, // no provisioning of sessions yet
            content_type: self.content_converter.body_type(),
            accept_type: self.accept_converter.body_type(),
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
            .accept_converter
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

        let response = self.request_client.process_request(request)?;
        self.response_to_result(response, req_opcode)
    }
}

impl Default for OperationClient {
    fn default() -> Self {
        OperationClient {
            content_converter: Box::from(ProtobufConverter {}),
            accept_converter: Box::from(ProtobufConverter {}),
            request_client: Default::default(),
        }
    }
}

/// Configuration methods for controlling communication with the service.
impl crate::BasicClient {
    /// Set the converter used for request bodies handled by this client.
    ///
    /// By default Protobuf will be used for this.
    pub fn set_request_body_converter(
        &mut self,
        content_converter: Box<dyn Convert + Send + Sync>,
    ) {
        self.op_client.content_converter = content_converter;
    }

    /// Set the converter used for response bodies handled by this client.
    ///
    /// By default Protobuf will be used for this.
    pub fn set_response_body_converter(
        &mut self,
        accept_converter: Box<dyn Convert + Send + Sync>,
    ) {
        self.op_client.accept_converter = accept_converter;
    }
}
