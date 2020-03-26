// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Client library for integration with the Parsec service

mod operation_handler;
mod request_handler;

use crate::auth::AuthenticationData;
use crate::error::{ClientErrorKind, Error, Result};
use operation_handler::OperationHandler;
use parsec_interface::operations::list_opcodes::Operation as ListOpcodes;
use parsec_interface::operations::list_providers::{Operation as ListProviders, ProviderInfo};
use parsec_interface::operations::ping::Operation as Ping;
use parsec_interface::operations::psa_algorithm::AsymmetricSignature;
use parsec_interface::operations::psa_destroy_key::Operation as PsaDestroyKey;
use parsec_interface::operations::psa_export_public_key::Operation as PsaExportPublicKey;
use parsec_interface::operations::psa_generate_key::Operation as PsaGenerateKey;
use parsec_interface::operations::psa_import_key::Operation as PsaImportKey;
use parsec_interface::operations::psa_key_attributes::KeyAttributes;
use parsec_interface::operations::psa_sign_hash::Operation as PsaSignHash;
use parsec_interface::operations::psa_verify_hash::Operation as PsaVerifyHash;
use parsec_interface::operations::{NativeOperation, NativeResult};
use parsec_interface::requests::Opcode;
use parsec_interface::requests::ProviderID;
use std::collections::HashSet;

/// Core client for Parsec service
///
/// The client exposes low-level functionality for using the Parsec service
#[derive(Debug)]
pub struct CoreClient {
    op_handler: OperationHandler,
    auth_data: AuthenticationData,
}

impl CoreClient {
    /// Create a new Parsec client given the authentication data of the app
    pub fn new(auth_data: AuthenticationData) -> Self {
        CoreClient {
            op_handler: Default::default(),
            auth_data,
        }
    }

    /// Update the authentication data of the client
    pub fn set_auth_data(&mut self, auth_data: AuthenticationData) {
        self.auth_data = auth_data;
    }

    /// list opcodes
    pub fn list_provider_operations(&self, provider: ProviderID) -> Result<HashSet<Opcode>> {
        let res = self.op_handler.process_operation(
            NativeOperation::ListOpcodes(ListOpcodes {}),
            provider,
            &self.auth_data,
        )?;

        if let NativeResult::ListOpcodes(res) = res {
            Ok(res.opcodes)
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// list providers
    pub fn list_providers(&self) -> Result<Vec<ProviderInfo>> {
        let res = self.op_handler.process_operation(
            NativeOperation::ListProviders(ListProviders {}),
            ProviderID::Core,
            &self.auth_data,
        )?;

        if let NativeResult::ListProviders(res) = res {
            Ok(res.providers)
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// ping
    pub fn ping(&self) -> Result<()> {
        let _ = self.op_handler.process_operation(
            NativeOperation::Ping(Ping {}),
            ProviderID::Core,
            &AuthenticationData::None,
        )?;

        Ok(())
    }

    /// generate key
    pub fn generate_key(
        &self,
        provider: ProviderID,
        key_name: String,
        key_attributes: KeyAttributes,
    ) -> Result<()> {
        let op = PsaGenerateKey {
            key_name,
            attributes: key_attributes,
        };

        let _ = self.op_handler.process_operation(
            NativeOperation::PsaGenerateKey(op),
            provider,
            &self.auth_data,
        )?;

        Ok(())
    }

    /// destroy key
    pub fn destroy_key(&self, provider: ProviderID, key_name: String) -> Result<()> {
        let op = PsaDestroyKey { key_name };

        let _ = self.op_handler.process_operation(
            NativeOperation::PsaDestroyKey(op),
            provider,
            &self.auth_data,
        )?;

        Ok(())
    }

    /// import key
    pub fn import_key(
        &self,
        provider: ProviderID,
        key_name: String,
        key_material: Vec<u8>,
        key_attributes: KeyAttributes,
    ) -> Result<()> {
        let op = PsaImportKey {
            key_name,
            attributes: key_attributes,
            data: key_material,
        };

        let _ = self.op_handler.process_operation(
            NativeOperation::PsaImportKey(op),
            provider,
            &self.auth_data,
        )?;

        Ok(())
    }

    /// export key
    pub fn export_public_key(&self, provider: ProviderID, key_name: String) -> Result<Vec<u8>> {
        let op = PsaExportPublicKey { key_name };

        let res = self.op_handler.process_operation(
            NativeOperation::PsaExportPublicKey(op),
            provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaExportPublicKey(res) = res {
            Ok(res.data)
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// sign hash
    pub fn sign_hash(
        &self,
        provider: ProviderID,
        key_name: String,
        hash: Vec<u8>,
        sign_algorithm: AsymmetricSignature,
    ) -> Result<Vec<u8>> {
        let op = PsaSignHash {
            key_name,
            alg: sign_algorithm,
            hash,
        };

        let res = self.op_handler.process_operation(
            NativeOperation::PsaSignHash(op),
            provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaSignHash(res) = res {
            Ok(res.signature)
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// verify hash
    pub fn verify_hash_signature(
        &self,
        provider: ProviderID,
        key_name: String,
        hash: Vec<u8>,
        sign_algorithm: AsymmetricSignature,
        signature: Vec<u8>,
    ) -> Result<()> {
        let op = PsaVerifyHash {
            key_name,
            alg: sign_algorithm,
            hash,
            signature,
        };

        let _ = self.op_handler.process_operation(
            NativeOperation::PsaVerifyHash(op),
            provider,
            &self.auth_data,
        )?;

        Ok(())
    }
}
