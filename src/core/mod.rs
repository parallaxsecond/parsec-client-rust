// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Client library for integration with the Parsec service
pub mod ipc_client;
mod operation_handler;
mod request_handler;
mod testing;

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
use parsec_interface::requests::ProviderID;
use std::collections::HashSet;
use uuid::Uuid;

pub use parsec_interface::operations::{psa_algorithm, psa_key_attributes};
pub use parsec_interface::requests::{BodyType, Opcode};

/// List of supported service providers.
#[derive(Debug, Copy, Clone)]
pub enum Provider {
    /// Core provider, responsible for management operations.
    Core,
    /// Software-based provider rooted in Mbed Crypto
    MbedCrypto,
    /// Provider offering abstraction over the PKCS 11 interface
    Pkcs11,
    /// Provider offering abstraction over the TPM 2.0 interface
    Tpm,
}

impl Provider {
    /// Get the ID associated with the provider.
    pub fn id(self) -> ProviderID {
        match self {
            Provider::Core => ProviderID::Core,
            Provider::MbedCrypto => ProviderID::MbedCrypto,
            Provider::Pkcs11 => ProviderID::Pkcs11,
            Provider::Tpm => ProviderID::Tpm,
        }
    }

    /// Get the v4 UUID associated with the provider.
    pub fn uuid(self) -> Uuid {
        // `.unwrap()` is safe below since the values are hardcoded and have been proven to work
        match self {
            Provider::Core => Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").unwrap(),
            Provider::MbedCrypto => {
                Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552").unwrap()
            }
            Provider::Pkcs11 => Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f").unwrap(),
            Provider::Tpm => Uuid::parse_str("1e4954a4-ff21-46d3-ab0c-661eeb667e1d").unwrap(),
        }
    }
}

/// Core client for Parsec service
///
/// The client exposes low-level functionality for using the Parsec service.
/// Below you can see code examples for a few of the operations supported.
///
/// Creating a `CoreClient` instance:
///```no_run
///use parsec_client::auth::AuthenticationData;
///use parsec_client::CoreClient;
///
///let app_name = String::from("app-name");
///let app_auth_data = AuthenticationData::AppIdentity(app_name);
///let client: CoreClient = CoreClient::new(app_auth_data);
///```
///
/// Performing a Ping operation to determine if the service is available
/// and what wire protocol it supports:
///```no_run
///# use parsec_client::auth::AuthenticationData;
///# use parsec_client::CoreClient;
///# let client: CoreClient = CoreClient::new(AuthenticationData::AppIdentity(String::from("app-name")));
///let res = client.ping();
///
///if let Ok((wire_prot_v_maj, wire_prot_v_min)) = res {
///    println!(
///        "Success! Service wire protocol version is {}.{}",
///        wire_prot_v_maj, wire_prot_v_min
///    );
///} else {
///    panic!("Ping failed. Error: {:?}", res);
///}
///```
///
/// Providers are abstracted representations of the secure elements that
/// PARSEC offers abstraction over. Providers are the ones to execute the
/// cryptographic operations requested by the user.
///
/// Checking for available providers:
///```no_run
///# use parsec_client::auth::AuthenticationData;
///# use parsec_client::CoreClient;
///# let client: CoreClient = CoreClient::new(AuthenticationData::AppIdentity(String::from("app-name")));
///use parsec_client::core::Provider;
///
///let desired_provider = Provider::Tpm;
///let available_providers = client.list_providers().expect("Failed to list providers");
///if available_providers
///    .iter()
///    .filter(|provider| provider.uuid == desired_provider.uuid())
///    .count()
///    == 0
///{
///    panic!("Did not find desired provider!");
///}
///```
///
/// Checking operations supported by the provider we're interested in:
///```no_run
///# use parsec_client::auth::AuthenticationData;
///# use parsec_client::CoreClient;
///# let client: CoreClient = CoreClient::new(AuthenticationData::AppIdentity(String::from("app-name")));
///# use parsec_client::core::Provider;
///# let desired_provider = Provider::Tpm;
///use parsec_client::core::Opcode;
///let provider_opcodes = client
///    .list_provider_operations(desired_provider)
///    .expect("Failed to list opcodes");
///// Each operation is identified by a specific `Opcode`
///assert!(provider_opcodes.contains(&Opcode::PsaGenerateKey));
///assert!(provider_opcodes.contains(&Opcode::PsaSignHash));
///assert!(provider_opcodes.contains(&Opcode::PsaDestroyKey));
///```
///
/// Creating a key-pair for signing SHA256 digests with RSA PKCS#1 v1.5:
///```no_run
///# use parsec_client::auth::AuthenticationData;
///# use parsec_client::CoreClient;
///# let client: CoreClient = CoreClient::new(AuthenticationData::AppIdentity(String::from("app-name")));
///# use parsec_client::core::Provider;
///# let desired_provider = Provider::Tpm;
///use parsec_client::core::psa_algorithm::{Algorithm, AsymmetricSignature, Hash};
///use parsec_client::core::psa_key_attributes::{KeyAttributes, KeyPolicy, KeyType, UsageFlags};
///
///let key_name = String::from("rusty key 🔑");
///// This algorithm identifier will be used within the key policy (i.e. what
///// algorithms are usable with the key) and for indicating the desired
///// algorithm for each operation involving the key.
///let asym_sign_algo = AsymmetricSignature::RsaPkcs1v15Sign {
///    hash_alg: Hash::Sha256,
///};
///
///// The key attributes define and limit the usage of the key material stored
///// by the underlying cryptographic provider.
///let key_attrs = KeyAttributes {
///    key_type: KeyType::RsaKeyPair,
///    key_bits: 2048,
///    key_policy: KeyPolicy {
///        key_usage_flags: UsageFlags {
///            export: true,
///            copy: true,
///            cache: true,
///            encrypt: false,
///            decrypt: false,
///            sign_message: true,
///            verify_message: false,
///            sign_hash: true,
///            verify_hash: false,
///            derive: false,
///        },
///        key_algorithm: asym_sign_algo.into(),
///    },
///};
///
///client
///    .generate_key(desired_provider, key_name, key_attrs)
///    .expect("Failed to create key!");
///```
///
/// It is recommended that before attempting to use cryptographic
/// operations users call [`list_providers`](#method.list_providers)
/// and [`list_provider_operations`](#method.list_provider_operations)
/// in order to figure out if their desired use case and provider are
/// available.
#[derive(Debug)]
pub struct CoreClient {
    op_handler: OperationHandler,
    auth_data: AuthenticationData,
}

/// Main client functionality.
impl CoreClient {
    /// Create a new Parsec client given the authentication data of the app.
    pub fn new(auth_data: AuthenticationData) -> Self {
        CoreClient {
            op_handler: Default::default(),
            auth_data,
        }
    }

    /// Update the authentication data of the client.
    pub fn set_auth_data(&mut self, auth_data: AuthenticationData) {
        self.auth_data = auth_data;
    }

    /// List the opcodes supported by the specified provider.
    pub fn list_provider_operations(&self, provider: Provider) -> Result<HashSet<Opcode>> {
        let res = self.op_handler.process_operation(
            NativeOperation::ListOpcodes(ListOpcodes {}),
            provider.id(),
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

    /// List the providers that are supported by the service.
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

    /// Send a ping request to the service.
    ///
    /// This operation is intended for testing connectivity to the
    /// service and for retrieving the maximum wire protocol version
    /// it supports.
    pub fn ping(&self) -> Result<(u8, u8)> {
        let res = self.op_handler.process_operation(
            NativeOperation::Ping(Ping {}),
            Provider::Core.id(),
            &AuthenticationData::None,
        )?;

        if let NativeResult::Ping(res) = res {
            Ok((res.wire_protocol_version_maj, res.wire_protocol_version_min))
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// Generate a key.
    ///
    /// Creates a new key with the given name within the namespace of the
    /// desired provider. Any UTF-8 string is considered a valid key name,
    /// however names must be unique per provider.
    ///
    /// If this method returns an error, no key will have been generated and
    /// the name used will still be available for another key.
    ///
    /// Persistence of keys is implemented at provider level, and currently all
    /// providers persist all the keys users create. However, no methods exist
    /// for discovering previously generated or imported keys, so users are
    /// responsible for keeping track of keys they have created.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_generate_key.html#specific-response-status-codes).
    pub fn generate_key(
        &self,
        provider: Provider,
        key_name: String,
        key_attributes: KeyAttributes,
    ) -> Result<()> {
        let op = PsaGenerateKey {
            key_name,
            attributes: key_attributes,
        };

        let _ = self.op_handler.process_operation(
            NativeOperation::PsaGenerateKey(op),
            provider.id(),
            &self.auth_data,
        )?;

        Ok(())
    }

    /// Destroy a key.
    ///
    /// Given that keys are namespaced at a provider level, it is
    /// important to call `destroy_key` on the correct combination of
    /// `provider` and `key_name`.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_destroy_key.html#specific-response-status-codes).
    pub fn destroy_key(&self, provider: Provider, key_name: String) -> Result<()> {
        let op = PsaDestroyKey { key_name };

        let _ = self.op_handler.process_operation(
            NativeOperation::PsaDestroyKey(op),
            provider.id(),
            &self.auth_data,
        )?;

        Ok(())
    }

    /// Import a key.
    ///
    /// Creates a new key with the given name within the namespace of the
    /// desired provider using the user-provided data. Any UTF-8 string is
    /// considered a valid key name, however names must be unique per provider.
    ///
    /// The key material should follow the appropriate binary format expressed
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_public_key.html).
    /// Several crates (e.g. [`picky-asn1`](https://crates.io/crates/picky-asn1))
    /// can greatly help in dealing with binary encodings.
    ///
    /// If this method returns an error, no key will have been imported and the
    /// name used will still be available for another key.
    ///
    /// Persistence of keys is implemented at provider level, and currently all
    /// providers persist all the keys users create. However, no methods exist
    /// for discovering previously generated or imported keys, so users are
    /// responsible for keeping track of keys they have created.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_import_key.html#specific-response-status-codes).
    pub fn import_key(
        &self,
        provider: Provider,
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
            provider.id(),
            &self.auth_data,
        )?;

        Ok(())
    }

    /// Export a public key or the public part of a key pair.
    ///
    /// The returned key material will follow the appropriate binary format expressed
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_public_key.html).
    /// Several crates (e.g. [`picky-asn1`](https://crates.io/crates/picky-asn1))
    /// can greatly help in dealing with binary encodings.
    ///
    /// In order to export a public key, the export flag found in the
    /// [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.KeyPolicy.html)
    /// **must** be `true`.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_public_key.html#specific-response-status-codes).
    pub fn export_public_key(&self, provider: Provider, key_name: String) -> Result<Vec<u8>> {
        let op = PsaExportPublicKey { key_name };

        let res = self.op_handler.process_operation(
            NativeOperation::PsaExportPublicKey(op),
            provider.id(),
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

    /// Create an asymmetric signature on a pre-computed message digest.
    ///
    /// The key intended for signing **must** have its `sign_hash` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.KeyPolicy.html).
    ///
    /// The signature will be created with the algorithm defined in
    /// `sign_algorithm`, but only after checking that the key policy
    /// and type conform with it.
    ///
    /// `hash` must be a hash pre-computed over the message of interest
    /// with the algorithm specified within `sign_algorithm`.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_sign_hash.html#specific-response-status-codes).
    pub fn sign_hash(
        &self,
        provider: Provider,
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
            provider.id(),
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

    /// Verify an existing asymmetric signature over a pre-computed message digest.
    ///
    /// The key intended for signing **must** have its `verify_hash` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.KeyPolicy.html).
    ///
    /// The signature will be verifyied with the algorithm defined in
    /// `sign_algorithm`, but only after checking that the key policy
    /// and type conform with it.
    ///
    /// `hash` must be a hash pre-computed over the message of interest
    /// with the algorithm specified within `sign_algorithm`.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_verify_hash.html#specific-response-status-codes).
    pub fn verify_hash_signature(
        &self,
        provider: Provider,
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
            provider.id(),
            &self.auth_data,
        )?;

        Ok(())
    }
}
