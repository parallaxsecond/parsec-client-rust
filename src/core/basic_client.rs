// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Basic client for Parsec integration
use super::operation_client::OperationClient;
use crate::auth::AuthenticationData;
use crate::error::{ClientErrorKind, Error, Result};
use parsec_interface::operations::list_opcodes::Operation as ListOpcodes;
use parsec_interface::operations::list_providers::{Operation as ListProviders, ProviderInfo};
use parsec_interface::operations::ping::Operation as Ping;
use parsec_interface::operations::psa_algorithm::AsymmetricSignature;
use parsec_interface::operations::psa_destroy_key::Operation as PsaDestroyKey;
use parsec_interface::operations::psa_export_public_key::Operation as PsaExportPublicKey;
use parsec_interface::operations::psa_generate_key::Operation as PsaGenerateKey;
use parsec_interface::operations::psa_import_key::Operation as PsaImportKey;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::operations::psa_sign_hash::Operation as PsaSignHash;
use parsec_interface::operations::psa_verify_hash::Operation as PsaVerifyHash;
use parsec_interface::operations::{NativeOperation, NativeResult};
use parsec_interface::requests::{Opcode, ProviderID};
use parsec_interface::secrecy::Secret;
use std::collections::HashSet;
use zeroize::Zeroizing;

/// Core client for Parsec service
///
/// The client exposes low-level functionality for using the Parsec service.
/// Below you can see code examples for a few of the operations supported.
///
/// For all cryptographic operations an implicit provider is used which can be
/// changed between operations. The client starts with no such defined provider
/// and it is the responsibility of the user to identify and set an appropriate
/// one. As such, it is critical that before attempting to use cryptographic
/// operations users call [`list_providers`](#method.list_providers)
/// and [`list_opcodes`](#method.list_opcodes)
/// in order to figure out if their desired use case and provider are
/// available.
///
/// Creating a `BasicClient` instance:
///```no_run
///use parsec_client::auth::AuthenticationData;
///use parsec_client::BasicClient;
///use parsec_client::core::secrecy::Secret;
///
///let app_name = String::from("app-name");
///let app_auth_data = AuthenticationData::AppIdentity(Secret::new(app_name));
///let client: BasicClient = BasicClient::new(app_auth_data);
///```
///
/// Performing a Ping operation helps to determine if the service is available
/// and what wire protocol it supports. Currently only a version 1.0 of the wire
/// protocol exists and new versions are expected to be extremely rare.
///```no_run
///# use parsec_client::auth::AuthenticationData;
///# use parsec_client::BasicClient;
///# use parsec_client::core::secrecy::Secret;
///# use parsec_client::core::interface::requests::ProviderID;
///# let client: BasicClient = BasicClient::new(AuthenticationData::AppIdentity(Secret::new(String::from("app-name"))));
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
///# use parsec_client::BasicClient;
///# use parsec_client::core::secrecy::Secret;
///# use parsec_client::core::interface::requests::ProviderID;
///# let client: BasicClient = BasicClient::new(AuthenticationData::AppIdentity(Secret::new(String::from("app-name"))));
///use uuid::Uuid;
///
///// Identify provider by its UUID (in this case, the PKCS11 provider)
///let desired_provider_uuid = Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f").unwrap();
///let available_providers = client.list_providers().expect("Failed to list providers");
///if available_providers
///    .iter()
///    .filter(|provider| provider.uuid == desired_provider_uuid)
///    .count()
///    == 0
///{
///    panic!("Did not find desired provider!");
///}
///```
///
/// Checking operations supported by the provider we're interested in is done
/// through the `list_opcodes` method:
///```no_run
///# use parsec_client::auth::AuthenticationData;
///# use parsec_client::BasicClient;
///# use parsec_client::core::interface::requests::ProviderID;
///# use parsec_client::core::secrecy::Secret;
///# let mut client: BasicClient = BasicClient::new(AuthenticationData::AppIdentity(Secret::new(String::from("app-name"))));
///use parsec_client::core::interface::requests::Opcode;
///
///let desired_provider = ProviderID::Pkcs11;
///let provider_opcodes = client
///    .list_opcodes(desired_provider)
///    .expect("Failed to list opcodes");
///// Each operation is identified by a specific `Opcode`
///assert!(provider_opcodes.contains(&Opcode::PsaGenerateKey));
///assert!(provider_opcodes.contains(&Opcode::PsaSignHash));
///assert!(provider_opcodes.contains(&Opcode::PsaDestroyKey));
///
///// Now that we're certain our desired provider offers all the functionality we need...
///client.set_implicit_provider(desired_provider);
///```
///
/// Creating a key-pair for signing SHA256 digests with RSA PKCS#1 v1.5:
///```no_run
///# use parsec_client::auth::AuthenticationData;
///# use parsec_client::BasicClient;
///# use parsec_client::core::secrecy::Secret;
///# use parsec_client::core::interface::requests::ProviderID;
///# let client: BasicClient = BasicClient::new(AuthenticationData::AppIdentity(Secret::new(String::from("app-name"))));
///use parsec_client::core::interface::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Hash};
///use parsec_client::core::interface::operations::psa_key_attributes::{Attributes, Lifetime, Policy, Type, UsageFlags};
///
///let key_name = String::from("rusty key 🔑");
///// This algorithm identifier will be used within the key policy (i.e. what
///// algorithms are usable with the key) and for indicating the desired
///// algorithm for each operation involving the key.
///let asym_sign_algo = AsymmetricSignature::RsaPkcs1v15Sign {
///    hash_alg: Hash::Sha256.into(),
///};
///
///// The key attributes define and limit the usage of the key material stored
///// by the underlying cryptographic provider.
///let key_attrs = Attributes {
///    lifetime: Lifetime::Persistent,
///    key_type: Type::RsaKeyPair,
///    bits: 2048,
///    policy: Policy {
///        usage_flags: UsageFlags {
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
///        permitted_algorithms: asym_sign_algo.into(),
///    },
///};
///
///client
///    .psa_generate_key(key_name.clone(), key_attrs)
///    .expect("Failed to create key!");
///```
#[derive(Debug)]
pub struct BasicClient {
    pub(crate) op_client: OperationClient,
    pub(crate) auth_data: AuthenticationData,
    pub(crate) implicit_provider: Option<ProviderID>,
}

/// Main client functionality.
impl BasicClient {
    /// Create a new Parsec client given the authentication data of the app.
    ///
    /// Before you can use this client for cryptographic operations, you first need to call
    /// [`set_implicit_provider`](#method.set_implicit_provider). In order to get a list of
    /// supported providers, call the [`list_providers`](#method.list_providers) method.
    pub fn new(auth_data: AuthenticationData) -> Self {
        BasicClient {
            op_client: Default::default(),
            auth_data,
            implicit_provider: None,
        }
    }

    /// Update the authentication data of the client.
    pub fn set_auth_data(&mut self, auth_data: AuthenticationData) {
        self.auth_data = auth_data;
    }

    /// Retrieve authentication data of the client.
    pub fn auth_data(&self) -> AuthenticationData {
        self.auth_data.clone()
    }

    /// Set the provider that the client will be implicitly working with.
    pub fn set_implicit_provider(&mut self, provider: ProviderID) {
        self.implicit_provider = Some(provider);
    }

    /// Retrieve client's implicit provider.
    pub fn implicit_provider(&self) -> Option<ProviderID> {
        self.implicit_provider
    }

    /// **[Core Operation]** List the opcodes supported by the specified provider.
    pub fn list_opcodes(&self, provider: ProviderID) -> Result<HashSet<Opcode>> {
        let res = self.op_client.process_operation(
            NativeOperation::ListOpcodes(ListOpcodes {
                provider_id: provider,
            }),
            ProviderID::Core,
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

    /// **[Core Operation]** List the providers that are supported by the service.
    pub fn list_providers(&self) -> Result<Vec<ProviderInfo>> {
        let res = self.op_client.process_operation(
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

    /// **[Core Operation]** Send a ping request to the service.
    ///
    /// This operation is intended for testing connectivity to the
    /// service and for retrieving the maximum wire protocol version
    /// it supports.
    pub fn ping(&self) -> Result<(u8, u8)> {
        let res = self.op_client.process_operation(
            NativeOperation::Ping(Ping {}),
            ProviderID::Core,
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

    /// **[Cryptographic Operation]** Generate a key.
    ///
    /// Creates a new key with the given name within the namespace of the
    /// implicit client provider. Any UTF-8 string is considered a valid key name,
    /// however names must be unique per provider.
    ///
    /// Persistence of keys is implemented at provider level, and currently all
    /// providers persist all the keys users create. However, no methods exist
    /// for discovering previously generated or imported keys, so users are
    /// responsible for keeping track of keys they have created.
    ///
    /// # Errors
    ///
    /// If this method returns an error, no key will have been generated and
    /// the name used will still be available for another key.
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// If the implicit client provider has not been set, a client error of
    /// `NoProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_generate_key.html#specific-response-status-codes).
    pub fn psa_generate_key(&self, key_name: String, key_attributes: Attributes) -> Result<()> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaGenerateKey {
            key_name,
            attributes: key_attributes,
        };

        let _ = self.op_client.process_operation(
            NativeOperation::PsaGenerateKey(op),
            crypto_provider,
            &self.auth_data,
        )?;

        Ok(())
    }

    /// **[Cryptographic Operation]** Destroy a key.
    ///
    /// Given that keys are namespaced at a provider level, it is
    /// important to call `psa_destroy_key` on the correct combination of
    /// implicit client provider and `key_name`.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// If the implicit client provider has not been set, a client error of
    /// `NoProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_destroy_key.html#specific-response-status-codes).
    pub fn psa_destroy_key(&self, key_name: String) -> Result<()> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaDestroyKey { key_name };

        let _ = self.op_client.process_operation(
            NativeOperation::PsaDestroyKey(op),
            crypto_provider,
            &self.auth_data,
        )?;

        Ok(())
    }

    /// **[Cryptographic Operation]** Import a key.
    ///
    /// Creates a new key with the given name within the namespace of the
    /// implicit client provider using the user-provided data. Any UTF-8 string is
    /// considered a valid key name, however names must be unique per provider.
    ///
    /// The key material should follow the appropriate binary format expressed
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_public_key.html).
    /// Several crates (e.g. [`picky-asn1`](https://crates.io/crates/picky-asn1))
    /// can greatly help in dealing with binary encodings.
    ///
    /// Persistence of keys is implemented at provider level, and currently all
    /// providers persist all the keys users create. However, no methods exist
    /// for discovering previously generated or imported keys, so users are
    /// responsible for keeping track of keys they have created.
    ///
    /// # Errors
    ///
    /// If this method returns an error, no key will have been imported and the
    /// name used will still be available for another key.
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// If the implicit client provider has not been set, a client error of
    /// `NoProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_import_key.html#specific-response-status-codes).
    pub fn psa_import_key(
        &self,
        key_name: String,
        key_material: &[u8],
        key_attributes: Attributes,
    ) -> Result<()> {
        let key_material = Secret::new(key_material.to_vec());
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaImportKey {
            key_name,
            attributes: key_attributes,
            data: key_material,
        };

        let _ = self.op_client.process_operation(
            NativeOperation::PsaImportKey(op),
            crypto_provider,
            &self.auth_data,
        )?;

        Ok(())
    }

    /// **[Cryptographic Operation]** Export a public key or the public part of a key pair.
    ///
    /// The returned key material will follow the appropriate binary format expressed
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_public_key.html).
    /// Several crates (e.g. [`picky-asn1`](https://crates.io/crates/picky-asn1))
    /// can greatly help in dealing with binary encodings.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// If the implicit client provider has not been set, a client error of
    /// `NoProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_public_key.html#specific-response-status-codes).
    pub fn psa_export_public_key(&self, key_name: String) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaExportPublicKey { key_name };

        let res = self.op_client.process_operation(
            NativeOperation::PsaExportPublicKey(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaExportPublicKey(res) = res {
            Ok(res.data.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Cryptographic Operation]** Create an asymmetric signature on a pre-computed message digest.
    ///
    /// The key intended for signing **must** have its `sign_hash` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// The signature will be created with the algorithm defined in
    /// `sign_algorithm`, but only after checking that the key policy
    /// and type conform with it.
    ///
    /// `hash` must be a hash pre-computed over the message of interest
    /// with the algorithm specified within `sign_algorithm`.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// If the implicit client provider has not been set, a client error of
    /// `NoProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_sign_hash.html#specific-response-status-codes).
    pub fn psa_sign_hash(
        &self,
        key_name: String,
        hash: &[u8],
        sign_algorithm: AsymmetricSignature,
    ) -> Result<Vec<u8>> {
        let hash = Zeroizing::new(hash.to_vec());
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaSignHash {
            key_name,
            alg: sign_algorithm,
            hash,
        };

        let res = self.op_client.process_operation(
            NativeOperation::PsaSignHash(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaSignHash(res) = res {
            Ok(res.signature.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Cryptographic Operation]** Verify an existing asymmetric signature over a pre-computed message digest.
    ///
    /// The key intended for signing **must** have its `verify_hash` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// The signature will be verifyied with the algorithm defined in
    /// `sign_algorithm`, but only after checking that the key policy
    /// and type conform with it.
    ///
    /// `hash` must be a hash pre-computed over the message of interest
    /// with the algorithm specified within `sign_algorithm`.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// If the implicit client provider has not been set, a client error of
    /// `NoProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_verify_hash.html#specific-response-status-codes).
    pub fn psa_verify_hash(
        &self,
        key_name: String,
        hash: &[u8],
        sign_algorithm: AsymmetricSignature,
        signature: &[u8],
    ) -> Result<()> {
        let hash = Zeroizing::new(hash.to_vec());
        let signature = Zeroizing::new(signature.to_vec());
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaVerifyHash {
            key_name,
            alg: sign_algorithm,
            hash,
            signature,
        };

        let _ = self.op_client.process_operation(
            NativeOperation::PsaVerifyHash(op),
            crypto_provider,
            &self.auth_data,
        )?;

        Ok(())
    }

    fn can_provide_crypto(&self) -> Result<ProviderID> {
        match self.implicit_provider {
            None => Err(Error::Client(ClientErrorKind::NoProvider)),
            Some(ProviderID::Core) => Err(Error::Client(ClientErrorKind::InvalidProvider)),
            Some(crypto_provider) => Ok(crypto_provider),
        }
    }
}
