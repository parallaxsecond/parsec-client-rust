// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Basic client for Parsec integration
use super::operation_client::OperationClient;
use crate::auth::Authentication;
use crate::error::{ClientErrorKind, Error, Result};
use log::{debug, warn};
use parsec_interface::operations::delete_client::Operation as DeleteClient;
use parsec_interface::operations::list_authenticators::{
    AuthenticatorInfo, Operation as ListAuthenticators,
};
use parsec_interface::operations::list_clients::Operation as ListClients;
use parsec_interface::operations::list_keys::{KeyInfo, Operation as ListKeys};
use parsec_interface::operations::list_opcodes::Operation as ListOpcodes;
use parsec_interface::operations::list_providers::{Operation as ListProviders, ProviderInfo};
use parsec_interface::operations::ping::Operation as Ping;
use parsec_interface::operations::psa_aead_decrypt::Operation as PsaAeadDecrypt;
use parsec_interface::operations::psa_aead_encrypt::Operation as PsaAeadEncrypt;
use parsec_interface::operations::psa_algorithm::{
    Aead, AsymmetricEncryption, AsymmetricSignature, Hash, RawKeyAgreement,
};
use parsec_interface::operations::psa_asymmetric_decrypt::Operation as PsaAsymDecrypt;
use parsec_interface::operations::psa_asymmetric_encrypt::Operation as PsaAsymEncrypt;
use parsec_interface::operations::psa_destroy_key::Operation as PsaDestroyKey;
use parsec_interface::operations::psa_export_key::Operation as PsaExportKey;
use parsec_interface::operations::psa_export_public_key::Operation as PsaExportPublicKey;
use parsec_interface::operations::psa_generate_key::Operation as PsaGenerateKey;
use parsec_interface::operations::psa_generate_random::Operation as PsaGenerateRandom;
use parsec_interface::operations::psa_hash_compare::Operation as PsaHashCompare;
use parsec_interface::operations::psa_hash_compute::Operation as PsaHashCompute;
use parsec_interface::operations::psa_import_key::Operation as PsaImportKey;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::operations::psa_raw_key_agreement::Operation as PsaRawKeyAgreement;
use parsec_interface::operations::psa_sign_hash::Operation as PsaSignHash;
use parsec_interface::operations::psa_verify_hash::Operation as PsaVerifyHash;
use parsec_interface::operations::{NativeOperation, NativeResult};
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{Opcode, ProviderID};
use parsec_interface::secrecy::{ExposeSecret, Secret};
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
///use parsec_client::auth::Authentication;
///use parsec_client::BasicClient;
///
///let app_name = String::from("app-name");
///let client: BasicClient = BasicClient::new(Some(app_name)).unwrap();
///```
///
/// Performing a Ping operation helps to determine if the service is available
/// and what wire protocol it supports. Currently only a version 1.0 of the wire
/// protocol exists and new versions are expected to be extremely rare.
///```no_run
///# use parsec_client::auth::Authentication;
///# use parsec_client::BasicClient;
///# use parsec_client::core::interface::requests::ProviderID;
///# let client: BasicClient = BasicClient::new(Some(String::from("app-name"))).unwrap();
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
///# use parsec_client::auth::Authentication;
///# use parsec_client::BasicClient;
///# use parsec_client::core::interface::requests::ProviderID;
///# let client: BasicClient = BasicClient::new(Some(String::from("app-name"))).unwrap();
///use parsec_interface::operations::list_providers::Uuid;
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
///# use parsec_client::auth::Authentication;
///# use parsec_client::BasicClient;
///# use parsec_client::core::interface::requests::ProviderID;
///# let mut client: BasicClient = BasicClient::new(Some(String::from("app-name"))).unwrap();
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
///# use parsec_client::auth::Authentication;
///# use parsec_client::BasicClient;
///# use parsec_client::core::interface::requests::ProviderID;
///# let client: BasicClient = BasicClient::new(Some(String::from("app-name"))).unwrap();
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
    pub(crate) auth_data: Authentication,
    pub(crate) implicit_provider: ProviderID,
}

/// Main client functionality.
impl BasicClient {
    /// Create a new Parsec client.
    ///
    /// The client will be initialised with default values obtained from the service for the
    /// implicit provider and for application identity.
    ///
    /// * `app_name` is the application name to be used if direct authentication is the default
    /// authentication choice
    ///
    /// This client will use the default configuration. That includes using a Protobuf converter
    /// for message bodies and a Unix Domain Socket IPC handler. The default timeout length is 60
    /// seconds.
    ///
    /// # Errors
    ///
    /// The errors that can be expected are all the ones coming from
    /// [`set_default_auth`](#method.set_default_auth) and
    /// [`set_default_provider`](#method.set_default_provider)
    pub fn new(app_name: Option<String>) -> Result<Self> {
        let mut client = BasicClient {
            op_client: OperationClient::new()?,
            auth_data: Authentication::None,
            implicit_provider: ProviderID::Core,
        };
        client.set_default_provider()?;
        client.set_default_auth(app_name)?;
        debug!("Parsec BasicClient created with implicit provider \"{}\" and authentication data \"{:?}\"", client.implicit_provider(), client.auth_data());
        Ok(client)
    }

    /// Create a client that can initially only be used with Core operations not necessitating
    /// authentication (eg ping).
    ///
    /// Setting an authentication method and an implicit provider is needed before calling crypto
    /// operations.
    ///
    /// # Example
    ///
    /// ```no_run
    ///use parsec_client::BasicClient;
    ///let client = BasicClient::new_naked();
    ///let (major, minor) = client.ping().unwrap();
    /// ```
    pub fn new_naked() -> Self {
        BasicClient {
            op_client: Default::default(),
            auth_data: Authentication::None,
            implicit_provider: ProviderID::Core,
        }
    }

    /// Query the service for the list of authenticators provided and use the first one as default
    ///
    /// * `app_name` is to be used if direct authentication is the default choice
    ///
    /// # Errors
    ///
    /// If no authenticator is reported by the service, a `NoAuthenticator` error kind is returned.
    ///
    /// If the default authenticator is `DirectAuthenticator` and `app_name` was set to `None`,
    /// an error of type `MissingParam` is returned.
    ///
    /// If none of the authenticators returned by the service is supported, `NoAuthenticator` is
    /// returned.
    pub fn set_default_auth(&mut self, app_name: Option<String>) -> Result<()> {
        let authenticators = self.list_authenticators()?;
        if authenticators.is_empty() {
            return Err(Error::Client(ClientErrorKind::NoAuthenticator));
        }
        for authenticator in authenticators {
            match authenticator.id {
                AuthType::Direct => {
                    self.auth_data = Authentication::Direct(
                        app_name.ok_or(Error::Client(ClientErrorKind::MissingParam))?,
                    )
                }
                AuthType::UnixPeerCredentials => {
                    self.auth_data = Authentication::UnixPeerCredentials
                }
                auth => {
                    warn!(
                        "Authenticator of type \"{:?}\" not supported by this client library",
                        auth
                    );
                    continue;
                }
            }
            return Ok(());
        }

        Err(Error::Client(ClientErrorKind::NoAuthenticator))
    }

    /// Update the authentication data of the client.
    pub fn set_auth_data(&mut self, auth_data: Authentication) {
        self.auth_data = auth_data;
    }

    /// Retrieve authentication data of the client.
    pub fn auth_data(&self) -> Authentication {
        self.auth_data.clone()
    }

    /// Query for the service provider list and set the default one as implicit
    ///
    /// # Errors
    ///
    /// If no provider is returned by the service, an client error of `NoProvider`
    /// type is returned.
    pub fn set_default_provider(&mut self) -> Result<()> {
        let providers = self.list_providers()?;
        if providers.is_empty() {
            return Err(Error::Client(ClientErrorKind::NoProvider));
        }
        self.implicit_provider = providers[0].id;

        Ok(())
    }

    /// Set the provider that the client will be implicitly working with.
    pub fn set_implicit_provider(&mut self, provider: ProviderID) {
        self.implicit_provider = provider;
    }

    /// Retrieve client's implicit provider.
    pub fn implicit_provider(&self) -> ProviderID {
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

    /// **[Core Operation]** List the authenticators that are supported by the service.
    pub fn list_authenticators(&self) -> Result<Vec<AuthenticatorInfo>> {
        let res = self.op_client.process_operation(
            NativeOperation::ListAuthenticators(ListAuthenticators {}),
            ProviderID::Core,
            &self.auth_data,
        )?;
        if let NativeResult::ListAuthenticators(res) = res {
            Ok(res.authenticators)
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Core Operation]** List all keys belonging to the application.
    pub fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let res = self.op_client.process_operation(
            NativeOperation::ListKeys(ListKeys {}),
            ProviderID::Core,
            &self.auth_data,
        )?;
        if let NativeResult::ListKeys(res) = res {
            Ok(res.keys)
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// Get the key attributes.
    ///
    /// This is a convenience method that uses `list_keys` underneath.
    pub fn key_attributes(&self, key_name: &str) -> Result<Attributes> {
        Ok(self
            .list_keys()?
            .into_iter()
            .find(|key_info| key_info.name == key_name)
            .ok_or(crate::error::Error::Client(ClientErrorKind::NotFound))?
            .attributes)
    }

    /// **[Core Operation, Admin Operation]** Lists all clients currently having
    /// data in the service.
    pub fn list_clients(&self) -> Result<Vec<String>> {
        let res = self.op_client.process_operation(
            NativeOperation::ListClients(ListClients {}),
            ProviderID::Core,
            &self.auth_data,
        )?;
        if let NativeResult::ListClients(res) = res {
            Ok(res.clients)
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Core Operation, Admin Operation]** Delete all data a client has in the service.
    pub fn delete_client(&self, client: String) -> Result<()> {
        let res = self.op_client.process_operation(
            NativeOperation::DeleteClient(DeleteClient { client }),
            ProviderID::Core,
            &self.auth_data,
        )?;
        if let NativeResult::DeleteClient(_) = res {
            Ok(())
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
            &Authentication::None,
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

    /// **[Cryptographic Operation]** Export a key.
    ///
    /// The returned key material will follow the appropriate binary format expressed
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_key.html).
    /// Several crates (e.g. [`picky-asn1`](https://crates.io/crates/picky-asn1))
    /// can greatly help in dealing with binary encodings.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_export_key.html#specific-response-status-codes).
    pub fn psa_export_key(&self, key_name: String) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaExportKey { key_name };

        let res = self.op_client.process_operation(
            NativeOperation::PsaExportKey(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaExportKey(res) = res {
            Ok(res.data.expose_secret().to_vec())
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

    /// **[Cryptographic Operation]** Encrypt a short message.
    ///
    /// The key intended for encrypting **must** have its `encrypt` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// The encryption will be performed with the algorithm defined in `alg`,
    /// but only after checking that the key policy and type conform with it.
    ///
    /// `salt` can be provided if supported by the algorithm. If the algorithm does not support salt, pass
    //    an empty vector. If the algorithm supports optional salt, pass an empty vector to indicate no
    //    salt. For RSA PKCS#1 v1.5 encryption, no salt is supported.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_asymmetric_encrypt.html#specific-response-status-codes).
    pub fn psa_asymmetric_encrypt(
        &self,
        key_name: String,
        encrypt_alg: AsymmetricEncryption,
        plaintext: &[u8],
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let salt = salt.map(|salt_ref| salt_ref.to_vec().into());
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaAsymEncrypt {
            key_name,
            alg: encrypt_alg,
            plaintext: plaintext.to_vec().into(),
            salt,
        };

        let encrypt_res = self.op_client.process_operation(
            NativeOperation::PsaAsymmetricEncrypt(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaAsymmetricEncrypt(res) = encrypt_res {
            Ok(res.ciphertext.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Cryptographic Operation]** Decrypt a short message.
    ///
    /// The key intended for decrypting **must** have its `decrypt` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// `salt` can be provided if supported by the algorithm. If the algorithm does not support salt, pass
    //    an empty vector. If the algorithm supports optional salt, pass an empty vector to indicate no
    //    salt. For RSA PKCS#1 v1.5 encryption, no salt is supported.
    ///
    ///
    /// The decryption will be performed with the algorithm defined in `alg`,
    /// but only after checking that the key policy and type conform with it.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_asymmetric_decrypt.html#specific-response-status-codes).
    pub fn psa_asymmetric_decrypt(
        &self,
        key_name: String,
        encrypt_alg: AsymmetricEncryption,
        ciphertext: &[u8],
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let salt = match salt {
            Some(salt) => Some(Zeroizing::new(salt.to_vec())),
            None => None,
        };
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaAsymDecrypt {
            key_name,
            alg: encrypt_alg,
            ciphertext: Zeroizing::new(ciphertext.to_vec()),
            salt,
        };

        let decrypt_res = self.op_client.process_operation(
            NativeOperation::PsaAsymmetricDecrypt(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaAsymmetricDecrypt(res) = decrypt_res {
            Ok(res.plaintext.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }
    /// **[Cryptographic Operation]** Compute hash of a message.
    ///
    /// The hash computation will be performed with the algorithm defined in `alg`.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_hash_compute.html#specific-response-status-codes).
    pub fn psa_hash_compute(&self, alg: Hash, input: &[u8]) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;
        let op = PsaHashCompute {
            alg,
            input: input.to_vec().into(),
        };
        let hash_compute_res = self.op_client.process_operation(
            NativeOperation::PsaHashCompute(op),
            crypto_provider,
            &self.auth_data,
        )?;
        if let NativeResult::PsaHashCompute(res) = hash_compute_res {
            Ok(res.hash.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Cryptographic Operation]** Compute hash of a message and compare it with a reference value.
    ///
    /// The hash computation will be performed with the algorithm defined in `alg`.
    ///
    /// If this operation returns no error, the hash was computed successfully and it matches the reference value.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_hash_compare.html#specific-response-status-codes).
    pub fn psa_hash_compare(&self, alg: Hash, input: &[u8], hash: &[u8]) -> Result<()> {
        let crypto_provider = self.can_provide_crypto()?;
        let op = PsaHashCompare {
            alg,
            input: input.to_vec().into(),
            hash: hash.to_vec().into(),
        };
        let _ = self.op_client.process_operation(
            NativeOperation::PsaHashCompare(op),
            crypto_provider,
            &self.auth_data,
        )?;
        Ok(())
    }

    /// **[Cryptographic Operation]** Authenticate and encrypt a short message.
    ///
    /// The key intended for decrypting **must** have its `encrypt` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// The encryption will be performed with the algorithm defined in `alg`,
    /// but only after checking that the key policy and type conform with it.
    ///
    /// `nonce` must be appropriate for the selected `alg`.
    ///
    /// For algorithms where the encrypted data and the authentication tag are defined as separate outputs,
    /// the returned buffer will contain the encrypted data followed by the authentication data.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_aead_encrypt.html#specific-response-status-codes).
    pub fn psa_aead_encrypt(
        &self,
        key_name: String,
        encrypt_alg: Aead,
        nonce: &[u8],
        additional_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaAeadEncrypt {
            key_name,
            alg: encrypt_alg,
            nonce: nonce.to_vec().into(),
            additional_data: additional_data.to_vec().into(),
            plaintext: plaintext.to_vec().into(),
        };

        let encrypt_res = self.op_client.process_operation(
            NativeOperation::PsaAeadEncrypt(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaAeadEncrypt(res) = encrypt_res {
            Ok(res.ciphertext.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Cryptographic Operation]** Decrypt and authenticate a short message.
    ///
    /// The key intended for decrypting **must** have its `decrypt` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// The decryption will be performed with the algorithm defined in `alg`,
    /// but only after checking that the key policy and type conform with it.
    ///
    /// `nonce` must be appropriate for the selected `alg`.
    ///
    /// For algorithms where the encrypted data and the authentication tag are defined as separate inputs,
    /// `ciphertext` must contain the encrypted data followed by the authentication data.
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_aead_decrypt.html#specific-response-status-codes).
    pub fn psa_aead_decrypt(
        &self,
        key_name: String,
        encrypt_alg: Aead,
        nonce: &[u8],
        additional_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaAeadDecrypt {
            key_name,
            alg: encrypt_alg,
            nonce: nonce.to_vec().into(),
            additional_data: additional_data.to_vec().into(),
            ciphertext: ciphertext.to_vec().into(),
        };

        let decrypt_res = self.op_client.process_operation(
            NativeOperation::PsaAeadDecrypt(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaAeadDecrypt(res) = decrypt_res {
            Ok(res.plaintext.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Cryptographic Operation]** Perform a raw key agreement.
    ///
    /// The provided private key **must** have its `derive` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// The raw_key_agreement will be performed with the algorithm defined in `alg`,
    /// but only after checking that the key policy and type conform with it.
    ///
    /// `peer_key` must be the peer public key to use in the raw key derivation. It must
    /// be in a format supported by [`PsaImportKey`](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_import_key.html).
    ///
    /// # Errors
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_raw_key_agreement.html#specific-response-status-codes).
    pub fn psa_raw_key_agreement(
        &self,
        alg: RawKeyAgreement,
        private_key_name: String,
        peer_key: &[u8],
    ) -> Result<Vec<u8>> {
        let op = PsaRawKeyAgreement {
            alg,
            private_key_name,
            peer_key: Zeroizing::new(peer_key.to_vec()),
        };
        let crypto_provider = self.can_provide_crypto()?;
        let raw_key_agreement_res = self.op_client.process_operation(
            NativeOperation::PsaRawKeyAgreement(op),
            crypto_provider,
            &self.auth_data,
        )?;
        if let NativeResult::PsaRawKeyAgreement(res) = raw_key_agreement_res {
            Ok(res.shared_secret.expose_secret().to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Cryptographic Operation]** Generate some random bytes.
    ///
    /// Generates a sequence of random bytes and returns them to the user.
    ///
    /// # Errors
    ///
    /// If this method returns an error, no bytes will have been generated.
    ///
    /// If the implicit client provider is `ProviderID::Core`, a client error
    /// of `InvalidProvider` type is returned.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/psa_generate_random.html).
    pub fn psa_generate_random(&self, nbytes: usize) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaGenerateRandom { size: nbytes };

        let res = self.op_client.process_operation(
            NativeOperation::PsaGenerateRandom(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaGenerateRandom(res) = res {
            Ok(res.random_bytes.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    fn can_provide_crypto(&self) -> Result<ProviderID> {
        match self.implicit_provider {
            ProviderID::Core => Err(Error::Client(ClientErrorKind::InvalidProvider)),
            crypto_provider => Ok(crypto_provider),
        }
    }
}
