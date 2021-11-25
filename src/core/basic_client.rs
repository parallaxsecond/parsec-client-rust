// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Basic client for Parsec integration
use super::operation_client::OperationClient;
use crate::auth::Authentication;
use crate::error::{ClientErrorKind, Error, Result};
use log::{debug, warn};
use parsec_interface::operations::attest_key::{Operation as AttestKey, Result as AttestKeyResult};
use parsec_interface::operations::can_do_crypto::{CheckType, Operation as CanDoCrypto};
use parsec_interface::operations::delete_client::Operation as DeleteClient;
use parsec_interface::operations::list_authenticators::{
    AuthenticatorInfo, Operation as ListAuthenticators,
};
use parsec_interface::operations::list_clients::Operation as ListClients;
use parsec_interface::operations::list_keys::{KeyInfo, Operation as ListKeys};
use parsec_interface::operations::list_opcodes::Operation as ListOpcodes;
use parsec_interface::operations::list_providers::{Operation as ListProviders, ProviderInfo};
use parsec_interface::operations::ping::Operation as Ping;
use parsec_interface::operations::prepare_key_attestation::{
    Operation as PrepareKeyAttestation, Result as PrepareKeyAttestationResult,
};
use parsec_interface::operations::psa_aead_decrypt::Operation as PsaAeadDecrypt;
use parsec_interface::operations::psa_aead_encrypt::Operation as PsaAeadEncrypt;
use parsec_interface::operations::psa_algorithm::{
    Aead, AsymmetricEncryption, AsymmetricSignature, Cipher, Hash, RawKeyAgreement,
};
use parsec_interface::operations::psa_asymmetric_decrypt::Operation as PsaAsymDecrypt;
use parsec_interface::operations::psa_asymmetric_encrypt::Operation as PsaAsymEncrypt;
use parsec_interface::operations::psa_cipher_decrypt::Operation as PsaCipherDecrypt;
use parsec_interface::operations::psa_cipher_encrypt::Operation as PsaCipherEncrypt;
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
use parsec_interface::operations::psa_sign_message::Operation as PsaSignMessage;
use parsec_interface::operations::psa_verify_hash::Operation as PsaVerifyHash;
use parsec_interface::operations::psa_verify_message::Operation as PsaVerifyMessage;
use parsec_interface::operations::{NativeOperation, NativeResult};
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{Opcode, ProviderId};
use parsec_interface::secrecy::{ExposeSecret, Secret};
use std::collections::HashSet;
use zeroize::Zeroizing;

/// Core client for the Parsec service
///
/// The client exposes low-level functionality for using the Parsec service.
/// Below you can see code examples for a few of the operations supported.
///
/// Providers are abstracted representations of the secure elements that
/// Parsec offers abstraction over. Providers are the ones to execute the
/// cryptographic operations requested by the user.
///
/// For all cryptographic operations an implicit provider is used which can be
/// changed between operations. The client starts with the default provider, the first
/// one returned by the ListProviders operation.
///
/// For crypto operations, if the implicit client provider is `ProviderId::Core`, a client error
/// of `InvalidProvider` type is returned.
/// See the operation-specific response codes returned by the service in the operation's page
/// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/index.html).
#[derive(Debug)]
pub struct BasicClient {
    pub(crate) op_client: OperationClient,
    pub(crate) auth_data: Authentication,
    pub(crate) implicit_provider: ProviderId,
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
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///# Ok(())}
    ///```
    pub fn new(app_name: Option<String>) -> Result<Self> {
        let mut client = BasicClient {
            op_client: OperationClient::new()?,
            auth_data: Authentication::None,
            implicit_provider: ProviderId::Core,
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
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///let client = BasicClient::new_naked()?;
    ///let (major, minor) = client.ping()?;
    ///# Ok(())}
    /// ```
    pub fn new_naked() -> Result<Self> {
        Ok(BasicClient {
            op_client: OperationClient::new()?,
            auth_data: Authentication::None,
            implicit_provider: ProviderId::Core,
        })
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
    ///
    /// # Example
    ///
    /// ```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::core::interface::requests::ProviderId;
    ///let mut client = BasicClient::new_naked()?;
    ///// Set the default authenticator but choose a specific provider.
    ///client.set_implicit_provider(ProviderId::Pkcs11);
    ///client.set_default_auth(Some("main_client".to_string()))?;
    ///# Ok(())}
    /// ```
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
                #[cfg(feature = "spiffe-auth")]
                AuthType::JwtSvid => self.auth_data = Authentication::JwtSvid,
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
    ///
    /// This is useful if you want to use a different authentication method than
    /// the default one.
    ///
    /// # Example
    ///
    /// See [`set_default_provider`].
    pub fn set_auth_data(&mut self, auth_data: Authentication) {
        self.auth_data = auth_data;
    }

    /// Retrieve authentication data of the client.
    ///
    /// # Example
    ///
    /// ```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::auth::Authentication;
    ///let mut client = BasicClient::new_naked()?;
    ///client.set_auth_data(Authentication::UnixPeerCredentials);
    ///assert_eq!(Authentication::UnixPeerCredentials, client.auth_data());
    ///# Ok(())}
    /// ```
    pub fn auth_data(&self) -> Authentication {
        self.auth_data.clone()
    }

    /// Query for the service provider list and set the default one as implicit
    ///
    /// # Errors
    ///
    /// If no provider is returned by the service, an client error of `NoProvider`
    /// type is returned.
    ///
    /// # Example
    ///
    /// ```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::auth::Authentication;
    ///let mut client = BasicClient::new_naked()?;
    ///// Use the default provider but use a specific authentication.
    ///client.set_default_provider()?;
    ///client.set_auth_data(Authentication::UnixPeerCredentials);
    ///# Ok(())}
    /// ```
    pub fn set_default_provider(&mut self) -> Result<()> {
        let providers = self.list_providers()?;
        if providers.is_empty() {
            return Err(Error::Client(ClientErrorKind::NoProvider));
        }
        self.implicit_provider = providers[0].id;

        Ok(())
    }

    /// Set the provider that the client will be implicitly working with.
    ///
    /// # Example
    ///
    /// See [`set_default_auth`].
    pub fn set_implicit_provider(&mut self, provider: ProviderId) {
        self.implicit_provider = provider;
    }

    /// Retrieve client's implicit provider.
    ///
    /// # Example
    ///
    /// ```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::core::interface::requests::ProviderId;
    ///let mut client = BasicClient::new_naked()?;
    ///client.set_implicit_provider(ProviderId::Pkcs11);
    ///assert_eq!(ProviderId::Pkcs11, client.implicit_provider());
    ///# Ok(())}
    /// ```
    pub fn implicit_provider(&self) -> ProviderId {
        self.implicit_provider
    }

    /// **[Core Operation]** List the opcodes supported by the specified provider.
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::core::interface::requests::{Opcode, ProviderId};
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let opcodes = client.list_opcodes(ProviderId::Pkcs11)?;
    ///if opcodes.contains(&Opcode::PsaGenerateRandom) {
    ///    let random_bytes = client.psa_generate_random(10)?;
    ///}
    ///# Ok(())}
    ///# Ok(())}
    ///```
    pub fn list_opcodes(&self, provider: ProviderId) -> Result<HashSet<Opcode>> {
        let res = self.op_client.process_operation(
            NativeOperation::ListOpcodes(ListOpcodes {
                provider_id: provider,
            }),
            ProviderId::Core,
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
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///
    ///let mut client: BasicClient = BasicClient::new_naked()?;
    ///let providers = client.list_providers()?;
    ///// Set the second most prioritary provider
    ///client.set_implicit_provider(providers[1].id);
    ///# Ok(())}
    ///```
    pub fn list_providers(&self) -> Result<Vec<ProviderInfo>> {
        let res = self.op_client.process_operation(
            NativeOperation::ListProviders(ListProviders {}),
            ProviderId::Core,
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
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let opcodes = client.list_authenticators()?;
    ///# Ok(())}
    ///```
    pub fn list_authenticators(&self) -> Result<Vec<AuthenticatorInfo>> {
        let res = self.op_client.process_operation(
            NativeOperation::ListAuthenticators(ListAuthenticators {}),
            ProviderId::Core,
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
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let keys = client.list_keys()?;
    ///# Ok(())}
    ///```
    pub fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let res = self.op_client.process_operation(
            NativeOperation::ListKeys(ListKeys {}),
            ProviderId::Core,
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
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if a key with this name does not exist.
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let attributes = client.key_attributes("my_key")?;
    ///# Ok(())}
    ///```
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
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let clients = client.list_clients()?;
    ///# Ok(())}
    ///```
    pub fn list_clients(&self) -> Result<Vec<String>> {
        let res = self.op_client.process_operation(
            NativeOperation::ListClients(ListClients {}),
            ProviderId::Core,
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
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///client.delete_client("main_client")?;
    ///# Ok(())}
    ///```
    pub fn delete_client(&self, client: &str) -> Result<()> {
        let res = self.op_client.process_operation(
            NativeOperation::DeleteClient(DeleteClient {
                client: client.to_string(),
            }),
            ProviderId::Core,
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
    ///
    /// # Example
    ///
    /// See [`new_naked`].
    pub fn ping(&self) -> Result<(u8, u8)> {
        let res = self.op_client.process_operation(
            NativeOperation::Ping(Ping {}),
            ProviderId::Core,
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
    /// providers persist all the keys users create.
    ///
    /// If this method returns an error, no key will have been generated and
    /// the name used will still be available for another key.
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::core::interface::operations::psa_key_attributes::{Attributes, Lifetime, Policy, Type, UsageFlags};
    ///use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricSignature, Hash};
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let key_attrs = Attributes {
    ///    lifetime: Lifetime::Persistent,
    ///    key_type: Type::RsaKeyPair,
    ///    bits: 2048,
    ///    policy: Policy {
    ///        usage_flags: UsageFlags::default(),
    ///        permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
    ///            hash_alg: Hash::Sha256.into(),
    ///        }.into(),
    ///    },
    ///};
    ///client.psa_generate_key("my_key", key_attrs)?;
    ///# Ok(())}
    ///```
    pub fn psa_generate_key(&self, key_name: &str, key_attributes: Attributes) -> Result<()> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaGenerateKey {
            key_name: String::from(key_name),
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
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///client.psa_destroy_key("my_key")?;
    ///# Ok(())}
    ///```
    pub fn psa_destroy_key(&self, key_name: &str) -> Result<()> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaDestroyKey {
            key_name: String::from(key_name),
        };

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
    /// If this method returns an error, no key will have been imported and the
    /// name used will still be available for another key.
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::core::interface::operations::psa_key_attributes::{Attributes, Lifetime, Policy, Type, UsageFlags, EccFamily};
    ///use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricSignature, Hash};
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let ecc_private_key = vec![
    ///    0x26, 0xc8, 0x82, 0x9e, 0x22, 0xe3, 0x0c, 0xa6, 0x3d, 0x29, 0xf5, 0xf7, 0x27, 0x39, 0x58, 0x47,
    ///    0x41, 0x81, 0xf6, 0x57, 0x4f, 0xdb, 0xcb, 0x4d, 0xbb, 0xdd, 0x52, 0xff, 0x3a, 0xc0, 0xf6, 0x0d,
    ///];
    ///let key_attrs = Attributes {
    ///    lifetime: Lifetime::Persistent,
    ///    key_type: Type::EccKeyPair {
    ///        curve_family: EccFamily::SecpR1,
    ///    },
    ///    bits: 256,
    ///    policy: Policy {
    ///        usage_flags: UsageFlags::default(),
    ///        permitted_algorithms: AsymmetricSignature::RsaPkcs1v15Sign {
    ///            hash_alg: Hash::Sha256.into(),
    ///        }.into(),
    ///    },
    ///};
    ///client.psa_import_key("my_key", &ecc_private_key, key_attrs)?;
    ///# Ok(())}
    ///```
    pub fn psa_import_key(
        &self,
        key_name: &str,
        key_material: &[u8],
        key_attributes: Attributes,
    ) -> Result<()> {
        let key_material = Secret::new(key_material.to_vec());
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaImportKey {
            key_name: String::from(key_name),
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
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let public_key_data = client.psa_export_public_key("my_key");
    ///# Ok(())}
    ///```
    pub fn psa_export_public_key(&self, key_name: &str) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaExportPublicKey {
            key_name: String::from(key_name),
        };

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
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let key_data = client.psa_export_key("my_key");
    ///# Ok(())}
    ///```
    pub fn psa_export_key(&self, key_name: &str) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaExportKey {
            key_name: String::from(key_name),
        };

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
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::core::interface::operations::psa_key_attributes::{Attributes, Lifetime, Policy, Type, UsageFlags};
    ///use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricSignature, Hash};
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///// Hash of a message pre-calculated with SHA-256.
    ///let hash = vec![
    ///  0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    ///  0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
    ///];
    ///let signature = client.psa_sign_hash("my_key", &hash, AsymmetricSignature::RsaPkcs1v15Sign {
    ///hash_alg: Hash::Sha256.into(),
    ///})?;
    ///# Ok(())}
    ///```
    pub fn psa_sign_hash(
        &self,
        key_name: &str,
        hash: &[u8],
        sign_algorithm: AsymmetricSignature,
    ) -> Result<Vec<u8>> {
        let hash = Zeroizing::new(hash.to_vec());
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaSignHash {
            key_name: String::from(key_name),
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
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::core::interface::operations::psa_key_attributes::{Attributes, Lifetime, Policy, Type, UsageFlags};
    ///use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricSignature, Hash};
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///// Hash of a message pre-calculated with SHA-256.
    ///let hash = vec![
    ///    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    ///    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
    ///];
    ///let alg = AsymmetricSignature::RsaPkcs1v15Sign {
    ///    hash_alg: Hash::Sha256.into(),
    ///};
    ///let signature = client.psa_sign_hash("my_key", &hash, alg)?;
    ///client.psa_verify_hash("my_key", &hash, alg, &signature)?;
    ///# Ok(())}
    ///```
    pub fn psa_verify_hash(
        &self,
        key_name: &str,
        hash: &[u8],
        sign_algorithm: AsymmetricSignature,
        signature: &[u8],
    ) -> Result<()> {
        let hash = Zeroizing::new(hash.to_vec());
        let signature = Zeroizing::new(signature.to_vec());
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaVerifyHash {
            key_name: String::from(key_name),
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

    /// **[Cryptographic Operation]** Create an asymmetric signature on a message.
    ///
    /// The key intended for signing **must** have its `sign_message` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// The signature will be created with the algorithm defined in
    /// `sign_algorithm`, but only after checking that the key policy
    /// and type conform with it.
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::core::interface::operations::psa_key_attributes::{Attributes, Lifetime, Policy, Type, UsageFlags};
    ///use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricSignature, Hash};
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let message = "This is the message to sign which can be of any size!".as_bytes();
    ///let signature = client.psa_sign_message(
    ///    "my_key",
    ///    message,
    ///    AsymmetricSignature::RsaPkcs1v15Sign {
    ///        hash_alg: Hash::Sha256.into(),
    ///    }
    ///)?;
    ///# Ok(())}
    ///```
    pub fn psa_sign_message(
        &self,
        key_name: &str,
        msg: &[u8],
        sign_algorithm: AsymmetricSignature,
    ) -> Result<Vec<u8>> {
        let message = Zeroizing::new(msg.to_vec());
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaSignMessage {
            key_name: String::from(key_name),
            alg: sign_algorithm,
            message,
        };

        let res = self.op_client.process_operation(
            NativeOperation::PsaSignMessage(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaSignMessage(res) = res {
            Ok(res.signature.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Cryptographic Operation]** Verify an existing asymmetric signature over a message.
    ///
    /// The key intended for signing **must** have its `verify_message` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// The signature will be verifyied with the algorithm defined in
    /// `sign_algorithm`, but only after checking that the key policy
    /// and type conform with it.
    ///
    /// # Example
    ///
    ///```no_run
    ///# use std::error::Error;
    ///#
    ///# fn main() -> Result<(), Box<dyn Error>> {
    ///use parsec_client::BasicClient;
    ///use parsec_client::core::interface::operations::psa_key_attributes::{Attributes, Lifetime, Policy, Type, UsageFlags};
    ///use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricSignature, Hash};
    ///
    ///let client: BasicClient = BasicClient::new(None)?;
    ///let message = "This is the message to sign which can be of any size!".as_bytes();
    ///let alg = AsymmetricSignature::RsaPkcs1v15Sign {
    ///    hash_alg: Hash::Sha256.into(),
    ///};
    ///let signature = client.psa_sign_message("my_key", message, alg)?;
    ///client.psa_verify_message("my_key", message, alg, &signature)?;
    ///# Ok(())}
    ///```
    pub fn psa_verify_message(
        &self,
        key_name: &str,
        msg: &[u8],
        sign_algorithm: AsymmetricSignature,
        signature: &[u8],
    ) -> Result<()> {
        let message = Zeroizing::new(msg.to_vec());
        let signature = Zeroizing::new(signature.to_vec());
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaVerifyMessage {
            key_name: String::from(key_name),
            alg: sign_algorithm,
            message,
            signature,
        };

        let _ = self.op_client.process_operation(
            NativeOperation::PsaVerifyMessage(op),
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
    ///   an empty vector. If the algorithm supports optional salt, pass an empty vector to indicate no
    ///   salt. For RSA PKCS#1 v1.5 encryption, no salt is supported.
    pub fn psa_asymmetric_encrypt(
        &self,
        key_name: &str,
        encrypt_alg: AsymmetricEncryption,
        plaintext: &[u8],
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let salt = salt.map(|salt_ref| salt_ref.to_vec().into());
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaAsymEncrypt {
            key_name: String::from(key_name),
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
    /// an empty vector. If the algorithm supports optional salt, pass an empty vector to indicate no
    /// salt. For RSA PKCS#1 v1.5 encryption, no salt is supported.
    ///
    ///
    /// The decryption will be performed with the algorithm defined in `alg`,
    /// but only after checking that the key policy and type conform with it.
    pub fn psa_asymmetric_decrypt(
        &self,
        key_name: &str,
        encrypt_alg: AsymmetricEncryption,
        ciphertext: &[u8],
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let salt = salt.map(|salt| Zeroizing::new(salt.to_vec()));
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaAsymDecrypt {
            key_name: String::from(key_name),
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
    pub fn psa_aead_encrypt(
        &self,
        key_name: &str,
        encrypt_alg: Aead,
        nonce: &[u8],
        additional_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaAeadEncrypt {
            key_name: String::from(key_name),
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
    pub fn psa_aead_decrypt(
        &self,
        key_name: &str,
        encrypt_alg: Aead,
        nonce: &[u8],
        additional_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaAeadDecrypt {
            key_name: String::from(key_name),
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

    /// **[Cryptographic Operation]** Encrypt a short message with a symmetric cipher.
    ///
    /// The key intended for decrypting **must** have its `encrypt` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// This function will encrypt a short message with a random initialisation vector (IV).
    pub fn psa_cipher_encrypt(
        &self,
        key_name: String,
        alg: Cipher,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaCipherEncrypt {
            key_name,
            alg,
            plaintext: plaintext.to_vec().into(),
        };

        let res = self.op_client.process_operation(
            NativeOperation::PsaCipherEncrypt(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaCipherEncrypt(res) = res {
            Ok(res.ciphertext.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Cryptographic Operation]** Decrypt a short message with a symmetric cipher.
    ///
    /// The key intended for decrypting **must** have its `decrypt` flag set
    /// to `true` in its [key policy](https://docs.rs/parsec-interface/*/parsec_interface/operations/psa_key_attributes/struct.Policy.html).
    ///
    /// `ciphertext` must be the IV followed by the ciphertext.
    ///
    /// This function will decrypt a short message using the provided initialisation vector (IV).
    pub fn psa_cipher_decrypt(
        &self,
        key_name: String,
        alg: Cipher,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let crypto_provider = self.can_provide_crypto()?;

        let op = PsaCipherDecrypt {
            key_name,
            alg,
            ciphertext: ciphertext.to_vec().into(),
        };

        let res = self.op_client.process_operation(
            NativeOperation::PsaCipherDecrypt(op),
            crypto_provider,
            &self.auth_data,
        )?;

        if let NativeResult::PsaCipherDecrypt(res) = res {
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
    pub fn psa_raw_key_agreement(
        &self,
        alg: RawKeyAgreement,
        private_key_name: &str,
        peer_key: &[u8],
    ) -> Result<Vec<u8>> {
        let op = PsaRawKeyAgreement {
            alg,
            private_key_name: String::from(private_key_name),
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
    /// If this method returns an error, no bytes will have been generated.
    ///
    /// # Example
    ///
    /// See [`list_opcodes`].
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

    /// **[Capability Discovery Operation]** Check if attributes are supported.
    ///
    /// Checks if the given attributes are supported for the given type of operation.
    ///
    /// #Errors
    ///
    /// This operation will either return Ok(()) or Err(PsaErrorNotSupported) indicating whether the attributes are supported.
    ///
    /// See the operation-specific response codes returned by the service
    /// [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/can_do_crypto.html#specific-response-status-codes).
    pub fn can_do_crypto(&self, check_type: CheckType, attributes: Attributes) -> Result<()> {
        let crypto_provider = self.can_provide_crypto()?;
        let op = CanDoCrypto {
            check_type,
            attributes,
        };
        let _ = self.op_client.process_operation(
            NativeOperation::CanDoCrypto(op),
            crypto_provider,
            &self.auth_data,
        )?;
        Ok(())
    }

    /// **[Cryptographic Operation]** Get data required to prepare an
    /// ActivateCredential key attestation.
    ///
    /// Retrieve the binary blobs required by a third party to perform a
    /// MakeCredential operation, in preparation for a key attestation using
    /// ActivateCredential.
    ///
    /// **This key attestation method is TPM-specific**
    pub fn prepare_activate_credential(
        &self,
        attested_key_name: String,
        attesting_key_name: Option<String>,
    ) -> Result<PrepareActivateCredential> {
        self.can_use_provider(ProviderId::Tpm)?;

        let op = PrepareKeyAttestation::ActivateCredential {
            attested_key_name,
            attesting_key_name,
        };

        let res = self.op_client.process_operation(
            NativeOperation::PrepareKeyAttestation(op),
            ProviderId::Tpm,
            &self.auth_data,
        )?;

        if let NativeResult::PrepareKeyAttestation(
            PrepareKeyAttestationResult::ActivateCredential {
                name,
                public,
                attesting_key_pub,
            },
        ) = res
        {
            Ok(PrepareActivateCredential {
                name: name.to_vec(),
                public: public.to_vec(),
                attesting_key_pub: attesting_key_pub.to_vec(),
            })
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    /// **[Cryptographic Operation]** Perform a key attestation operation via
    /// ActivateCredential
    ///
    /// **This key attestation method is TPM-specific**
    ///
    /// You can see more details on the inner-workings, and on the requirements
    /// for this operation [here](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/attest_key.html).
    ///
    /// Before performing an ActivateCredential attestation you must compute
    /// the `credential_blob` and `secret` parameters using the outputs from
    /// the `prepare_activate_credential` method.
    pub fn activate_credential_attestation(
        &self,
        attested_key_name: String,
        attesting_key_name: Option<String>,
        credential_blob: Vec<u8>,
        secret: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.can_use_provider(ProviderId::Tpm)?;

        let op = AttestKey::ActivateCredential {
            attested_key_name,
            attesting_key_name,
            credential_blob: credential_blob.into(),
            secret: secret.into(),
        };

        let res = self.op_client.process_operation(
            NativeOperation::AttestKey(op),
            ProviderId::Tpm,
            &self.auth_data,
        )?;

        if let NativeResult::AttestKey(AttestKeyResult::ActivateCredential { credential }) = res {
            Ok(credential.to_vec())
        } else {
            // Should really not be reached given the checks we do, but it's not impossible if some
            // changes happen in the interface
            Err(Error::Client(ClientErrorKind::InvalidServiceResponseType))
        }
    }

    fn can_provide_crypto(&self) -> Result<ProviderId> {
        match self.implicit_provider {
            ProviderId::Core => Err(Error::Client(ClientErrorKind::InvalidProvider)),
            crypto_provider => Ok(crypto_provider),
        }
    }

    fn can_use_provider(&self, provider: ProviderId) -> Result<()> {
        let providers = self.list_providers()?;
        if providers.iter().any(|prov| prov.id == provider) {
            Ok(())
        } else {
            Err(Error::Client(ClientErrorKind::NoProvider))
        }
    }
}

impl Default for BasicClient {
    fn default() -> Self {
        BasicClient {
            op_client: Default::default(),
            auth_data: Authentication::None,
            implicit_provider: ProviderId::Core,
        }
    }
}

/// Wrapper for the data needed to prepare for an
/// ActivateCredential attestation.
#[derive(Debug)]
pub struct PrepareActivateCredential {
    /// TPM name of key to be attested
    pub name: Vec<u8>,
    /// Bytes representing the serialized version of the key public parameters
    pub public: Vec<u8>,
    /// The public part of the attesting key
    pub attesting_key_pub: Vec<u8>,
}
