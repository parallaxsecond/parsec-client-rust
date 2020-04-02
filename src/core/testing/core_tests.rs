// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{TestCoreClient, DEFAULT_APP_NAME};
use crate::error::{ClientErrorKind, Error};
use mockstream::MockStream;
use parsec_interface::operations;
use parsec_interface::operations::list_providers::ProviderInfo;
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::operations::Convert;
use parsec_interface::operations::{NativeOperation, NativeResult};
use parsec_interface::operations_protobuf::ProtobufConverter;
use parsec_interface::requests::Response;
use parsec_interface::requests::ResponseStatus;
use parsec_interface::requests::{request::RequestHeader, Request};
use parsec_interface::requests::{AuthType, BodyType, Opcode, ProviderID};
use std::collections::HashSet;

const PROTOBUF_CONVERTER: ProtobufConverter = ProtobufConverter {};
const REQ_HEADER: RequestHeader = RequestHeader {
    version_maj: 1,
    version_min: 0,
    provider: ProviderID::Core,
    session: 0,
    content_type: BodyType::Protobuf,
    accept_type: BodyType::Protobuf,
    auth_type: AuthType::NoAuth,
    opcode: Opcode::Ping,
};

fn get_response_bytes_from_result(result: NativeResult) -> Vec<u8> {
    let mut stream = MockStream::new();
    let mut req_hdr = REQ_HEADER;
    req_hdr.opcode = result.opcode();
    let mut resp = Response::from_request_header(req_hdr, ResponseStatus::Success);
    resp.body = PROTOBUF_CONVERTER.result_to_body(result).unwrap();
    resp.write_to_stream(&mut stream).unwrap();
    stream.pop_bytes_written()
}

fn get_req_from_bytes(bytes: Vec<u8>) -> Request {
    let mut stream = MockStream::new();
    stream.push_bytes_to_read(&bytes);
    Request::read_from_stream(&mut stream, usize::max_value()).unwrap()
}

fn get_operation_from_req_bytes(bytes: Vec<u8>) -> NativeOperation {
    let req = get_req_from_bytes(bytes);
    PROTOBUF_CONVERTER
        .body_to_operation(req.body, req.header.opcode)
        .unwrap()
}

#[test]
fn ping_test() {
    let mut client: TestCoreClient = Default::default();
    client.set_mock_read(&get_response_bytes_from_result(NativeResult::Ping(
        operations::ping::Result {
            wire_protocol_version_maj: 1,
            wire_protocol_version_min: 0,
        },
    )));
    // Check request:
    // Ping request is empty so no checking to be done

    // Check response:
    assert_eq!(client.ping().expect("Ping failed"), (1, 0));
}

#[test]
fn list_provider_test() {
    let mut client: TestCoreClient = Default::default();
    let mut provider_info = Vec::new();
    provider_info.push(ProviderInfo {
        uuid: uuid::Uuid::nil(),
        description: String::from("Some empty provider"),
        vendor: String::from("Arm Ltd."),
        version_maj: 1,
        version_min: 0,
        version_rev: 0,
        id: ProviderID::Core,
    });
    client.set_mock_read(&get_response_bytes_from_result(
        NativeResult::ListProviders(operations::list_providers::Result {
            providers: provider_info,
        }),
    ));
    let providers = client.list_providers().expect("Failed to list providers");
    // Check request:
    // ListProviders request is empty so no checking to be done

    // Check response:
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].uuid, uuid::Uuid::nil());
}

#[test]
fn list_provider_operations_test() {
    let mut client: TestCoreClient = Default::default();
    let mut opcodes = HashSet::new();
    let _ = opcodes.insert(Opcode::PsaDestroyKey);
    let _ = opcodes.insert(Opcode::PsaGenerateKey);
    client.set_mock_read(&get_response_bytes_from_result(NativeResult::ListOpcodes(
        operations::list_opcodes::Result { opcodes },
    )));
    let opcodes = client
        .list_provider_operations(ProviderID::MbedCrypto)
        .expect("Failed to retrieve opcodes");
    // Check request:
    // ListOpcodes request is empty so no checking to be done

    // Check response:
    assert_eq!(opcodes.len(), 2);
    assert!(opcodes.contains(&Opcode::PsaGenerateKey) && opcodes.contains(&Opcode::PsaDestroyKey));
}

#[test]
fn generate_key_test() {
    let mut client: TestCoreClient = Default::default();
    client.set_mock_read(&get_response_bytes_from_result(
        NativeResult::PsaGenerateKey(operations::psa_generate_key::Result {}),
    ));
    let key_name = String::from("key-name");
    let key_attrs = KeyAttributes {
        key_type: KeyType::Aes,
        key_bits: 192,
        key_policy: KeyPolicy {
            key_usage_flags: UsageFlags {
                export: true,
                copy: true,
                cache: true,
                encrypt: false,
                decrypt: true,
                sign_message: false,
                verify_message: false,
                sign_hash: false,
                verify_hash: false,
                derive: false,
            },
            key_algorithm: Algorithm::Cipher(Cipher::Ctr),
        },
    };

    client
        .generate_key(ProviderID::Tpm, key_name.clone(), key_attrs.clone())
        .expect("failed to generate key");

    // Check request:
    let op = get_operation_from_req_bytes(client.get_mock_write());
    if let NativeOperation::PsaGenerateKey(op) = op {
        assert_eq!(op.attributes, key_attrs);
        assert_eq!(op.key_name, key_name);
    } else {
        panic!("Got wrong operation type: {:?}", op);
    }

    // Check response:
    // GenerateKey response is empty so no checking to be done
}

#[test]
fn destroy_key_test() {
    let mut client: TestCoreClient = Default::default();
    client.set_mock_read(&get_response_bytes_from_result(
        NativeResult::PsaDestroyKey(operations::psa_destroy_key::Result {}),
    ));
    let key_name = String::from("key-name");
    client
        .destroy_key(ProviderID::Pkcs11, key_name.clone())
        .expect("Failed to call destroy key");

    // Check request:
    let op = get_operation_from_req_bytes(client.get_mock_write());
    if let NativeOperation::PsaDestroyKey(op) = op {
        assert_eq!(op.key_name, key_name);
    } else {
        panic!("Got wrong operation type: {:?}", op);
    }

    // Check response:
    // DestroyKey response is empty so no checking to be done
}

#[test]
fn import_key_test() {
    let mut client: TestCoreClient = Default::default();
    client.set_mock_read(&get_response_bytes_from_result(NativeResult::PsaImportKey(
        operations::psa_import_key::Result {},
    )));
    let key_name = String::from("key-name");
    let key_attrs = KeyAttributes {
        key_type: KeyType::Aes,
        key_bits: 192,
        key_policy: KeyPolicy {
            key_usage_flags: UsageFlags {
                export: true,
                copy: true,
                cache: true,
                encrypt: false,
                decrypt: true,
                sign_message: false,
                verify_message: false,
                sign_hash: false,
                verify_hash: false,
                derive: false,
            },
            key_algorithm: Algorithm::Cipher(Cipher::Ctr),
        },
    };
    let key_data = vec![0xff_u8; 128];
    client
        .import_key(
            ProviderID::Pkcs11,
            key_name.clone(),
            key_data.clone(),
            key_attrs.clone(),
        )
        .unwrap();

    // Check request:
    let op = get_operation_from_req_bytes(client.get_mock_write());
    if let NativeOperation::PsaImportKey(op) = op {
        assert_eq!(op.attributes, key_attrs);
        assert_eq!(op.key_name, key_name);
        assert_eq!(op.data, key_data);
    } else {
        panic!("Got wrong operation type: {:?}", op);
    }

    // Check response:
    // ImportKey response is empty so no checking to be done
}

#[test]
fn export_public_key_test() {
    let mut client: TestCoreClient = Default::default();
    let key_data = vec![0xa5; 128];
    client.set_mock_read(&get_response_bytes_from_result(
        NativeResult::PsaExportPublicKey(operations::psa_export_public_key::Result {
            data: key_data.clone(),
        }),
    ));

    let key_name = String::from("key-name");
    // Check response:
    assert_eq!(
        client
            .export_public_key(ProviderID::MbedCrypto, key_name.clone())
            .expect("Failed to export public key"),
        key_data
    );

    // Check request:
    let op = get_operation_from_req_bytes(client.get_mock_write());
    if let NativeOperation::PsaExportPublicKey(op) = op {
        assert_eq!(op.key_name, key_name);
    } else {
        panic!("Got wrong operation type: {:?}", op);
    }
}

#[test]
fn sign_hash_test() {
    let mut client: TestCoreClient = Default::default();
    let hash = vec![0x77_u8; 32];
    let key_name = String::from("key_name");
    let sign_algorithm = AsymmetricSignature::Ecdsa {
        hash_alg: Hash::Sha256,
    };
    let signature = vec![0x33_u8; 128];
    client.set_mock_read(&get_response_bytes_from_result(NativeResult::PsaSignHash(
        operations::psa_sign_hash::Result {
            signature: signature.clone(),
        },
    )));

    // Check response:
    assert_eq!(
        client
            .sign_hash(
                ProviderID::MbedCrypto,
                key_name.clone(),
                hash.clone(),
                sign_algorithm.clone()
            )
            .expect("Failed to sign hash"),
        signature
    );

    // Check request:
    let op = get_operation_from_req_bytes(client.get_mock_write());
    if let NativeOperation::PsaSignHash(op) = op {
        assert_eq!(op.key_name, key_name);
        assert_eq!(op.hash, hash);
        assert_eq!(op.alg, sign_algorithm);
    } else {
        panic!("Got wrong operation type: {:?}", op);
    }
}

#[test]
fn verify_hash_test() {
    let mut client: TestCoreClient = Default::default();
    let hash = vec![0x77_u8; 32];
    let key_name = String::from("key_name");
    let sign_algorithm = AsymmetricSignature::Ecdsa {
        hash_alg: Hash::Sha256,
    };
    let signature = vec![0x33_u8; 128];
    client.set_mock_read(&get_response_bytes_from_result(
        NativeResult::PsaVerifyHash(operations::psa_verify_hash::Result {}),
    ));

    client
        .verify_hash_signature(
            ProviderID::MbedCrypto,
            key_name.clone(),
            hash.clone(),
            sign_algorithm.clone(),
            signature.clone(),
        )
        .expect("Failed to sign hash");

    // Check request:
    let op = get_operation_from_req_bytes(client.get_mock_write());
    if let NativeOperation::PsaVerifyHash(op) = op {
        assert_eq!(op.key_name, key_name);
        assert_eq!(op.hash, hash);
        assert_eq!(op.alg, sign_algorithm);
        assert_eq!(op.signature, signature);
    } else {
        panic!("Got wrong operation type: {:?}", op);
    }

    // Check response:
    // VerifyHash response is empty so no checking to be done
}

#[test]
fn different_response_type_test() {
    let mut client: TestCoreClient = Default::default();
    client.set_mock_read(&get_response_bytes_from_result(
        NativeResult::PsaVerifyHash(operations::psa_verify_hash::Result {}),
    ));
    let key_name = String::from("key-name");
    let err = client
        .destroy_key(ProviderID::Pkcs11, key_name)
        .expect_err("Error was expected");

    assert_eq!(
        err,
        Error::Client(ClientErrorKind::InvalidServiceResponseType)
    );
}

#[test]
fn response_status_test() {
    let mut client: TestCoreClient = Default::default();
    let mut stream = MockStream::new();
    let status = ResponseStatus::PsaErrorDataCorrupt;
    let mut resp = Response::from_request_header(REQ_HEADER, ResponseStatus::Success);
    resp.header.status = status;
    resp.write_to_stream(&mut stream).unwrap();
    client.set_mock_read(&stream.pop_bytes_written());
    let err = client.ping().expect_err("Error was expected");

    assert_eq!(err, Error::Service(status));
}

#[test]
fn malformed_response_test() {
    let mut client: TestCoreClient = Default::default();
    client.set_mock_read(&[0xcb_u8; 130]);
    let err = client.ping().expect_err("Error was expected");

    assert_eq!(
        err,
        Error::Client(ClientErrorKind::Interface(ResponseStatus::InvalidHeader))
    );
}

#[test]
fn request_fields_test() {
    let mut client: TestCoreClient = Default::default();
    client.set_mock_read(&get_response_bytes_from_result(NativeResult::Ping(
        operations::ping::Result {
            wire_protocol_version_maj: 1,
            wire_protocol_version_min: 0,
        },
    )));
    let _ = client.ping().expect("Ping failed");

    let req = get_req_from_bytes(client.get_mock_write());
    assert_eq!(req.header, REQ_HEADER);
}

#[test]
fn auth_value_test() {
    let mut client: TestCoreClient = Default::default();
    client.set_mock_read(&get_response_bytes_from_result(
        NativeResult::PsaDestroyKey(operations::psa_destroy_key::Result {}),
    ));
    let key_name = String::from("key-name");
    client
        .destroy_key(ProviderID::Pkcs11, key_name)
        .expect("Failed to call destroy key");

    let req = get_req_from_bytes(client.get_mock_write());
    assert_eq!(
        String::from_utf8(req.auth.bytes().to_owned()).unwrap(),
        String::from(DEFAULT_APP_NAME)
    );
}
