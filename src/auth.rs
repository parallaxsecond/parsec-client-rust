// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Client app authentication data
use parsec_interface::requests::{request::RequestAuth, AuthType};

/// Authentication data used in Parsec requests
#[derive(Clone, Debug)]
pub enum AuthenticationData {
    /// Used in cases where no authentication is desired or required
    None,
    /// Data used for direct, identity-based authentication
    AppIdentity(String),
}

impl AuthenticationData {
    /// Get the Parsec authentication type based on the data type
    pub fn auth_type(&self) -> AuthType {
        match self {
            AuthenticationData::None => AuthType::NoAuth,
            AuthenticationData::AppIdentity(_) => AuthType::Direct,
        }
    }
}

impl From<&AuthenticationData> for RequestAuth {
    fn from(data: &AuthenticationData) -> Self {
        match data {
            AuthenticationData::None => Default::default(),
            AuthenticationData::AppIdentity(name) => {
                RequestAuth::from_bytes(name.bytes().collect())
            }
        }
    }
}
