// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Client app authentication data
use parsec_interface::requests::{request::RequestAuth, AuthType};
use parsec_interface::secrecy::{ExposeSecret, Secret};

/// Authentication data used in Parsec requests
#[derive(Clone, Debug)]
pub enum AuthenticationData {
    /// Used in cases where no authentication is desired or required
    None,
    /// Data used for direct, identity-based authentication
    ///
    /// The app name is wrapped in a [`Secret`](https://docs.rs/secrecy/*/secrecy/struct.Secret.html).
    /// The `Secret` struct can be imported from
    /// `parsec_client::core::secrecy::Secret`.
    AppIdentity(Secret<String>),
    /// Used for authentication via Peer Credentials provided by Unix
    /// operating systems for Domain Socket connections.
    UnixPeerCredentials,
}

impl AuthenticationData {
    /// Get the Parsec authentication type based on the data type
    pub fn auth_type(&self) -> AuthType {
        match self {
            AuthenticationData::None => AuthType::NoAuth,
            AuthenticationData::AppIdentity(_) => AuthType::Direct,
            AuthenticationData::UnixPeerCredentials => AuthType::UnixPeerCredentials,
        }
    }
}

impl From<&AuthenticationData> for RequestAuth {
    fn from(data: &AuthenticationData) -> Self {
        match data {
            AuthenticationData::None => RequestAuth::new(Vec::new()),
            AuthenticationData::AppIdentity(name) => {
                RequestAuth::new(name.expose_secret().bytes().collect())
            }
            AuthenticationData::UnixPeerCredentials => {
                let current_uid = users::get_current_uid();
                RequestAuth::new(current_uid.to_le_bytes().to_vec())
            }
        }
    }
}
