// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Client app authentication data
use crate::error::{Error, Result};
use parsec_interface::requests::{request::RequestAuth, AuthType};
use std::convert::TryFrom;

/// Authentication data used in Parsec requests
#[derive(Clone, Debug)]
pub enum Authentication {
    /// Used in cases where no authentication is desired or required
    None,
    /// Data used for direct, identity-based authentication
    ///
    /// Warning: Systems using direct authentication require extra measures
    /// to be as secure as deployments with other authentication mechanisms.
    /// Please check the
    /// [Parsec Threat Model](https://parallaxsecond.github.io/parsec-book/parsec_security/parsec_threat_model/threat_model.html)
    /// for more information.
    Direct(String),
    /// Used for authentication via Peer Credentials provided by Unix
    /// operating systems for Domain Socket connections.
    UnixPeerCredentials,
}

impl Authentication {
    /// Get the Parsec authentication type based on the data type
    pub fn auth_type(&self) -> AuthType {
        match self {
            Authentication::None => AuthType::NoAuth,
            Authentication::Direct(_) => AuthType::Direct,
            Authentication::UnixPeerCredentials => AuthType::UnixPeerCredentials,
        }
    }
}

impl TryFrom<&Authentication> for RequestAuth {
    type Error = Error;

    fn try_from(data: &Authentication) -> Result<Self> {
        match data {
            Authentication::None => Ok(RequestAuth::new(Vec::new())),
            Authentication::Direct(name) => Ok(RequestAuth::new(name.bytes().collect())),
            Authentication::UnixPeerCredentials => {
                let current_uid = users::get_current_uid();
                Ok(RequestAuth::new(current_uid.to_le_bytes().to_vec()))
            }
        }
    }
}

impl PartialEq for Authentication {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Authentication::None, Authentication::None) => true,
            (Authentication::UnixPeerCredentials, Authentication::UnixPeerCredentials) => true,
            (Authentication::Direct(app_name), Authentication::Direct(other_app_name)) => {
                app_name == other_app_name
            }
            _ => false,
        }
    }
}
