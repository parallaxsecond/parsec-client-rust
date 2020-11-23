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
    /// Authentication using JWT SVID tokens. The will fetch its JWT-SVID and pass it in the
    /// Authentication field. The socket endpoint is found through the SPIFFE_ENDPOINT_SOCKET
    /// environment variable.
    #[cfg(feature = "spiffe-auth")]
    JwtSvid,
}

impl Authentication {
    /// Get the Parsec authentication type based on the data type
    pub fn auth_type(&self) -> AuthType {
        match self {
            Authentication::None => AuthType::NoAuth,
            Authentication::Direct(_) => AuthType::Direct,
            Authentication::UnixPeerCredentials => AuthType::UnixPeerCredentials,
            #[cfg(feature = "spiffe-auth")]
            Authentication::JwtSvid => AuthType::JwtSvid,
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
            #[cfg(feature = "spiffe-auth")]
            Authentication::JwtSvid => {
                use crate::error::ClientErrorKind;
                use log::error;
                use spiffe::workload::jwt::JWTClient;
                use std::env;

                let client = JWTClient::new(
                    &env::var("SPIFFE_ENDPOINT_SOCKET").map_err(|e| {
                        error!(
                            "Cannot read the SPIFFE_ENDPOINT_SOCKET environment variable ({}).",
                            e
                        );
                        Error::Client(ClientErrorKind::NoAuthenticator)
                    })?,
                    None,
                    None,
                );
                let audience = String::from("parsec");

                let result = client.fetch(audience).map_err(|e| {
                    error!("Error while fetching the JWT-SVID ({}).", e);
                    Error::Client(ClientErrorKind::Spiffe(e))
                })?;
                Ok(RequestAuth::new(result.svid().as_bytes().into()))
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
            #[cfg(feature = "spiffe-auth")]
            (Authentication::JwtSvid, Authentication::JwtSvid) => true,
            _ => false,
        }
    }
}
