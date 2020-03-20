// Copyright (c) 2020, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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
