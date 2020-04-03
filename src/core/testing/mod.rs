// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
use super::ipc_client::{Connect, ReadWrite};
use super::CoreClient;
use crate::auth::AuthenticationData;
use crate::error::Result;
use mockstream::{FailingMockStream, SyncMockStream};
use std::ops::{Deref, DerefMut};

mod core_tests;

const DEFAULT_APP_NAME: &str = "default-test-app-name";

struct MockIpc(SyncMockStream);

impl Connect for MockIpc {
    fn connect(&self) -> Result<Box<dyn ReadWrite>> {
        Ok(Box::from(self.0.clone()))
    }
}

struct FailingMockIpc(FailingMockStream);

impl Connect for FailingMockIpc {
    fn connect(&self) -> Result<Box<dyn ReadWrite>> {
        Ok(Box::from(self.0.clone()))
    }
}

struct TestCoreClient {
    core_client: CoreClient,
    mock_stream: SyncMockStream,
}

impl TestCoreClient {
    pub fn set_mock_read(&mut self, bytes: &[u8]) {
        self.mock_stream.push_bytes_to_read(bytes);
    }

    pub fn get_mock_write(&mut self) -> Vec<u8> {
        self.mock_stream.pop_bytes_written()
    }
}

impl Deref for TestCoreClient {
    type Target = CoreClient;

    fn deref(&self) -> &Self::Target {
        &self.core_client
    }
}

impl DerefMut for TestCoreClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core_client
    }
}

impl Default for TestCoreClient {
    fn default() -> Self {
        let mut client = TestCoreClient {
            core_client: CoreClient::new(AuthenticationData::AppIdentity(String::from(
                DEFAULT_APP_NAME,
            ))),
            mock_stream: SyncMockStream::new(),
        };

        client
            .core_client
            .set_ipc_client(Box::from(MockIpc(client.mock_stream.clone())));
        client
    }
}
