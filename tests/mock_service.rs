// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use parsec_client::BasicClient;

#[test]
fn ping_noauth() {
    let client = BasicClient::new_naked().unwrap();

    // ping_noauth request
    assert_eq!(client.ping().expect("Ping failed"), (1, 0));
}
