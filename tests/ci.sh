#!/usr/bin/env bash

# Copyright 2020 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Continuous Integration test script, executed by GitHub Actions on x86 and
# Travis CI on Arm64.

set -euf -o pipefail

################
# Build client #
################
RUST_BACKTRACE=1 cargo build
RUST_BACKTRACE=1 cargo build --features testing
RUST_BACKTRACE=1 cargo build --features spiffe-auth
RUST_BACKTRACE=1 cargo build --no-default-features

#################
# Static checks #
#################
# On native target clippy or fmt might not be available.
if cargo fmt -h; then
	cargo fmt --all -- --check
fi
if cargo clippy -h; then
	cargo clippy --all-targets -- -D clippy::all -D clippy::cargo
fi

######################
# Start Mock Service #
######################
CURRENT_PATH=$(pwd)
cd parsec-mock-0.1.1
python parsec_mock/parsec_mock.py --parsec-socket $CURRENT_PATH/parsec_mock.sock &
while [[ ! -S $CURRENT_PATH/parsec_mock.sock ]]; do
	sleep 5
done
cd ..
export PARSEC_SERVICE_ENDPOINT="unix://$CURRENT_PATH/parsec_mock.sock"

#############
# Run tests #
#############
RUST_BACKTRACE=1 cargo test
