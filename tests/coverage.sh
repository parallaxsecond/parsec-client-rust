#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -euf -o pipefail

cargo install cargo-tarpaulin

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

######################
# Run tests          #
######################
cargo tarpaulin --tests --out Xml --exclude-files="src/core/testing/*"

bash <(curl -s https://codecov.io/bash)
