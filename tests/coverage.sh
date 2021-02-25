#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -euf -o pipefail

cargo install cargo-tarpaulin

cargo tarpaulin --tests --out Xml --exclude-files="src/core/testing/*"

bash <(curl -s https://codecov.io/bash)
