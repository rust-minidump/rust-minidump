#!/bin/sh

set -v -e -x

cargo test --verbose
cargo test -p range-map --verbose
cargo test -p breakpad-symbols --verbose
