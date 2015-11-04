#!/bin/sh

set -v -e -x

cargo test -p range-map $*
cargo test -p breakpad-symbols $*
cargo test $*
