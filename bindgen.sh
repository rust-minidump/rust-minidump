#!/bin/sh
dir=`dirname $0`
$dir/../rust-bindgen/target/debug/bindgen -I $dir/../google-breakpad/src/ $dir/../google-breakpad/src/google_breakpad/common/minidump_format.h > src/minidump_format.rs
