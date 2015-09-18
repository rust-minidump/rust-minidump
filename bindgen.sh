#!/bin/sh
dir=`dirname $0`
(echo "#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
"; $dir/../rust-bindgen/target/debug/bindgen -I $dir/../breakpad/src/src/ $dir/../breakpad/src/src/google_breakpad/common/minidump_format.h) | sed 's/#\[repr(C)\]/#\[repr(C, packed)\]/' > src/minidump_format.rs
