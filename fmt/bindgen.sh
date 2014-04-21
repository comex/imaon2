#!/bin/bash
set -e
in=$1
out=$2
shift 2
(
    cat fmt/bind_defs.rs;
    externals/rust-bindgen/bindgen -allow-bitfields "$@" "$in" |
        tail -n +4 |
        sed 's/Struct_//g' |
        awk '/pub struct/ { print "#[deriving_swappable]" } {print} '
) > "$out"
