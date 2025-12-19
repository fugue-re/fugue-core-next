#!/bin/sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

pushd $SCRIPT_DIR

# Generate lifters for AArch64
cargo run --bin lifter-packager \
    ./fugue-lifter-aarch64/data/processors \
    AARCH64:BE:64:v8A \
    ./fugue-lifter-aarch64/data/generated/aarch64_be.rs.gz

cargo run --bin lifter-packager \
    ./fugue-lifter-aarch64/data/processors \
    AARCH64:LE:64:v8A \
    ./fugue-lifter-aarch64/data/generated/aarch64_le.rs.gz

# Generate lifters for ARM
cargo run --bin lifter-packager \
    ./fugue-lifter-arm/data/processors \
    ARM:BE:32:v8 \
    ./fugue-lifter-arm/data/generated/arm_be.rs.gz

cargo run --bin lifter-packager \
    ./fugue-lifter-arm/data/processors \
    ARM:LE:32:v8 \
    ./fugue-lifter-arm/data/generated/arm_le.rs.gz

# Generate lifters for x86 and x86_64
cargo run --bin lifter-packager \
    ./fugue-lifter-x86/data/processors \
   x86:LE:32:default \
    ./fugue-lifter-x86/data/generated/x86.rs.gz

cargo run --bin lifter-packager \
    ./fugue-lifter-x86/data/processors \
   x86:LE:64:default \
    ./fugue-lifter-x86/data/generated/x86_64.rs.gz

popd
