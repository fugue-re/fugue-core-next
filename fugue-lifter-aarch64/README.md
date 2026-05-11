# fugue-lifter-aarch64

Fugue lifters for AArch64.

## Build options

By default, both architectures are built and pre-transpiled lifters are used
for faster compile times. To generate lifters from source, use the following:

```sh
cargo build --features=compiled,aarch64-be,aarch64-le --no-default-features
```

## Development

The bundled pre-transpiled lifters can be regenerated with:

```sh
./generate-lifters.sh
```

To refresh the vendored language definitions from the latest stable upstream
release before regenerating lifters, run:

```sh
./generate-lifters.sh --sync
```

To regenerate only this crate's bundled outputs manually, use:

```sh
cargo run --bin lifter-packager \
    ./fugue-lifter-aarch64/data/processors \
    AARCH64:BE:64:v8A \
    ./fugue-lifter-aarch64/data/generated/aarch64_be.rs.gz

cargo run --bin lifter-packager \
    ./fugue-lifter-aarch64/data/processors \
    AARCH64:LE:64:v8A \
    ./fugue-lifter-aarch64/data/generated/aarch64_le.rs.gz
```
