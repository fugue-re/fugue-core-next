# fugue-lifter-arm

Fugue lifters for ARM.

## Build options

By default, both architectures are built and pre-transpiled lifters are used
for faster compile times. To generate lifters from source, use the following:

```sh
cargo build --features=compiled,arm-be,arm-le --no-default-features
```

## Development

The bundled pre-transpiled lifters can be regenerated with:

```sh
cargo run --bin lifter-packager \
    ./fugue-lifter-arm/data/processors \
    ARM:BE:32:v8 \
    ./fugue-lifter-arm/data/generated/arm_be.rs.gz

cargo run --bin lifter-packager \
    ./fugue-lifter-arm/data/processors \
    ARM:LE:32:v8 \
    ./fugue-lifter-arm/data/generated/arm_le.rs.gz
```
