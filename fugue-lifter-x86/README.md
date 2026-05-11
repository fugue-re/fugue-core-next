# fugue-lifter-x86

Fugue lifters for x86 and x86-64.

## Build options

By default, both architectures are built and pre-transpiled lifters are used
for faster compile times. To generate lifters from source, use the following:

```sh
cargo build --features=compiled,x86,x86-64 --no-default-features
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
    ./fugue-lifter-x86/data/processors \
    x86:LE:32:default \
    ./fugue-lifter-x86/data/generated/x86.rs.gz

cargo run --bin lifter-packager \
    ./fugue-lifter-x86/data/processors \
    x86:LE:64:default \
    ./fugue-lifter-x86/data/generated/x86_64.rs.gz
```
