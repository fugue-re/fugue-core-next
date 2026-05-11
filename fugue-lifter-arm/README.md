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
    ./fugue-lifter-arm/data/processors \
    ARM:BE:32:v8 \
    ./fugue-lifter-arm/data/generated/arm_be.rs.gz

cargo run --bin lifter-packager \
    ./fugue-lifter-arm/data/processors \
    ARM:LE:32:v8 \
    ./fugue-lifter-arm/data/generated/arm_le.rs.gz
```

Both endians compile from the same `.sinc` sources, so regenerate **both**
bundles whenever the source tree (or `data/patches/`) changes — otherwise the
outdated half will collide with the fresh half at compile time.

## Patches

`data/processors/` is vendored from upstream Ghidra and re-pulled by
`generate-lifters.sh --sync`, so direct edits there are clobbered on the next
sync. Local fixes (e.g. SLEIGH-level defects upstream hasn't fixed yet) live as
unified-diff overlays in `data/patches/`. The packager auto-detects the
sibling `patches/` directory next to `data/processors/` and applies every
`*.patch` / `*.diff` file in filename-sorted order to a scratch copy under
`OUT_DIR` before invoking the SLEIGH compiler.

When authoring or regenerating a patch:

- **Paths in the diff are relative to `data/processors/`**, not the repository
  root. Generate the patch from inside that directory:

  ```sh
  cd fugue-lifter-arm/data/processors
  git diff -- ARM/ARMinstructions.sinc > ../patches/0001-your-fix.patch
  ```

  A `git diff` taken from the repository root produces headers like
  `a/fugue-lifter-arm/data/processors/ARM/...`, which the patcher rejects
  because the prefix is not part of the source tree it sees.
- The patcher is **strict**: context lines must match exactly (no fuzz). If
  `generate-lifters.sh --sync` pulls upstream changes that shift lines around
  the patched region, the next build fails loudly and the patch must be
  re-diffed against the new upstream.
- Multiple patches apply in filename order, so use `0001-`, `0002-`, … prefixes
  to control sequencing when later patches depend on earlier ones.
- After editing `data/patches/`, regenerate both `arm_le.rs.gz` and
  `arm_be.rs.gz` (see above) so the bundled artefacts reflect the new patch
  state.
