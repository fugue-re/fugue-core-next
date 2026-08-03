# fugue-lifter-mips

Fugue lifters for MIPS.

## Build options

By default, all four targets (32/64-bit, big/little endian) are built and
pre-transpiled lifters are used for faster compile times. The 64-bit targets
additionally bundle the `64-32addr` variant, which truncates the `ram` space to
32-bit addresses. To generate lifters from source, use the following:

```sh
cargo build --features=compiled,mips-be,mips-le,mips64-be,mips64-le --no-default-features
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
cargo run --bin lifter-packager -- build-static \
    --language-db ./fugue-lifter-mips/data/processors \
    --language MIPS:BE:32:default \
    --output ./fugue-lifter-mips/data/generated/mips_be.rs.gz

cargo run --bin lifter-packager -- build-static \
    --language-db ./fugue-lifter-mips/data/processors \
    --language MIPS:LE:32:default \
    --output ./fugue-lifter-mips/data/generated/mips_le.rs.gz

cargo run --bin lifter-packager -- build-static \
    --language-db ./fugue-lifter-mips/data/processors \
    --language MIPS:BE:64:default --variant 64-32addr \
    --output ./fugue-lifter-mips/data/generated/mips64_be.rs.gz

cargo run --bin lifter-packager -- build-static \
    --language-db ./fugue-lifter-mips/data/processors \
    --language MIPS:LE:64:default --variant 64-32addr \
    --output ./fugue-lifter-mips/data/generated/mips64_le.rs.gz
```

All targets compile from the same `.sinc` sources, so regenerate **all four**
bundles whenever the source tree (or `data/patches/`) changes — otherwise the
outdated bundles will collide with the fresh ones at compile time.

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
  cd fugue-lifter-mips/data/processors
  git diff -- MIPS/mips32instructions.sinc > ../patches/0001-your-fix.patch
  ```

  A `git diff` taken from the repository root produces headers like
  `a/fugue-lifter-mips/data/processors/MIPS/...`, which the patcher rejects
  because the prefix is not part of the source tree it sees.
- The patcher is **strict**: context lines must match exactly (no fuzz). If
  `generate-lifters.sh --sync` pulls upstream changes that shift lines around
  the patched region, the next build fails loudly and the patch must be
  re-diffed against the new upstream.
- Multiple patches apply in filename order, so use `0001-`, `0002-`, … prefixes
  to control sequencing when later patches depend on earlier ones.
- After editing `data/patches/`, regenerate both `mips_le.rs.gz` and
  `mips_be.rs.gz` (see above) so the bundled artefacts reflect the new patch
  state.
