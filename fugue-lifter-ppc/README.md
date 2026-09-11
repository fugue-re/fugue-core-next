# fugue-lifter-ppc

Fugue lifters for PowerPC.

## Build options

By default, six targets are built and pre-transpiled lifters are used for
faster compile times: 32-bit and 64-bit in both endians, plus the Power ISA 3.0
targets (`A2ALT`) in both endians. Each 64-bit target additionally bundles its
`-32addr` variant, which truncates the `ram` space to 32-bit addresses. To
generate lifters from source, use the following:

```sh
cargo build --no-default-features \
    --features=compiled,ppc-be,ppc-le,ppc64-be,ppc64-le,ppc64-a2alt-be,ppc64-a2alt-le
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
    --language-db ./fugue-lifter-ppc/data/processors \
    --language PowerPC:BE:32:default \
    --output ./fugue-lifter-ppc/data/generated/ppc_be.rs.gz

cargo run --bin lifter-packager -- build-static \
    --language-db ./fugue-lifter-ppc/data/processors \
    --language PowerPC:LE:32:default \
    --output ./fugue-lifter-ppc/data/generated/ppc_le.rs.gz

cargo run --bin lifter-packager -- build-static \
    --language-db ./fugue-lifter-ppc/data/processors \
    --language PowerPC:BE:64:default --variant 64-32addr \
    --output ./fugue-lifter-ppc/data/generated/ppc64_be.rs.gz

cargo run --bin lifter-packager -- build-static \
    --language-db ./fugue-lifter-ppc/data/processors \
    --language PowerPC:LE:64:default --variant 64-32addr \
    --output ./fugue-lifter-ppc/data/generated/ppc64_le.rs.gz
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
`*.patch`/`*.diff` file in filename-sorted order to a scratch copy under
`OUT_DIR` before invoking the SLEIGH compiler.

When authoring or regenerating a patch:

- **Paths in the diff are relative to `data/processors/`**, not the repository
  root. Generate the patch from inside that directory:

  ```sh
  cd fugue-lifter-ppc/data/processors
  git diff -- PowerPC/ppc_instructions.sinc > ../patches/0001-your-fix.patch
  ```

  A `git diff` taken from the repository root produces headers like
  `a/fugue-lifter-ppc/data/processors/PowerPC/...`, which the patcher rejects
  because the prefix is not part of the source tree it sees.
- The patcher is **strict**: context lines must match exactly (no fuzz). If
  `generate-lifters.sh --sync` pulls upstream changes that shift lines around
  the patched region, the next build fails loudly and the patch must be
  re-diffed against the new upstream.
- Multiple patches apply in filename order, so use `0001-`, `0002-`, … prefixes
  to control sequencing when later patches depend on earlier ones.
- After editing `data/patches/`, regenerate all four bundles (see above) so the
  bundled artefacts reflect the new patch state.
