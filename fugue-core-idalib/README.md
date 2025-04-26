# fugue-core-idalib

This crate provides a loader implementation for `fugue` based on IDA; it also
provides function recovery and builder analysis passes.

To use this crate, in downstream projects, add the following to your `Cargo.toml`:

```toml
[build-dependencies]
idalib-build = "0.5"
```

And supply the following environment variables for Linux/macOS:

```bash
```

Or the following for Windows:

```powershell
```

And finaly, ensure the build script contains the following:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);
    if !ida_path.exists() || !idalib_path.exists() {
        idalib_build::configure_idasdk_linkage();
    } else {
        idalib_build::configure_linkage()?;
    }
    Ok(())
}
```
