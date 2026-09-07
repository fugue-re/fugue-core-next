use proc_macro::TokenStream;
use syn::{DeriveInput, ItemImpl, parse_macro_input};

mod analysis;
mod extension;
mod storage;

#[proc_macro_derive(AnalysisData, attributes(analysis_data))]
pub fn derive_analysis_data(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match analysis::expand(input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// Derive macro for registering SegmentStorageProvider implementations.
///
/// This macro generates inventory registration for the provider type,
/// enabling dynamic instantiation without knowing concrete types at compile time.
///
/// # Attributes
///
/// - `tag = "custom-tag"` - Set a custom stable tag for persistence
/// - `persistent = true/false` - Enable/disable from_storage factory
/// - `concrete = Type<...>` - Register a concrete instantiation (for generic types)
///
/// # Examples
///
/// ## Non-generic type:
///
/// ```ignore
/// #[derive(SegmentStorageProvider)]
/// #[provider(tag = "in-memory")]
/// pub struct InMemorySegmentStorage { /* ... */ }
/// ```
///
/// ## Generic type with concrete instantiations:
///
/// ```ignore
/// #[derive(SegmentStorageProvider)]
/// #[provider(concrete = MemoryMappedSegmentStorage<{ PERSISTENT }>, tag = "memory-mapped-persistent")]
/// #[provider(concrete = MemoryMappedSegmentStorage<{ TRANSIENT }>, tag = "memory-mapped-transient", persistent = false)]
/// pub struct MemoryMappedSegmentStorage<const PERSISTENCE: StoragePersistence> { /* ... */ }
/// ```
#[proc_macro_derive(SegmentStorageProvider, attributes(provider))]
pub fn derive_segment_storage_provider(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match storage::expand(input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// Attribute macro for declaring an extension point registration ergonomically.
///
/// Applied to an `impl` block of an extension descriptor type, it passes each
/// associated `const` and `fn` to the descriptor constructor and emits the
/// `extension::submit!` registration automatically.
///
/// Constants and functions are passed to `new` in declaration order.
///
/// # Example
///
/// ```ignore
/// #[fugue_core::extension]
/// impl ArchProvider {
///     const NAME: &str = "x86-64";
///
///     fn supports(language: &'static Language) -> bool { /* ... */ }
///     fn create(language: &'static Language) -> Arch { X86_64::new(language) }
/// }
/// ```
#[proc_macro_attribute]
pub fn extension(_attribute: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemImpl);

    match extension::expand(item) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}
