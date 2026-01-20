use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, LitStr, Token};

/// Derive macro for registering SegmentStorageProvider implementations.
///
/// This macro generates inventory registration for the provider type,
/// enabling dynamic instantiation without knowing concrete types at compile time.
///
/// # Attributes
///
/// - `#[provider(tag = "custom-tag")]` - Set a custom stable tag for persistence
/// - `#[provider(from_storage)]` - Enable from_storage factory (requires SegmentStorageProviderFromStorage impl)
///
/// # Example
///
/// ```ignore
/// #[derive(SegmentStorageProvider)]
/// #[provider(tag = "in-memory")]
/// pub struct InMemorySegmentStorage { /* ... */ }
/// ```
#[proc_macro_derive(SegmentStorageProvider, attributes(provider))]
pub fn derive_segment_storage_provider(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let mut custom_tag: Option<LitStr> = None;
    let mut has_from_storage = false;

    // Parse attributes
    for attr in &input.attrs {
        if attr.path().is_ident("provider") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("tag") {
                    meta.input.parse::<Token![=]>()?;
                    custom_tag = Some(meta.input.parse::<LitStr>()?);
                    Ok(())
                } else if meta.path.is_ident("from_storage") {
                    has_from_storage = true;
                    Ok(())
                } else {
                    Err(meta.error("unrecognised provider attribute"))
                }
            });
        }
    }

    // Generate stable tag: use custom or default to module path + type name
    let stable_tag = custom_tag
        .map(|lit| lit.value())
        .unwrap_or_else(|| name.to_string());

    // Generate from_storage factory if enabled
    let from_storage_fn = if has_from_storage {
        quote! {
            Some(|path: &::std::path::Path, attributes: &mut ::fugue_core::types::AttributeMap| -> ::std::result::Result<::std::boxed::Box<dyn ::fugue_core::storage::segments::SegmentStorageProvider>, ::fugue_core::storage::segments::SegmentStorageError> {
                let provider = <#name as ::fugue_core::storage::segments::registry::SegmentStorageProviderFromStorage>::from_storage(path, attributes)?;
                Ok(::std::boxed::Box::new(provider))
            })
        }
    } else {
        quote! { None }
    };

    let expanded = quote! {
        ::inventory::submit! {
            ::fugue_core::storage::segments::registry::ProviderEntry {
                type_id: ::std::any::TypeId::of::<#name>(),
                stable_tag: #stable_tag,
                from_segment_range: Some(|start: ::fugue_core::ir::Address, end: ::fugue_core::ir::Address, attributes: &mut ::fugue_core::types::AttributeMap| -> ::std::result::Result<::std::boxed::Box<dyn ::fugue_core::storage::segments::SegmentStorageProvider>, ::fugue_core::storage::segments::SegmentStorageError> {
                    let provider = <#name as ::fugue_core::storage::segments::registry::SegmentStorageProviderFromSegmentRange>::from_segment_range(start, end, attributes)?;
                    Ok(::std::boxed::Box::new(provider))
                }),
                from_storage: #from_storage_fn,
            }
        }
    };

    TokenStream::from(expanded)
}
