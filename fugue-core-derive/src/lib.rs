use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{DeriveInput, LitBool, LitStr, Token, Type, parse_macro_input};

struct ProviderAttr {
    concrete: Option<Type>,
    tag: Option<String>,
    persistent: Option<bool>,
}

impl Default for ProviderAttr {
    fn default() -> Self {
        Self {
            concrete: None,
            tag: None,
            persistent: None,
        }
    }
}

impl ProviderAttr {
    fn parse(attr: &syn::Attribute) -> syn::Result<ProviderAttr> {
        let mut result = ProviderAttr::default();

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("concrete") {
                meta.input.parse::<Token![=]>()?;
                result.concrete = Some(meta.input.parse::<Type>()?);
                Ok(())
            } else if meta.path.is_ident("tag") {
                meta.input.parse::<Token![=]>()?;
                let lit: LitStr = meta.input.parse()?;
                result.tag = Some(lit.value());
                Ok(())
            } else if meta.path.is_ident("persistent") {
                meta.input.parse::<Token![=]>()?;
                let lit: LitBool = meta.input.parse()?;
                result.persistent = Some(lit.value());
                Ok(())
            } else {
                Err(meta.error("unrecognised provider attribute"))
            }
        })?;

        Ok(result)
    }
}

fn generate_from_storage_fn(ty: &impl quote::ToTokens) -> TokenStream2 {
    quote! {
        Some(|path: &::std::path::Path, attributes: &mut ::fugue_core::types::AttributeMap| ->
            ::std::result::Result<::std::boxed::Box<dyn ::fugue_core::storage::segments::SegmentStorageProvider>, ::fugue_core::storage::segments::SegmentStorageError> {

            let provider = <#ty as ::fugue_core::storage::segments::provider::SegmentStorageProviderFromStorage>::from_storage(path, attributes)?;
            Ok(::std::boxed::Box::new(provider))
        })
    }
}

fn generate_registration(ty: &impl quote::ToTokens, tag: &str, persistent: bool) -> TokenStream2 {
    let from_storage_fn = if persistent {
        generate_from_storage_fn(ty)
    } else {
        quote! { None }
    };

    quote! {
        ::inventory::submit! {
            ::fugue_core::storage::segments::provider::SegmentStorageProviderEntry::new_with::<#ty>(
                #tag,
                Some(|start: ::fugue_core::ir::Address, end: ::fugue_core::ir::Address, attributes: &mut ::fugue_core::types::AttributeMap| ->
                    ::std::result::Result<::std::boxed::Box<dyn ::fugue_core::storage::segments::SegmentStorageProvider>, ::fugue_core::storage::segments::SegmentStorageError> {

                    let provider = <#ty as ::fugue_core::storage::segments::provider::SegmentStorageProviderFromSegmentRange>::from_segment_range(start, end, attributes)?;
                    Ok(::std::boxed::Box::new(provider))
                }),
                #from_storage_fn,
            )
        }

        impl ::fugue_core::storage::segments::provider::StableSegmentStorageProvider for #ty {
            const STABLE_TAG: &'static str = #tag;

            fn stable_tag(&self) -> &'static str {
                Self::STABLE_TAG
            }
        }
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
    let name = &input.ident;

    let mut attrs = Vec::new();
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("provider")) {
        match ProviderAttr::parse(attr) {
            Ok(a) => attrs.push(a),
            Err(e) => return e.to_compile_error().into(),
        }
    }

    let (concrete_attrs, simple_attrs) = attrs
        .into_iter()
        .partition::<Vec<_>, _>(|a| a.concrete.is_some());

    if !concrete_attrs.is_empty() {
        let mut registrations = Vec::new();

        for attr in &concrete_attrs {
            if attr.tag.is_none() {
                let ty = attr.concrete.as_ref().unwrap();
                return syn::Error::new_spanned(
                    ty,
                    "concrete instantiation requires `tag = \"...\"`",
                )
                .to_compile_error()
                .into();
            }

            let ty = attr.concrete.as_ref().unwrap();
            let tag = attr.tag.as_deref().unwrap();
            let persistent = attr.persistent.unwrap_or(true);

            registrations.push(generate_registration(ty, tag, persistent));
        }

        let expanded = quote! {
            #(#registrations)*
        };

        return TokenStream::from(expanded);
    }

    let mut tag = None;
    let mut persistent = None;

    for attr in simple_attrs {
        if attr.tag.is_some() {
            tag = attr.tag;
        }
        if attr.persistent.is_some() {
            persistent = attr.persistent;
        }
    }

    let stable_tag = tag.unwrap_or_else(|| name.to_string());
    let persistent = persistent.unwrap_or(true);

    let expanded = generate_registration(name, &stable_tag, persistent);

    TokenStream::from(expanded)
}
