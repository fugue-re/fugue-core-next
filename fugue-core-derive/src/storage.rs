use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{Attribute, DeriveInput, Error, LitBool, LitStr, Result, Token, Type};

#[derive(Default)]
struct ProviderAttr {
    concrete: Option<Type>,
    tag: Option<String>,
    persistent: Option<bool>,
}

impl ProviderAttr {
    fn parse(attribute: &Attribute) -> Result<Self> {
        let mut result = Self::default();

        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("concrete") {
                meta.input.parse::<Token![=]>()?;
                result.concrete = Some(meta.input.parse::<Type>()?);
                Ok(())
            } else if meta.path.is_ident("tag") {
                meta.input.parse::<Token![=]>()?;
                let literal = meta.input.parse::<LitStr>()?;
                result.tag = Some(literal.value());
                Ok(())
            } else if meta.path.is_ident("persistent") {
                meta.input.parse::<Token![=]>()?;
                let literal = meta.input.parse::<LitBool>()?;
                result.persistent = Some(literal.value());
                Ok(())
            } else {
                Err(meta.error("unrecognised provider attribute"))
            }
        })?;

        Ok(result)
    }
}

pub(crate) fn expand(input: DeriveInput) -> Result<TokenStream> {
    let name = &input.ident;
    let attributes = input
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("provider"))
        .map(ProviderAttr::parse)
        .collect::<Result<Vec<_>>>()?;
    let (concrete, simple) = attributes
        .into_iter()
        .partition::<Vec<_>, _>(|attribute| attribute.concrete.is_some());

    if !concrete.is_empty() {
        if !simple.is_empty() {
            return Err(Error::new_spanned(
                &input.ident,
                "provider attributes cannot mix concrete and non-concrete registrations",
            ));
        }
        let mut registrations = Vec::new();

        for attribute in &concrete {
            let ty = attribute
                .concrete
                .as_ref()
                .expect("concrete provider attribute must contain a type");
            let Some(tag) = attribute.tag.as_deref() else {
                return Err(Error::new_spanned(
                    ty,
                    "concrete instantiation requires `tag = \"...\"`",
                ));
            };
            let persistent = attribute.persistent.unwrap_or(true);
            registrations.push(generate_registration(ty, tag, persistent));
        }

        return Ok(quote! {
            #(#registrations)*
        });
    }

    let mut tag = None;
    let mut persistent = None;
    for attribute in simple {
        if attribute.tag.is_some() {
            tag = attribute.tag;
        }
        if attribute.persistent.is_some() {
            persistent = attribute.persistent;
        }
    }

    let tag = tag.unwrap_or_else(|| name.to_string());
    Ok(generate_registration(
        name,
        &tag,
        persistent.unwrap_or(true),
    ))
}

fn generate_from_storage(ty: &impl ToTokens) -> TokenStream {
    quote! {
        Some(|path: &::std::path::Path, attributes: &mut ::fugue_core::types::AttributeMap| ->
            ::std::result::Result<::std::boxed::Box<dyn ::fugue_core::storage::SegmentStorageProvider>, ::fugue_core::storage::SegmentStorageError> {

            let provider = <#ty as ::fugue_core::storage::SegmentStorageProviderFromStorage>::from_storage(path, attributes)?;
            Ok(::std::boxed::Box::new(provider))
        })
    }
}

fn generate_registration(ty: &impl ToTokens, tag: &str, persistent: bool) -> TokenStream {
    let (from_storage, persistence) = if persistent {
        (
            generate_from_storage(ty),
            quote! { ::fugue_core::storage::PERSISTENT },
        )
    } else {
        (quote! { None }, quote! { ::fugue_core::storage::TRANSIENT })
    };

    quote! {
        ::inventory::submit! {
            ::fugue_core::storage::SegmentStorageProviderEntry::new_with::<#ty>(
                #tag,
                |id: ::fugue_core::storage::SegmentStorageProviderId, range: ::std::ops::RangeInclusive<::fugue_core::ir::Address>, attributes: &mut ::fugue_core::types::AttributeMap| ->
                    ::std::result::Result<::std::boxed::Box<dyn ::fugue_core::storage::SegmentStorageProvider>, ::fugue_core::storage::SegmentStorageError> {

                    let provider = <#ty as ::fugue_core::storage::SegmentStorageProviderFromSegmentRange>::from_segment_range(id, range, attributes)?;
                    Ok(::std::boxed::Box::new(provider))
                },
                #from_storage,
            )
        }

        impl ::fugue_core::storage::SegmentStorageProviderDescriptor for #ty {
            const STABLE_TAG: &'static str = #tag;
            const PERSISTENCE: ::fugue_core::storage::StoragePersistence = #persistence;

            fn stable_tag(&self) -> &'static str {
                Self::STABLE_TAG
            }

            fn persistence(&self) -> ::fugue_core::storage::StoragePersistence {
                Self::PERSISTENCE
            }
        }
    }
}
