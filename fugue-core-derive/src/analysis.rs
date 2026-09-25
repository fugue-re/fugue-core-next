use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Attribute, Data, DataEnum, DataStruct, DeriveInput, Error, Fields, Ident, Member, Result, Type,
};

struct StructDelegation {
    member: Member,
    ty: Type,
}

struct EnumDelegation {
    fields: Fields,
    index: usize,
    name: Ident,
    ty: Type,
}

enum AnalysisDataDelegation {
    Enum(Vec<EnumDelegation>),
    Leaf,
    Struct(Box<StructDelegation>),
}

pub(crate) fn expand(input: DeriveInput) -> Result<TokenStream> {
    let delegated = delegates_analysis_data(&input.attrs)?;
    let delegation = match &input.data {
        Data::Enum(data) => enum_delegation(data, delegated)?,
        Data::Struct(data) => struct_delegation(data, delegated)?,
        Data::Union(data) => {
            return Err(Error::new_spanned(
                data.union_token,
                "`AnalysisData` cannot be derived for a union",
            ));
        }
    };
    let name = &input.ident;
    let (_, original_type_generics, _) = input.generics.split_for_impl();
    let mut generics = input.generics.clone();
    generics
        .make_where_clause()
        .predicates
        .push(syn::parse_quote!(#name #original_type_generics: ::std::marker::Send + 'static));

    let delegated_types = match &delegation {
        AnalysisDataDelegation::Enum(variants) => variants
            .iter()
            .map(|variant| &variant.ty)
            .collect::<Vec<_>>(),
        AnalysisDataDelegation::Leaf => Vec::new(),
        AnalysisDataDelegation::Struct(field) => vec![&field.ty],
    };
    for ty in delegated_types {
        generics
            .make_where_clause()
            .predicates
            .push(syn::parse_quote!(#ty: ::fugue_core::engine::AnalysisData));
    }

    let methods = analysis_data_methods(&delegation);
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics ::fugue_core::engine::AnalysisData for #name #type_generics
        #where_clause
        {
            #methods
        }
    })
}

fn delegates_analysis_data(attributes: &[Attribute]) -> Result<bool> {
    let mut delegated = false;

    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("analysis_data"))
    {
        let mut recognised = false;
        attribute.parse_nested_meta(|meta| {
            if !meta.path.is_ident("delegate") {
                return Err(meta.error("unrecognised analysis_data attribute"));
            }
            if !meta.input.is_empty() {
                return Err(meta.error("`delegate` does not accept a value"));
            }
            if delegated {
                return Err(meta.error("duplicate `delegate` attribute"));
            }
            delegated = true;
            recognised = true;
            Ok(())
        })?;
        if !recognised {
            return Err(Error::new_spanned(
                attribute,
                "expected `analysis_data(delegate)`",
            ));
        }
    }

    Ok(delegated)
}

fn struct_delegation(data: &DataStruct, delegated: bool) -> Result<AnalysisDataDelegation> {
    let selected = delegated_fields(&data.fields)?;

    if delegated {
        if !selected.is_empty() {
            return Err(Error::new_spanned(
                &data.fields,
                "delegation cannot be specified on both the struct and a field",
            ));
        }
        let Fields::Unnamed(fields) = &data.fields else {
            return Err(Error::new_spanned(
                &data.fields,
                "type-level delegation requires a single-field tuple struct",
            ));
        };
        if fields.unnamed.len() != 1 {
            return Err(Error::new_spanned(
                fields,
                "type-level delegation requires a single-field tuple struct",
            ));
        }
        let field = fields
            .unnamed
            .first()
            .expect("single-field tuple struct must contain one field");
        return Ok(AnalysisDataDelegation::Struct(Box::new(StructDelegation {
            member: Member::Unnamed(0.into()),
            ty: field.ty.clone(),
        })));
    }

    match selected.as_slice() {
        [] => Ok(AnalysisDataDelegation::Leaf),
        [(index, ty)] => {
            let member = data
                .fields
                .iter()
                .nth(*index)
                .and_then(|field| field.ident.clone())
                .map(Member::Named)
                .unwrap_or_else(|| Member::Unnamed((*index).into()));
            Ok(AnalysisDataDelegation::Struct(Box::new(StructDelegation {
                member,
                ty: ty.clone(),
            })))
        }
        _ => Err(Error::new_spanned(
            &data.fields,
            "a delegating struct must select exactly one field",
        )),
    }
}

fn enum_delegation(data: &DataEnum, delegated: bool) -> Result<AnalysisDataDelegation> {
    let mut variants = Vec::new();
    let mut any_selected = false;

    for variant in &data.variants {
        if let Some(attribute) = variant
            .attrs
            .iter()
            .find(|attribute| attribute.path().is_ident("analysis_data"))
        {
            return Err(Error::new_spanned(
                attribute,
                "`analysis_data` is not supported on an enum variant",
            ));
        }
        let selected = delegated_fields(&variant.fields)?;
        any_selected |= !selected.is_empty();
        let (index, ty) = if delegated {
            if !selected.is_empty() {
                return Err(Error::new_spanned(
                    &variant.fields,
                    "delegation cannot be specified on both the enum and a variant field",
                ));
            }
            if variant.fields.len() != 1 {
                return Err(Error::new_spanned(
                    &variant.fields,
                    "type-level delegation requires exactly one field in every variant",
                ));
            }
            let field = variant
                .fields
                .iter()
                .next()
                .expect("single-field enum variant must contain one field");
            (0, field.ty.clone())
        } else if let [(index, ty)] = selected.as_slice() {
            (*index, ty.clone())
        } else if selected.is_empty() {
            variants.push(None);
            continue;
        } else {
            return Err(Error::new_spanned(
                &variant.fields,
                "a delegating enum variant must select exactly one field",
            ));
        };
        variants.push(Some(EnumDelegation {
            fields: variant.fields.clone(),
            index,
            name: variant.ident.clone(),
            ty,
        }));
    }

    if !delegated && !any_selected {
        return Ok(AnalysisDataDelegation::Leaf);
    }
    if variants.iter().any(Option::is_none) {
        return Err(Error::new_spanned(
            data.enum_token,
            "every variant of a delegating enum must select one field",
        ));
    }

    Ok(AnalysisDataDelegation::Enum(
        variants.into_iter().flatten().collect(),
    ))
}

fn delegated_fields(fields: &Fields) -> Result<Vec<(usize, Type)>> {
    let mut selected = Vec::new();

    for (index, field) in fields.iter().enumerate() {
        if delegates_analysis_data(&field.attrs)? {
            selected.push((index, field.ty.clone()));
        }
    }

    Ok(selected)
}

fn analysis_data_methods(delegation: &AnalysisDataDelegation) -> TokenStream {
    match delegation {
        AnalysisDataDelegation::Enum(variants) => {
            let immutable = variants.iter().map(enum_delegation_arm);
            let mutable = variants.iter().map(enum_delegation_arm);
            quote! {
                fn delegated(&self) -> ::std::option::Option<&dyn ::fugue_core::engine::AnalysisData> {
                    match self {
                        #(#immutable),*
                    }
                }

                fn delegated_mut(&mut self) -> ::std::option::Option<&mut dyn ::fugue_core::engine::AnalysisData> {
                    match self {
                        #(#mutable),*
                    }
                }
            }
        }
        AnalysisDataDelegation::Leaf => TokenStream::new(),
        AnalysisDataDelegation::Struct(field) => {
            let member = &field.member;
            quote! {
                fn delegated(&self) -> ::std::option::Option<&dyn ::fugue_core::engine::AnalysisData> {
                    ::std::option::Option::Some(&self.#member)
                }

                fn delegated_mut(&mut self) -> ::std::option::Option<&mut dyn ::fugue_core::engine::AnalysisData> {
                    ::std::option::Option::Some(&mut self.#member)
                }
            }
        }
    }
}

fn enum_delegation_arm(variant: &EnumDelegation) -> TokenStream {
    let name = &variant.name;

    match &variant.fields {
        Fields::Named(fields) => {
            let field = fields
                .named
                .iter()
                .nth(variant.index)
                .and_then(|field| field.ident.as_ref())
                .expect("named delegated field must have a name");
            quote! { Self::#name { #field: delegated, .. } => ::std::option::Option::Some(delegated) }
        }
        Fields::Unnamed(fields) => {
            let patterns = fields.unnamed.iter().enumerate().map(|(index, _)| {
                if index == variant.index {
                    quote! { delegated }
                } else {
                    quote! { _ }
                }
            });
            quote! { Self::#name(#(#patterns),*) => ::std::option::Option::Some(delegated) }
        }
        Fields::Unit => unreachable!("delegating enum variant must contain a field"),
    }
}
