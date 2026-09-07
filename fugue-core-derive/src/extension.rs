use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, ImplItem, ItemImpl, Result};

pub(crate) fn expand(item: ItemImpl) -> Result<TokenStream> {
    let self_ty = &item.self_ty;
    let mut free_fns = Vec::new();
    let mut constructor_values = Vec::new();

    for item in &item.items {
        match item {
            ImplItem::Const(constant) => {
                let value = &constant.expr;
                constructor_values.push(quote! { #value });
            }
            ImplItem::Fn(function) => {
                let mut function = function.clone();
                let mut attributes = Vec::with_capacity(function.attrs.len());
                for attribute in function.attrs.drain(..) {
                    if attribute.path().is_ident("provides") {
                        return Err(Error::new_spanned(
                            attribute,
                            "`#[provides]` is not supported by constructor-based extensions",
                        ));
                    }
                    attributes.push(attribute);
                }
                function.attrs = attributes;

                let name = &function.sig.ident;
                constructor_values.push(quote! { #name });
                free_fns.push(function);
            }
            other => {
                return Err(Error::new_spanned(
                    other,
                    "`#[extension]` only supports `const` and `fn` items",
                ));
            }
        }
    }

    Ok(quote! {
        const _: () = {
            #(#free_fns)*

            ::fugue_core::extension::submit! {
                #self_ty::new(#(#constructor_values),*)
            }
        };
    })
}
