#![recursion_limit = "256"]
#![cfg_attr(test, deny(warnings))]
#![allow(unused)]

#[macro_use]
extern crate quote;
#[macro_use]
extern crate syn;

use syn::export::{Span, ToTokens, TokenStream, TokenStream2};
use syn::spanned::Spanned;
use syn::{
    Attribute, Data, DataStruct, DeriveInput, Error, Field, Fields, Ident, Index, Lit, Member,
    Meta, NestedMeta, Path, Result, Type, TypeSlice,
};

#[proc_macro_derive(StrictEncode, attributes(strict_error))]
pub fn derive_strict_encode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    strict_encode_inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

fn strict_encode_inner(input: DeriveInput) -> Result<TokenStream2> {
    match input.data {
        Data::Struct(ref data) => strict_encode_inner_struct(&input, data),
        Data::Enum(ref data) => Err(Error::new_spanned(
            &input,
            "Deriving StrictEncode is not supported in enums yet",
        )),
        //strict_encode_inner_enum(&input, &data),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            "Deriving StrictEncode is not supported in unions",
        )),
    }
}

fn strict_encode_inner_struct(input: &DeriveInput, data: &DataStruct) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let ident_name = &input.ident;

    let mut strict_error: Option<Ident> = None;
    let example = "#[strict_error(ErrorType)]";
    input.attrs.iter().try_for_each(|attr| -> Result<()> {
        if attr.path.is_ident("strict_error") {
            match attr.parse_meta() {
                Ok(meta) => {
                    match meta {
                        Meta::Path(path) => return Err(Error::new(attr.span(), format!("`strict_error` attribute must has form of `{}`", example))),
                        Meta::List(list) => {
                            match list.nested.len() {
                                0 => return Err(Error::new(attr.span(), format!("`strict_error` must be followed by a error type identifier, like `{}`", example))),
                                1 => match list.nested.first().expect("Stdlib collection object is broken") {
                                    NestedMeta::Meta(meta) => match meta {
                                        Meta::Path(path) =>  strict_error = path.get_ident().cloned(),
                                        _ => return Err(Error::new(attr.span(), format!("`strict_error` must contain only a single error type identifier, like `{}`", example))),
                                    },
                                    NestedMeta::Lit(lit) => return Err(Error::new(attr.span(), format!("`strict_error` must contain type identifier, not literal. Example: `{}`", example))),
                                },
                                _ => return Err(Error::new(attr.span(), format!("`strict_error` must contain only a single type identifier, like `{}`", example)))
                            }
                        },
                        Meta::NameValue(name_val) => {},
                    }
                }
                Err(e) => {
                    return Err(Error::new(
                        e.span(),
                        format!("{}. Try: `strict_encode(Error)`", e),
                    ))
                }
            }
        }
        Ok(())
    })?;

    let error_type_def = match strict_error {
        Some(ident) => quote! { type Error = #ident; },
        None => quote! {},
    };

    let recurse = match data.fields {
        Fields::Named(ref fields) => fields
            .named
            .iter()
            .map(|f| {
                let name = &f.ident;
                quote_spanned! { f.span() =>
                    len += self.#name.strict_encode(&mut e)?;
                }
            })
            .collect(),
        Fields::Unnamed(ref fields) => fields
            .unnamed
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let index = Index::from(i);
                quote_spanned! { f.span() =>
                    len += self.#index.strict_encode(&mut e)?;
                }
            })
            .collect(),
        Fields::Unit => {
            // Nothing to do here
            vec![]
        }
    };

    let inner = match recurse.len() {
        0 => quote! { Ok(0) },
        _ => quote! {
            let mut len = 0;
            #( #recurse )*
            Ok(len)
        },
    };

    Ok(quote! {
        #[allow(unused_qualifications)]
        impl #impl_generics lnpbp::strict_encoding::StrictEncode for #ident_name #ty_generics #where_clause {
            #error_type_def

            #[inline]
            fn strict_encode<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, Error> {
                #inner
            }
        }
    })
}
