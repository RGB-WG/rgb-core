// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

#![recursion_limit = "256"]
#![cfg_attr(test, deny(warnings))]
#![allow(unused)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate quote;
#[macro_use]
extern crate syn;

use amplify::proc_macro;
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

#[proc_macro_derive(StrictDecode, attributes(strict_decode))]
pub fn derive_strict_decode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    strict_decode_inner(derive_input)
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

fn strict_decode_inner(input: DeriveInput) -> Result<TokenStream2> {
    match input.data {
        Data::Struct(ref data) => strict_decode_inner_struct(&input, data),
        Data::Enum(ref data) => Err(Error::new_spanned(
            &input,
            "Deriving StrictDecode is not supported in enums yet",
        )),
        //strict_encode_inner_enum(&input, &data),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            "Deriving StrictDecode is not supported in unions",
        )),
    }
}

fn strict_encode_inner_struct(input: &DeriveInput, data: &DataStruct) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let ident_name = &input.ident;

    let error_type_def = get_strict_error(input, data)?;

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
            fn strict_encode<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
                #inner
            }
        }
    })
}

fn strict_decode_inner_struct(input: &DeriveInput, data: &DataStruct) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let ident_name = &input.ident;

    let error_type_def = get_strict_error(input, data)?;

    let inner = match data.fields {
        Fields::Named(ref fields) => {
            let recurse: Vec<TokenStream2> = fields
                .named
                .iter()
                .map(|f| {
                    let name = &f.ident;
                    quote_spanned! { f.span() =>
                        #name: lnpbp::strict_encoding::StrictDecode::strict_decode(&mut d)?,
                    }
                })
                .collect();
            quote! {
                Self {
                    #( #recurse )*
                }
            }
        }
        Fields::Unnamed(ref fields) => {
            let recurse: Vec<TokenStream2> = fields
                .unnamed
                .iter()
                .map(|f| {
                    quote_spanned! { f.span() =>
                        lnpbp::strict_encoding::StrictDecode::strict_decode(&mut d)?,
                    }
                })
                .collect();
            quote! {
                Self (
                    #( #recurse )*
                )
            }
        }
        Fields::Unit => {
            // Nothing to do here
            quote! { Self() }
        }
    };

    Ok(quote! {
        #[allow(unused_qualifications)]
        impl #impl_generics lnpbp::strict_encoding::StrictDecode for #ident_name #ty_generics #where_clause {
            #error_type_def

            #[inline]
            fn strict_decode<D: ::std::io::Read>(mut d: D) -> Result<Self, Self::Error> {
                Ok(#inner)
            }
        }
    })
}

fn get_strict_error(input: &DeriveInput, data: &DataStruct) -> Result<TokenStream2> {
    macro_rules! return_err {
        ($attr:ident, $msg:tt) => {
            return Err(Error::new(
                $attr.span(),
                format!(
                    "Attribute macro canonical form `#[strict_error(ErrorType)]` violation: {}",
                    $msg
                ),
            ));
        };
    }

    let name = "strict_error";
    let example = "#[strict_error(ErrorType)]";
    let mut strict_error: Option<Ident> = None;

    let list = match proc_macro::attr_list(input, name, example)? {
        Some(x) => x,
        None => return Ok(quote! {}),
    };
    let strict_error = proc_macro::attr_nested_one_arg(list.into_iter(), name, example)?;

    Ok(match strict_error {
        Some(ident) => quote! { type Error = #ident; },
        None => quote! {},
    })
}
