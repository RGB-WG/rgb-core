// LNP/BP Derive Library implementing LNPBP specifications & standards
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

use proc_macro2::TokenStream as TokenStream2;
use syn::spanned::Spanned;
use syn::{Data, DataStruct, DeriveInput, Error, Fields, Index, Result};

use crate::util::get_lnpbp_crate;

pub(crate) fn encode_inner(input: DeriveInput) -> Result<TokenStream2> {
    match input.data {
        Data::Struct(ref data) => encode_inner_struct(&input, data),
        Data::Enum(_) => Err(Error::new_spanned(
            &input,
            "Deriving LightningEncode is not supported in enums",
        )),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            "Deriving LightningEncode is not supported in unions",
        )),
    }
}

pub(crate) fn decode_inner(input: DeriveInput) -> Result<TokenStream2> {
    match input.data {
        Data::Struct(ref data) => decode_inner_struct(&input, data),
        Data::Enum(_) => Err(Error::new_spanned(
            &input,
            "Deriving LightningDecode is not supported in enums",
        )),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            "Deriving LightningDecode is not supported in unions",
        )),
    }
}

fn encode_inner_struct(
    input: &DeriveInput,
    data: &DataStruct,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let import = get_lnpbp_crate(input);

    let recurse = match data.fields {
        Fields::Named(ref fields) => fields
            .named
            .iter()
            .map(|f| {
                let name = &f.ident;
                quote_spanned! { f.span() =>
                    len += self.#name.lightning_encode(&mut e)?;
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
                    len += self.#index.lightning_encode(&mut e)?;
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
        impl #impl_generics #import::lightning_encoding::LightningEncode for #ident_name #ty_generics #where_clause {
            #[inline]
            fn lightning_encode<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, ::std::io::Error> {
                use #import::lightning_encoding::LightningEncode;

                #inner
            }
        }
    })
}

fn decode_inner_struct(
    input: &DeriveInput,
    data: &DataStruct,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let import = get_lnpbp_crate(input);

    let inner = match data.fields {
        Fields::Named(ref fields) => {
            let recurse: Vec<TokenStream2> = fields
                .named
                .iter()
                .map(|f| {
                    let name = &f.ident;
                    quote_spanned! { f.span() =>
                        #name: #import::lightning_encoding::LightningDecode::lightning_decode(&mut d)?,
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
                        #import::lightning_encoding::LightningDecode::lightning_decode(&mut d)?,
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
        impl #impl_generics #import::lightning_encoding::LightningDecode for #ident_name #ty_generics #where_clause {
            #[inline]
            fn lightning_decode<D: ::std::io::Read>(mut d: D) -> Result<Self, #import::lightning_encoding::Error> {
                use #import::lightning_encoding::LightningDecode;

                Ok(#inner)
            }
        }
    })
}
