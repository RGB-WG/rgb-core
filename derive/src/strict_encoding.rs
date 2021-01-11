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
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Error, Fields, Ident, Index,
    Result,
};

use crate::util::get_lnpbp_crate;

pub(crate) fn encode_inner(input: DeriveInput) -> Result<TokenStream2> {
    match input.data {
        Data::Struct(ref data) => encode_inner_struct(&input, data),
        Data::Enum(ref data) => encode_inner_enum(&input, data),
        //strict_encode_inner_enum(&input, &data),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            "Deriving StrictEncode is not supported in unions",
        )),
    }
}

pub(crate) fn decode_inner(input: DeriveInput) -> Result<TokenStream2> {
    match input.data {
        Data::Struct(ref data) => decode_inner_struct(&input, data),
        Data::Enum(ref data) => decode_inner_enum(&input, data),
        //strict_encode_inner_enum(&input, &data),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            "Deriving StrictDecode is not supported in unions",
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
        impl #impl_generics #import::strict_encoding::StrictEncode for #ident_name #ty_generics #where_clause {
            #[inline]
            fn strict_encode<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, #import::strict_encoding::Error> {
                use #import::strict_encoding::StrictEncode;

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
                        #name: #import::strict_encoding::StrictDecode::strict_decode(&mut d)?,
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
                        #import::strict_encoding::StrictDecode::strict_decode(&mut d)?,
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
        impl #impl_generics #import::strict_encoding::StrictDecode for #ident_name #ty_generics #where_clause {
            #[inline]
            fn strict_decode<D: ::std::io::Read>(mut d: D) -> Result<Self, #import::strict_encoding::Error> {
                use #import::strict_encoding::StrictDecode;

                Ok(#inner)
            }
        }
    })
}

fn encode_inner_enum(
    input: &DeriveInput,
    data: &DataEnum,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let import = get_lnpbp_crate(input);

    let mut inner: Vec<TokenStream2> = none!();
    for (idx, variant) in data.variants.iter().enumerate() {
        let idx = idx as u8;
        let code = match variant.fields {
            Fields::Named(ref fields) => {
                let ident = &variant.ident;
                let f = fields
                    .named
                    .iter()
                    .map(|f| {
                        f.ident.as_ref().expect("named fields are always named")
                    })
                    .collect::<Vec<_>>();
                quote_spanned! { fields.span() =>
                    Self::#ident { #( #f ),* } => {
                        len += #idx.strict_encode(&mut e)?;
                        #( len += #f.strict_encode(&mut e)?; )*
                    }
                }
            }
            Fields::Unnamed(ref fields) => {
                let ident = &variant.ident;
                let f = fields
                    .unnamed
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        Ident::new(&format!("_{}", i), variant.span())
                    })
                    .collect::<Vec<_>>();
                quote_spanned! { fields.span() =>
                    Self::#ident ( #( #f ),* ) => {
                        len += #idx.strict_encode(&mut e)?;
                        #( len += #f.strict_encode(&mut e)?; )*
                    }
                }
            }
            Fields::Unit => {
                let ident = &variant.ident;
                quote_spanned! { variant.span() =>
                    Self::#ident => {
                        len += #idx.strict_encode(&mut e)?;
                    }
                }
            }
        };
        inner.push(code);
    }

    let inner = match inner.len() {
        0 => quote! { Ok(0) },
        _ => quote! {
            let mut len = 0;
            match self {
                #( #inner )*
            }
            Ok(len)
        },
    };

    Ok(quote! {
        #[allow(unused_qualifications)]
        impl #impl_generics #import::strict_encoding::StrictEncode for #ident_name #ty_generics #where_clause {
            #[inline]
            fn strict_encode<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, #import::strict_encoding::Error> {
                use #import::strict_encoding::StrictEncode;

                #inner
            }
        }
    })
}

fn decode_inner_enum(
    input: &DeriveInput,
    data: &DataEnum,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let import = get_lnpbp_crate(input);

    let mut inner: Vec<TokenStream2> = none!();
    for (idx, variant) in data.variants.iter().enumerate() {
        let idx = idx as u8;
        let code = match variant.fields {
            Fields::Named(ref fields) => {
                let ident = &variant.ident;
                let f = fields
                    .named
                    .iter()
                    .map(|f| {
                        f.ident.as_ref().expect("named fields are always named")
                    })
                    .collect::<Vec<_>>();
                quote_spanned! { fields.span() =>
                    #idx => {
                        Self::#ident {
                            #( #f: StrictDecode::strict_decode(&mut d)?, )*
                        }
                    }
                }
            }
            Fields::Unnamed(ref fields) => {
                let ident = &variant.ident;
                let f = fields
                    .unnamed
                    .iter()
                    .enumerate()
                    .map(|(i, _)| Index::from(i))
                    .collect::<Vec<_>>();
                quote_spanned! { fields.span() =>
                    #idx => {
                        Self::#ident {
                            #( #f: StrictDecode::strict_decode(&mut d)?, )*
                        }
                    }
                }
            }
            Fields::Unit => {
                let ident = &variant.ident;
                quote_spanned! { variant.span() =>
                    #idx => {
                        Self::#ident
                    }
                }
            }
        };
        inner.push(code);
    }

    let inner = match inner.len() {
        0 => quote! { Ok(0) },
        _ => quote! {
            match u8::strict_decode(&mut d)? {
                #( #inner )*
                other => Err(#import::strict_encoding::Error::EnumValueNotKnown(stringify!(#ident_name).to_owned(), other))?
            }
        },
    };

    Ok(quote! {
        #[allow(unused_qualifications)]
        impl #impl_generics #import::strict_encoding::StrictDecode for #ident_name #ty_generics #where_clause {
            #[inline]
            fn strict_decode<D: ::std::io::Read>(mut d: D) -> Result<Self, #import::strict_encoding::Error> {
                use #import::strict_encoding::StrictDecode;

                Ok(#inner)
            }
        }
    })
}
