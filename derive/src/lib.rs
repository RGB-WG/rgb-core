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

use core::convert::TryFrom;
use syn::export::{Span, ToTokens, TokenStream, TokenStream2};
use syn::spanned::Spanned;
use syn::{
    Attribute, Data, DataEnum, DataStruct, DeriveInput, Error, Field, Fields,
    Ident, Index, Lit, Member, Meta, MetaNameValue, NestedMeta, Path, Result,
    Type, TypeSlice, Variant,
};

macro_rules! proc_macro_err {
    ($attr:ident, $msg:tt, $example:tt) => {
        Err(Error::new(
            $attr.span(),
            format!(
                "Attribute macro canonical form `{}` violation: {}",
                $example, $msg
            ),
        ));
    };
}

fn attr_named_value(
    input: &DeriveInput,
    ident: &str,
    example: &str,
) -> Result<Option<Lit>> {
    for attr in &input.attrs {
        if attr.path.is_ident(ident) {
            match attr.parse_meta() {
                Ok(meta) => match meta {
                    Meta::Path(_) => {
                        return proc_macro_err!(
                            attr,
                            "unexpected path argument",
                            example
                        )
                    }
                    Meta::List(_) => return proc_macro_err!(
                        attr,
                        "must have form `name=\"value\"`, not `name(value)`",
                        example
                    ),
                    Meta::NameValue(name_val) => return Ok(Some(name_val.lit)),
                },
                Err(_) => {
                    return proc_macro_err!(attr, "wrong format", example)
                }
            }
        }
    }

    Ok(None)
}

fn attr_list<'a>(
    attrs: impl IntoIterator<Item = &'a Attribute>,
    ident: &str,
    example: &str,
) -> Result<Option<Vec<NestedMeta>>> {
    for attr in attrs {
        if attr.path.is_ident(ident) {
            match attr.parse_meta() {
                Ok(meta) => match meta {
                    Meta::Path(_) => {
                        return proc_macro_err!(
                            attr,
                            "unexpected path argument",
                            example
                        )
                    }
                    Meta::List(list) => {
                        return Ok(Some(list.nested.into_iter().collect()))
                    }
                    Meta::NameValue(_) => {
                        return proc_macro_err!(
                            attr,
                            "unexpected `name=\"value\"` argument",
                            example
                        )
                    }
                },
                Err(_) => {
                    return proc_macro_err!(attr, "wrong format", example)
                }
            }
        }
    }

    Ok(None)
}

fn attr_nested_one_arg(
    mut list: impl ExactSizeIterator<Item = NestedMeta>,
    attr_name: &str,
    example: &str,
) -> Result<Option<Path>> {
    match list.len() {
        0 => proc_macro_err!(
            attr_name,
            "unexpected absence of argument",
            example
        ),
        1 => match list.next().expect("Core library iterator is broken") {
            NestedMeta::Meta(meta) => match meta {
                Meta::Path(path) => Ok(Some(path)),
                _ => proc_macro_err!(
                    attr_name,
                    "unexpected attribute type",
                    example
                ),
            },
            NestedMeta::Lit(_) => proc_macro_err!(
                attr_name,
                "unexpected literal for type identifier is met",
                example
            ),
        },
        _ => proc_macro_err!(
            attr_name,
            "unexpected multiple type identifiers",
            example
        ),
    }
}

fn attr_nested_one_named_value(
    mut list: impl ExactSizeIterator<Item = NestedMeta>,
    attr_name: &str,
    example: &str,
) -> Result<MetaNameValue> {
    match list.len() {
        0 => proc_macro_err!(
            attr_name,
            "unexpected absence of argument",
            example
        ),
        1 => match list.next().expect("Core library iterator is broken") {
            NestedMeta::Meta(meta) => match meta {
                Meta::NameValue(path) => Ok(path),
                _ => proc_macro_err!(
                    attr_name,
                    "unexpected attribute type",
                    example
                ),
            },
            NestedMeta::Lit(_) => proc_macro_err!(
                attr_name,
                "unexpected literal for type identifier is met",
                example
            ),
        },
        _ => proc_macro_err!(
            attr_name,
            "unexpected multiple type identifiers",
            example
        ),
    }
}

// LNP API Derive
// ==============

#[proc_macro_derive(LnpApi, attributes(lnp_api, lnpbp_crate))]
pub fn derive_lnp_api(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    lnp_api_inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

enum EncodingSrategy {
    Strict,
    Bitcoin,
    Lightning,
}

impl EncodingSrategy {
    pub fn encode_fn(&self, span: Span, import: &TokenStream2) -> TokenStream2 {
        match self {
            Self::Strict => {
                quote_spanned!(span => #import::strict_encoding::strict_encode)
            }
            Self::Bitcoin => {
                quote_spanned!(span => #import::bitcoin::consensus::encode::consensus_encode)
            }
            Self::Lightning => unimplemented!(),
        }
    }

    pub fn decode_fn(&self, span: Span, import: &TokenStream2) -> TokenStream2 {
        match self {
            Self::Strict => quote_spanned!(span => strict_decode),
            Self::Bitcoin => quote_spanned!(span => consensus_decode),
            Self::Lightning => unimplemented!(),
        }
    }

    pub fn encode_use(&self, import: &TokenStream2) -> TokenStream2 {
        match self {
            Self::Strict => quote!(
                use #import::strict_encoding::strict_encode;
            ),
            Self::Bitcoin => quote!(
                use #import::bitcoin::consensus::encode::{
                    consensus_encode, Encode,
                };
            ),
            Self::Lightning => unimplemented!(),
        }
    }

    pub fn decode_use(&self, import: &TokenStream2) -> TokenStream2 {
        match self {
            Self::Strict => quote!(
                use #import::strict_encoding::StrictDecode;
            ),
            Self::Bitcoin => quote!(
                use #import::bitcoin::consensus::encode::Decode;
            ),
            Self::Lightning => unimplemented!(),
        }
    }
}

impl TryFrom<Lit> for EncodingSrategy {
    type Error = Error;

    fn try_from(value: Lit) -> Result<Self> {
        let err = Error::new(
            value.span(),
            "Wrong encoding strategy for LNP API; allowed strategies: strict, bitcoin, lightning",
        );
        Ok(match value {
            Lit::Str(s) => match s.value().to_lowercase().as_ref() {
                "strict" => EncodingSrategy::Strict,
                "bitcoin" => EncodingSrategy::Bitcoin,
                "lightning" => EncodingSrategy::Lightning,
                _ => Err(err)?,
            },
            _ => Err(err)?,
        })
    }
}

fn lnp_api_inner(input: DeriveInput) -> Result<TokenStream2> {
    match input.data {
        Data::Struct(ref data) => Err(Error::new_spanned(
            &input,
            "Deriving LnpApi can be done only with enums, not with structs",
        )),
        Data::Enum(ref data) => lnp_api_inner_enum(&input, data),
        //strict_encode_inner_enum(&input, &data),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            "Deriving LnpApi can be done only with enums, not with unions",
        )),
    }
}

fn lnp_api_inner_enum(
    input: &DeriveInput,
    data: &DataEnum,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let name = "lnp_api";
    let example = "#[lnp_api(encoding=\"strict|bitcoin|lightning\")]";
    let global_params = match attr_list(&input.attrs, name, example)? {
        Some(x) => x,
        None => vec![],
    };
    let import = get_lnpbp_crate(input)?;
    let global_encoding = EncodingSrategy::try_from(
        attr_nested_one_named_value(
            global_params.into_iter(),
            "encoding",
            example,
        )?
        .lit,
    )?;

    let example = "#[lnp_api(type=1000)]";
    let mut msg_const = vec![];
    let mut unmarshaller = vec![];
    let mut unmarshall_fn = vec![];
    let mut from_type = vec![];
    let mut get_type = vec![];
    let mut get_payload = vec![];
    for v in &data.variants {
        let meta =
            attr_list(&v.attrs, "lnp_api", example)?.ok_or(Error::new(
                v.span(),
                format!(
                "Attribute macro canonical form `{}` violation: {}",
                example,
                "`lnp_api` attribute is required for each message enum case",
            ),
            ))?;

        let type_lit: Lit =
            attr_nested_one_named_value(meta.into_iter(), "type", example)?.lit;
        let type_id: u16 = match type_lit {
            Lit::Int(i) => i.base10_parse().or_else(|_| {
                proc_macro_err!(i, "`type` must be an integer", example)
            })?,
            _ => {
                proc_macro_err!(type_lit, "`type` must be an integer", example)?
            }
        };
        let type_name = &v.ident;
        let type_snake = Ident::new(
            &format!("parse_{}", type_name.to_string().to_lowercase()),
            type_name.span(),
        );
        let type_const = Ident::new(
            &format!("MSG_TYPE_{}", type_name.to_string().to_uppercase()),
            type_name.span(),
        );

        msg_const.push(quote_spanned! { v.span() =>
            const #type_const: u16 = #type_id;
        });

        unmarshaller.push(quote_spanned! { v.span() =>
            map.insert(Self::#type_const, Self::#type_snake as #import::lnp::UnmarshallFn<_>);
        });

        let unmarshall_empty = quote_spanned! { v.span() =>
            fn #type_snake(_: &mut dyn ::std::io::Read) -> Result<::std::sync::Arc<dyn ::core::any::Any>, #import::lnp::presentation::Error> {
                struct NoData;
                Ok(::std::sync::Arc::new(NoData))
            }
        };

        match &v.fields {
            Fields::Named(_) => {
                return proc_macro_err!(
                v,
                "LNP API does not support requests represented by named enums",
                example
            )
            }
            Fields::Unnamed(args) => {
                let fields = &args.unnamed;
                if fields.len() > 1 {
                    return proc_macro_err!(
                        v,
                        "each LNP API message enum variant must contain not more than a single argument",
                        example
                    );
                }
                if let Some(f) = fields.first() {
                    let payload = &f.ty;
                    let payload_fisheye: TokenStream2 = syn::parse_str(
                        &quote!(#payload).to_string().replacen("<", "::<", 1),
                    )
                    .expect("Internal error");
                    let encode_fn =
                        global_encoding.encode_fn(f.span(), &import);
                    let decode_fn =
                        global_encoding.decode_fn(f.span(), &import);

                    unmarshall_fn.push(quote_spanned! { v.span() =>
                        fn #type_snake(mut reader: &mut dyn ::std::io::Read) -> Result<::std::sync::Arc<dyn ::core::any::Any>, #import::lnp::presentation::Error> {
                            use #import::strict_encoding::StrictDecode;
                            Ok(::std::sync::Arc::new(#payload_fisheye::#decode_fn(&mut reader)?))
                        }
                    });

                    from_type.push(quote_spanned! { v.span() =>
                        Self::#type_const => {
                            Self::#type_name(data.downcast_ref::<#payload>().expect(ERR).clone())
                        }
                    });

                    get_payload.push(quote_spanned! { v.span() =>
                        Self::#type_name(a) => #encode_fn(a).expect(ERR),
                    });

                    get_type.push(quote_spanned! { v.span() =>
                        Self::#type_name(_) => Self::#type_const,
                    });
                } else {
                    unmarshall_fn.push(unmarshall_empty);

                    from_type.push(quote_spanned! { v.span() =>
                        Self::#type_const => {
                            Self::#type_name()
                        }
                    });

                    get_payload.push(quote_spanned! { v.span() =>
                        Self::#type_name() => vec![],
                    });

                    get_type.push(quote_spanned! { v.span() =>
                        Self::#type_name() => Self::#type_const,
                    });
                }
            }
            Fields::Unit => {
                unmarshall_fn.push(unmarshall_empty);

                from_type.push(quote_spanned! { v.span() =>
                    Self::#type_const => {
                        Self::#type_name
                    }
                });

                get_payload.push(quote_spanned! { v.span() =>
                    Self::#type_name => vec![],
                });

                get_type.push(quote_spanned! { v.span() =>
                    Self::#type_name => Self::#type_const,
                });
            }
        }
    }
    let msg_const = quote! { #( #msg_const )* };
    let unmarshaller = quote! { #( #unmarshaller )* };
    let unmarshall_fn = quote! { #( #unmarshall_fn )* };
    let from_type = quote! { #( #from_type )* };
    let get_type = quote! { #( #get_type )* };
    let get_payload = quote! { #( #get_payload )* };
    let encode_use = global_encoding.encode_use(&import);
    let decode_use = global_encoding.decode_use(&import);

    Ok(quote! {
        impl #import::lnp::CreateUnmarshaller for #ident_name {
            fn create_unmarshaller() -> #import::lnp::Unmarshaller<Self> {
                let mut map = ::std::collections::BTreeMap::new();
                #unmarshaller
                #import::lnp::Unmarshaller::new(map)
            }
        }

        impl #ident_name {
            #msg_const

            #unmarshall_fn
        }

        impl #import::lnp::TypedEnum for #ident_name {
            fn try_from_type(type_id: #import::lnp::TypeId, data: &dyn ::core::any::Any) -> Result<Self, #import::lnp::UnknownTypeError> {
                use ::amplify::Wrapper;

                const ERR: &'static str = "Internal API parsing inconsistency";
                Ok(match type_id.into_inner() {
                    #from_type
                    // Here we receive odd-numbered messages. However, in terms of RPC,
                    // there is no "upstream processor", so we return error (but do not
                    // break connection).
                    _ => Err(#import::lnp::UnknownTypeError)?,
                })
            }

            fn get_type(&self) -> #import::lnp::TypeId {
                use ::amplify::Wrapper;
                #import::lnp::TypeId::from_inner(match self {
                    #get_type
                })
            }

            fn get_payload(&self) -> Vec<u8> {
                const ERR: &'static str = "Message encoding has failed";
                match self {
                    #get_payload
                }
            }
        }
    })
}

// Strict Encode/Decode Derives
// ============================

#[proc_macro_derive(StrictEncode, attributes(strict_error, lnpbp_crate))]
pub fn derive_strict_encode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    strict_encode_inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[proc_macro_derive(StrictDecode, attributes(strict_error, lnpbp_crate))]
pub fn derive_strict_decode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    strict_decode_inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

fn strict_encode_inner(input: DeriveInput) -> Result<TokenStream2> {
    match input.data {
        Data::Struct(ref data) => strict_encode_inner_struct(&input, data),
        Data::Enum(ref data) => strict_encode_inner_enum(&input, data),
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
        Data::Enum(ref data) => strict_decode_inner_enum(&input, data),
        //strict_encode_inner_enum(&input, &data),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            "Deriving StrictDecode is not supported in unions",
        )),
    }
}

fn strict_encode_inner_struct(
    input: &DeriveInput,
    data: &DataStruct,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let error_type_def = get_strict_error(input)?;
    let import = get_lnpbp_crate(input)?;

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
            type Error = #error_type_def;

            #[inline]
            fn strict_encode<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
                use #import::strict_encoding::StrictEncode;

                #inner
            }
        }
    })
}

fn strict_decode_inner_struct(
    input: &DeriveInput,
    data: &DataStruct,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let error_type_def = get_strict_error(input)?;
    let import = get_lnpbp_crate(input)?;

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
            type Error = #error_type_def;

            #[inline]
            fn strict_decode<D: ::std::io::Read>(mut d: D) -> Result<Self, Self::Error> {
                use #import::strict_encoding::StrictDecode;

                Ok(#inner)
            }
        }
    })
}

fn strict_encode_inner_enum(
    input: &DeriveInput,
    data: &DataEnum,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let error_type_def = get_strict_error(input)?;
    let import = get_lnpbp_crate(input)?;

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
            type Error = #error_type_def;

            #[inline]
            fn strict_encode<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
                use #import::strict_encoding::StrictEncode;

                #inner
            }
        }
    })
}

fn strict_decode_inner_enum(
    input: &DeriveInput,
    data: &DataEnum,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let error_type_def = get_strict_error(input)?;
    let import = get_lnpbp_crate(input)?;

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
            type Error = #error_type_def;

            #[inline]
            fn strict_decode<D: ::std::io::Read>(mut d: D) -> Result<Self, Self::Error> {
                use #import::strict_encoding::StrictDecode;

                Ok(#inner)
            }
        }
    })
}

fn get_strict_error(input: &DeriveInput) -> Result<TokenStream2> {
    let import = get_lnpbp_crate(input)?;

    let name = "strict_error";
    let example = "#[strict_error(ErrorType)]";
    let mut strict_error: Option<Ident> = None;

    let list = match attr_list(&input.attrs, name, example)? {
        Some(x) => x,
        None => return Ok(quote! { #import::strict_encoding::Error }),
    };
    let strict_error = attr_nested_one_arg(list.into_iter(), name, example)?;

    Ok(match strict_error {
        Some(ident) => quote! { #ident },
        None => quote! { #import::strict_encoding::Error },
    })
}

fn get_lnpbp_crate(input: &DeriveInput) -> Result<TokenStream2> {
    let name = "lnpbp_crate";
    let example = "#[lnpbp_crate(lnpbp_crate_name)]";
    let default = quote! { ::lnpbp };

    let list = match attr_list(&input.attrs, name, example)? {
        Some(x) => x,
        None => return Ok(default),
    };
    let strict_crate = attr_nested_one_arg(list.into_iter(), name, example)?;

    Ok(match strict_crate {
        Some(ident) => quote! { #ident },
        None => return Ok(default),
    })
}
