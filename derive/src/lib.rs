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
#![feature(try_trait)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate quote;
#[macro_use]
extern crate syn;

use amplify::proc_macro;
use core::convert::TryFrom;
use core::option::NoneError;
use syn::export::{Span, ToTokens, TokenStream, TokenStream2};
use syn::spanned::Spanned;
use syn::{
    Attribute, Data, DataEnum, DataStruct, DeriveInput, Error, Field, Fields, Ident, Index, Lit,
    Member, Meta, NestedMeta, Path, Result, Type, TypeSlice, Variant,
};

// LNP API Derive
// ==============

#[proc_macro_derive(LnpApi, attributes(lnp_api))]
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
    pub fn encode_fn(&self, span: Span) -> TokenStream2 {
        match self {
            Self::Strict => quote_spanned!(span => strict_encode),
            Self::Bitcoin => quote_spanned!(span => consensus_encode),
            Self::Lightning => unimplemented!(),
        }
    }

    pub fn decode_fn(&self, span: Span) -> TokenStream2 {
        match self {
            Self::Strict => quote_spanned!(span => strict_decode),
            Self::Bitcoin => quote_spanned!(span => consensus_decode),
            Self::Lightning => unimplemented!(),
        }
    }

    pub fn encode_use(&self) -> TokenStream2 {
        match self {
            Self::Strict => quote!(
                use ::lnpbp::strict_encoding::strict_encode;
            ),
            Self::Bitcoin => quote!(
                use ::lnpbp::bitcoin::consensus::encode::{consensus_encode, Encode};
            ),
            Self::Lightning => unimplemented!(),
        }
    }

    pub fn decode_use(&self) -> TokenStream2 {
        match self {
            Self::Strict => quote!(
                use ::lnpbp::strict_encoding::StrictDecode;
            ),
            Self::Bitcoin => quote!(
                use ::lnpbp::bitcoin::consensus::encode::Decode;
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

fn lnp_api_inner_enum(input: &DeriveInput, data: &DataEnum) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let ident_name = &input.ident;

    let name = "lnp_api";
    let example = "#[lnp_api(encoding=\"strict|bitcoin|lightning\")]";
    let global_params = match proc_macro::attr_list(&input.attrs, name, example)? {
        Some(x) => x,
        None => vec![],
    };
    let global_encoding = EncodingSrategy::try_from(
        proc_macro::attr_nested_one_named_value(global_params.into_iter(), "encoding", example)?
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
        let meta = proc_macro::attr_list(&v.attrs, "lnp_api", example)?.ok_or(Error::new(
            v.span(),
            format!(
                "Attribute macro canonical form `{}` violation: {}",
                example, "`lnp_api` attribute is required for each message enum case",
            ),
        ))?;

        let type_lit: Lit =
            proc_macro::attr_nested_one_named_value(meta.into_iter(), "type", example)?.lit;
        let type_id: u16 = match type_lit {
            Lit::Int(i) => i
                .base10_parse()
                .or_else(|_| proc_macro_err!(i, "`type` must be an integer", example))?,
            _ => proc_macro_err!(type_lit, "`type` must be an integer", example)?,
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
            map.insert(Self::#type_const, Self::#type_snake as UnmarshallFn<_>);
        });

        let unmarshall_empty = quote_spanned! { v.span() =>
            fn #type_snake(_: &mut dyn ::std::io::Read) -> Result<::std::sync::Arc<dyn ::core::any::Any>, ::lnpbp::lnp::presentation::Error> {
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
                    let payload_fisheye: TokenStream2 =
                        syn::parse_str(&quote!(#payload).to_string().replacen("<", "::<", 1))
                            .expect("Internal error");
                    let encode_fn = global_encoding.encode_fn(f.span());
                    let decode_fn = global_encoding.decode_fn(f.span());

                    unmarshall_fn.push(quote_spanned! { v.span() =>
                        fn #type_snake(mut reader: &mut dyn ::std::io::Read) -> Result<::std::sync::Arc<dyn ::core::any::Any>, ::lnpbp::lnp::presentation::Error> {
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
    let encode_use = global_encoding.encode_use();
    let decode_use = global_encoding.decode_use();

    Ok(quote! { mod __lnp_implementaiton {
        use super::#ident_name;
        use ::amplify::Wrapper;
        use ::lnpbp::lnp::{Type, TypedEnum, UnknownTypeError, UnmarshallFn, Unmarshaller};
        #encode_use
        #decode_use

        impl #ident_name {
            #msg_const

            pub fn create_unmarshaller() -> Unmarshaller<Self> {
                let mut map = ::std::collections::BTreeMap::new();
                #unmarshaller
                Unmarshaller::new(map)
            }

            #unmarshall_fn
        }

        impl TypedEnum for #ident_name {
            fn try_from_type(type_id: Type, data: &dyn ::core::any::Any) -> Result<Self, UnknownTypeError> {
                const ERR: &'static str = "Internal API parsing inconsistency";
                Ok(match type_id.into_inner() {
                    #from_type
                    // Here we receive odd-numbered messages. However, in terms of RPC,
                    // there is no "upstream processor", so we return error (but do not
                    // break connection).
                    _ => Err(UnknownTypeError)?,
                })
            }

            fn get_type(&self) -> Type {
                Type::from_inner(match self {
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
    } })
}

// Strict Encode/Decode Derives
// ============================

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
    let name = "strict_error";
    let example = "#[strict_error(ErrorType)]";
    let mut strict_error: Option<Ident> = None;

    let list = match proc_macro::attr_list(&input.attrs, name, example)? {
        Some(x) => x,
        None => return Ok(quote! {}),
    };
    let strict_error = proc_macro::attr_nested_one_arg(list.into_iter(), name, example)?;

    Ok(match strict_error {
        Some(ident) => quote! { type Error = #ident; },
        None => quote! {},
    })
}
