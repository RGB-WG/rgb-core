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

use core::convert::TryFrom;
use syn::export::{Span, TokenStream2};
use syn::spanned::Spanned;
use syn::{
    Data, DataEnum, DeriveInput, Error, Fields, Ident, Lit, Path, Result,
};

use crate::util::{attr_list, get_lnpbp_crate, nested_one_named_value};

const NAME: &'static str = "lnp_api";
const EXAMPLE: &'static str =
    "#[lnp_api(encoding=\"strict|bitcoin|lightning\")]";

pub(crate) fn inner(input: DeriveInput) -> Result<TokenStream2> {
    match input.data {
        Data::Struct(_) => Err(Error::new_spanned(
            &input,
            "Deriving LnpApi can be done only with enums, not with structs",
        )),
        Data::Enum(ref data) => inner_enum(&input, data),
        //strict_encode_inner_enum(&input, &data),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            "Deriving LnpApi can be done only with enums, not with unions",
        )),
    }
}

fn inner_enum(input: &DeriveInput, data: &DataEnum) -> Result<TokenStream2> {
    let ident_name = &input.ident;

    let global_params = attr_list(&input.attrs, NAME, EXAMPLE)?
        .ok_or(attr_err!(input, "encoding type must be specified"))?;
    let import = get_lnpbp_crate(input);
    let global_encoding = EncodingSrategy::try_from(
        nested_one_named_value(&global_params, "encoding", EXAMPLE)?
            .ok_or(attr_err!(input, "encoding must be specified"))?
            .lit,
    )?;
    let encode_use = global_encoding.encode_use(&import);
    let decode_use = global_encoding.decode_use(&import);
    let encode_fn = global_encoding.encode_fn();

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

        let type_lit: Lit = nested_one_named_value(&meta, "type", EXAMPLE)?
            .ok_or(attr_err!(v, "type must be specified"))?
            .lit;
        let type_id: u16 = match type_lit {
            Lit::Int(i) => i
                .base10_parse()
                .or_else(|_| Err(attr_err!(i, "`type` must be an integer")))?,
            _ => err!(type_lit, "`type` must be an integer"),
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
                err!(
                    v,
                    "LNP API does not support requests represented by named enums"
                )
            }
            Fields::Unnamed(args) => {
                let fields = &args.unnamed;
                if fields.len() > 1 {
                    err!(
                        v,
                        "each LNP API message enum variant must contain not more than a single argument"     
                   );
                }
                if let Some(f) = fields.first() {
                    let payload = &f.ty;
                    let payload_fisheye: TokenStream2 = syn::parse_str(
                        &quote!(#payload).to_string().replacen("<", "::<", 1),
                    )
                    .expect("Internal error");
                    let serialize_fn =
                        global_encoding.serialize_fn(f.span(), &import);
                    let decode_fn = global_encoding.decode_fn(f.span());

                    unmarshall_fn.push(quote_spanned! { v.span() =>
                        fn #type_snake(mut reader: &mut dyn ::std::io::Read) -> Result<::std::sync::Arc<dyn ::core::any::Any>, #import::lnp::presentation::Error> {
                            #decode_use
                            Ok(::std::sync::Arc::new(#payload_fisheye::#decode_fn(&mut reader)?))
                        }
                    });

                    from_type.push(quote_spanned! { v.span() =>
                        Self::#type_const => {
                            Self::#type_name(data.downcast_ref::<#payload>().expect(ERR).clone())
                        }
                    });

                    get_payload.push(quote_spanned! { v.span() =>
                        Self::#type_name(obj) => #serialize_fn,
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

            fn serialize(&self) -> Vec<u8> {
                #encode_use
                let mut e = vec![];
                let _ = self.get_type().#encode_fn(&mut e);
                let _ = self.get_payload().#encode_fn(&mut e);
                e
            }
        }
    })
}

enum EncodingSrategy {
    Strict,
    Bitcoin,
    Lightning,
}

impl EncodingSrategy {
    pub fn serialize_fn(&self, span: Span, import: &Path) -> TokenStream2 {
        match self {
            Self::Strict => {
                quote_spanned!(span => #import::strict_encoding::strict_serialize(obj).expect(ERR))
            }
            Self::Bitcoin => {
                quote_spanned!(span => #import::bitcoin::consensus::encode::consensus_encode(obj))
            }
            Self::Lightning => {
                quote_spanned!(span => #import::lightning_encoding::lightning_serialize(obj))
            }
        }
    }

    pub fn encode_fn(&self) -> TokenStream2 {
        match self {
            Self::Strict => {
                quote!(strict_encode)
            }
            Self::Bitcoin => {
                quote!(consensus_encode)
            }
            Self::Lightning => {
                quote!(lightning_encode)
            }
        }
    }

    pub fn decode_fn(&self, span: Span) -> TokenStream2 {
        match self {
            Self::Strict => quote_spanned!(span => strict_decode),
            Self::Bitcoin => quote_spanned!(span => consensus_decode),
            Self::Lightning => quote_spanned!(span => lightning_decode),
        }
    }

    pub fn encode_use(&self, import: &Path) -> TokenStream2 {
        match self {
            Self::Strict => quote!(
                use #import::strict_encoding::StrictEncode;
            ),
            Self::Bitcoin => quote!(
                use #import::bitcoin::consensus::encode::Encode;
            ),
            Self::Lightning => quote!(
                use #import::lightning_encoding::LightningEncode;
            ),
        }
    }

    pub fn decode_use(&self, import: &Path) -> TokenStream2 {
        match self {
            Self::Strict => quote!(
                use #import::strict_encoding::StrictDecode;
            ),
            Self::Bitcoin => quote!(
                use #import::bitcoin::consensus::encode::Decode;
            ),
            Self::Lightning => quote!(
                use #import::lightning_encoding::LightningDecode;
            ),
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
