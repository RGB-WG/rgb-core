// Rust language amplification derive library providing multiple generic trait
// implementations, type wrappers, derive macros and other language enhancements
//
// Written in 2019-2020 by
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

#![allow(dead_code)]

use syn::punctuated::IntoIter;
use syn::spanned::Spanned;
use syn::{
    Attribute, DeriveInput, Ident, Lit, Meta, MetaNameValue, NestedMeta, Path,
    Result,
};

/// Macro producing [`Result::Err`] with [`syn::Error`] containing span
/// information from `$attr` (first) argument and formatted string describing
/// concrete error (description is taken from `$msg` second macro argument) and
/// providing an example `$example` (third macro argument) of how the macro
/// should be used.
macro_rules! attr_err {
    ($attr:expr, $msg:tt) => {
        attr_err!($attr.span(), NAME, $msg, EXAMPLE);
    };
    ($name:expr, $msg:tt, $example:tt) => {
        attr_err!(::proc_macro2::Span::call_site(), $name, $msg, $example);
    };
    ($attr:expr, $name:expr, $msg:tt, $example:tt) => {
        ::syn::Error::new(
            $attr.span(),
            format!(
                "Attribute `#[{}]`: {}\nExample use: {}",
                $name, $msg, $example
            ),
        );
    };
}

macro_rules! err {
    ( $span:expr, $msg:literal ) => {
        Err(attr_err!($span, $msg))?
    };
}

pub(crate) fn get_lnpbp_crate(input: &DeriveInput) -> Path {
    let name = "lnpbp_crate";
    let example = "#[lnpbp_crate(crate_path)]";
    let default = Path::from(Ident::new("lnpbp", input.span()));

    let list = match attr_list(&input.attrs, name, example).ok().flatten() {
        Some(x) => x,
        None => return default,
    };
    nested_one_path(&list, name, example)
        .ok()
        .flatten()
        .unwrap_or(default)
}

pub(crate) fn attr_list<'a>(
    attrs: impl IntoIterator<Item = &'a Attribute>,
    ident: &str,
    example: &str,
) -> Result<Option<IntoIter<NestedMeta>>> {
    for attr in attrs {
        if attr.path.is_ident(ident) {
            match attr.parse_meta() {
                Ok(meta) => match meta {
                    Meta::Path(_) => {
                        return Err(attr_err!(
                            ident,
                            "unexpected path argument",
                            example
                        ))
                    }
                    Meta::List(list) => {
                        return Ok(Some(list.nested.into_iter()))
                    }
                    Meta::NameValue(_) => {
                        return Err(attr_err!(
                            ident,
                            "unexpected `name=\"value\"` argument",
                            example
                        ))
                    }
                },
                Err(_) => {
                    return Err(attr_err!(ident, "wrong format", example))
                }
            }
        }
    }

    Ok(None)
}

pub(crate) fn attr_named_value<'a>(
    attrs: impl IntoIterator<Item = &'a Attribute>,
    ident: &str,
    example: &str,
) -> Result<Option<Lit>> {
    for attr in attrs {
        if attr.path.is_ident(ident) {
            match attr.parse_meta() {
                Ok(meta) => match meta {
                    Meta::Path(_) => {
                        return Err(attr_err!(
                            ident,
                            "unexpected path argument",
                            example
                        ))
                    }
                    Meta::List(_) => {
                        return Err(attr_err!(
                        ident,
                        "must have form `name=\"value\"`, not `name(value)`",
                        example
                    ))
                    }
                    Meta::NameValue(name_val) => return Ok(Some(name_val.lit)),
                },
                Err(_) => {
                    return Err(attr_err!(ident, "wrong format", example))
                }
            }
        }
    }

    Ok(None)
}

pub(crate) fn nested_one_meta(
    list: &IntoIter<NestedMeta>,
    attr_name: &str,
    example: &str,
) -> Result<Option<Meta>> {
    match list.len() {
        0 => Err(attr_err!(
            attr_name,
            "unexpected absence of argument",
            example
        )),
        1 => match list
            .clone()
            .peekable()
            .peek()
            .expect("Core library iterator is broken")
        {
            NestedMeta::Meta(meta) => Ok(Some(meta.clone())),
            NestedMeta::Lit(_) => Err(attr_err!(
                attr_name,
                "unexpected literal for type identifier is met",
                example
            )),
        },
        _ => Err(attr_err!(
            attr_name,
            "unexpected multiple type identifiers",
            example
        )),
    }
}

pub(crate) fn nested_one_path(
    list: &IntoIter<NestedMeta>,
    attr_name: &str,
    example: &str,
) -> Result<Option<Path>> {
    let meta = nested_one_meta(list, attr_name, example)?;
    Ok(meta
        .map(|meta| match meta {
            Meta::Path(path) => Ok(path),
            _ => {
                Err(attr_err!(attr_name, "unexpected attribute type", example))
            }
        })
        .transpose()?)
}

pub(crate) fn nested_one_named_value(
    list: &IntoIter<NestedMeta>,
    attr_name: &str,
    example: &str,
) -> Result<Option<MetaNameValue>> {
    let meta = nested_one_meta(list, attr_name, example)?;
    Ok(meta
        .map(|meta| match meta {
            Meta::NameValue(nested_meta) => Ok(nested_meta),
            _ => {
                Err(attr_err!(attr_name, "unexpected attribute type", example))
            }
        })
        .transpose()?)
}
