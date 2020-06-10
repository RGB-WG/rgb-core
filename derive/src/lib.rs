#![recursion_limit = "256"]
#![cfg_attr(test, deny(warnings))]
#![allow(unused)]

#[macro_use]
extern crate quote;
#[macro_use]
extern crate syn;

use syn::export::{Span, ToTokens, TokenStream, TokenStream2};
use syn::{
    Attribute, Data, DeriveInput, Error, Field, Fields, Ident, Index, Lit, Member, Meta,
    NestedMeta, Path, Result, Type, TypeSlice,
};

struct Details<'a> {
    struct_name: &'a Ident,
    field_name: TokenStream2,
    field_type: &'a Type,
}

impl<'a> Details<'a> {
    pub fn from_input(struct_name: &'a Ident, field: &'a Field) -> Self {
        let field_name = field
            .ident
            .as_ref()
            .map_or_else(|| quote!(0), ToTokens::into_token_stream);

        Details {
            struct_name,
            field_name,
            field_type: &field.ty,
        }
    }
}

#[proc_macro_derive(StrictEncode, attributes(strict_error))]
pub fn derive_strict_encode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    strict_encode_inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

fn strict_encode_inner(input: DeriveInput) -> Result<TokenStream2> {
    match input.data {
        Data::Struct(_) => strict_encode_inner_struct(&input),
        Data::Enum(ref _data) => Err(Error::new_spanned(
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

fn strict_encode_inner_struct(input: &DeriveInput) -> Result<TokenStream2> {
    let field = get_field(&input, "StrictEncode")?;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let strict_error = get_meta_value(
        &input.attrs,
        "StrictEncode",
        "strict_error",
        Some("#[strict_error(Error)]`"),
    )?
    .expect("provided example, should always return a value if succeeded.");
    let Details {
        struct_name,
        field_name,
        ..
    } = Details::from_input(&input.ident, field);

    Ok(quote! {
        #[allow(unused_qualifications)]
        impl #impl_generics lnpbp::strict_encoding::StrictEncode for #struct_name #ty_generics #where_clause {
            type Error = #strict_error;

            #[inline]
            fn strict_encode<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, Error> {
                unimplemented!()
            }
        }
    })
}

fn get_meta_value(
    attrs: &[Attribute],
    trait_name: &str,
    attribute_name: &str,
    example_if_required: Option<&str>,
) -> Result<Option<Member>> {
    let mut traits_found = Vec::with_capacity(attrs.len());
    for attr in attrs {
        let mv = find_meta_value(
            attr,
            attribute_name,
            example_if_required.unwrap_or_default(),
        )
        .unwrap_or_default();
        if mv.multiple() {
            return Err(Error::new_spanned(
                attr,
                format!("lnpbp_derive: {} doesn't nested attributes", attribute_name),
            ));
        }
        if mv.found {
            if let Some(trait_name) = mv.name.get(0) {
                traits_found.push(trait_name.clone());
            } else {
                return Err(Error::new_spanned(attr, format!("lnpbp_derive: when using the {} attribute on the struct you must specify the trait you want to use to implement {}", attribute_name, trait_name)));
            }
        }
    }

    match traits_found.len() {
        1 => Ok(traits_found.pop()),
        0 => {
            if let Some(example) = example_if_required {
                Err(Error::new(Span::call_site(), format!("Deriving {} requires specifying which trait to use using the `{}` attribute. Try: `{}`", trait_name, attribute_name, example)))
            } else {
                Ok(None)
            }
        }
        _ => Err(Error::new(
            Span::call_site(),
            format!(
                "Deriving {} supports only a single {} attribute",
                trait_name, attribute_name
            ),
        )),
    }
}

fn array_to_slice(ty: Type) -> Type {
    if let Type::Array(arr) = ty {
        Type::Slice(TypeSlice {
            bracket_token: arr.bracket_token,
            elem: arr.elem,
        })
    } else {
        ty
    }
}

fn get_field<'a>(input: &'a DeriveInput, trait_name: &str) -> Result<&'a Field> {
    let fields = match input.data {
        Data::Struct(ref data) => &data.fields,
        _ => {
            return Err(Error::new_spanned(
                &input,
                format!("Deriving {} is supported only in structs", trait_name),
            ))
        }
    };

    if fields.iter().len() > 1 {
        let mut marked_fields = parse_outer_attributes(&input.attrs, &fields)?;
        marked_fields.extend(parse_field_attributes(&fields)?);
        match marked_fields.len() {
            1 => Ok(marked_fields.pop().unwrap()),
            0 => Err(Error::new_spanned(&input, format!("Deriving {} for a struct with multiple fields requires specifying a wrap attribute", trait_name))),
            _ => Err(Error::new_spanned(&input, format!("Deriving {} supports only a single wrap attribute", trait_name))),
        }
    } else {
        fields.iter().next().ok_or_else(|| {
            Error::new_spanned(
                &input,
                format!(
                    "Deriving {} for an empty struct isn't supported",
                    trait_name
                ),
            )
        })
    }
}

fn extract_types_from_potential_tupled_attribute(attr: &Attribute) -> Result<Vec<Type>> {
    let ty: Type = syn::parse2(attr.tts.clone())?;
    Ok(match ty {
        Type::Paren(paren) => vec![*paren.elem],
        Type::Tuple(tuple) => tuple.elems.into_iter().collect(),
        _ => vec![ty],
    })
}

fn path_to_string(p: &Path) -> String {
    let mut res = String::with_capacity(p.segments.len() * 6);
    if p.leading_colon.is_some() {
        res.push_str("::");
    }
    for segment in p.segments.iter() {
        res.push_str(&segment.ident.to_string());
        res.push_str("::");
    }
    if !p.segments.is_empty() {
        let len = res.len() - 2;
        res.truncate(len);
    }
    res
}

#[derive(Default)]
struct MetaValue {
    pub found: bool,
    pub name: Vec<Member>,
}

impl MetaValue {
    pub fn push_name_ident(&mut self, ident: Ident) {
        self.name.push(Member::Named(ident));
    }

    pub fn multiple(&self) -> bool {
        self.name.len() > 1
    }

    pub fn push_name_index(&mut self, index: u32, span: Span) {
        self.name.push(Member::Unnamed(Index { index, span }));
    }

    pub fn push_name_from_lit(&mut self, lit: Lit) -> Result<()> {
        match lit {
            Lit::Str(l) => {
                if let Ok(index) = l.value().parse::<u32>() {
                    self.push_name_index(index, l.span());
                } else {
                    self.push_name_ident(l.parse::<Ident>()?);
                }
            }
            Lit::Int(int) => self.push_name_index(int.value() as u32, int.span()),
            _ => (),
        }
        Ok(())
    }

    pub fn get_first_name(&self) -> Option<String> {
        self.name.get(0).map(|name| match *name {
            Member::Unnamed(ref index) => index.index.to_string(),
            Member::Named(ref ident) => ident.to_string(),
        })
    }

    pub fn get_first_index(&self) -> Option<u32> {
        self.name.get(0).and_then(|n| match *n {
            Member::Unnamed(ref i) => Some(i.index),
            Member::Named(_) => None,
        })
    }
}
fn find_meta_value(attr: &Attribute, name: &str, example: &str) -> Result<MetaValue> {
    let mut res = MetaValue::default();
    match attr.parse_meta() {
        Ok(meta) => {
            if meta.name() == name {
                res.found = true;
                match meta {
                    Meta::NameValue(nv) => res.push_name_from_lit(nv.lit)?,
                    Meta::List(list) => {
                        for nestedmeta in list.nested.into_iter() {
                            match nestedmeta {
                                NestedMeta::Literal(lit) => res.push_name_from_lit(lit)?,
                                NestedMeta::Meta(meta) => {
                                    if let Meta::Word(ident) = meta {
                                        res.push_name_ident(ident)
                                    }
                                }
                            }
                        }
                    }
                    Meta::Word(_) => (),
                }
            }
        }
        Err(e) => return Err(Error::new(e.span(), format!("{}. Try: `{}`", e, example))),
    }

    Ok(res)
}

fn parse_outer_attributes<'a>(attrs: &[Attribute], fields: &'a Fields) -> Result<Vec<&'a Field>> {
    let mut res = Vec::with_capacity(attrs.len());
    for attr in attrs {
        let mv = find_meta_value(attr, "strict_error", "#[strict_error(Error)]")?;
        if mv.found {
            if let Some(index) = mv.get_first_index() {
                if let Some(field) = fields.iter().nth(index as usize) {
                    res.push(field);
                } else {
                    return Err(Error::new_spanned(&fields, format!("lnpbp_derive: there's no field no. {} in the struct or it's not a tuple", index)));
                }
            } else if let Some(lit_name) = mv.get_first_name() {
                let mut found = false;
                for f in fields {
                    if let Some(ref field_name) = f.ident {
                        if field_name == &lit_name {
                            res.push(f);
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    return Err(Error::new_spanned(
                        &fields,
                        format!("lnpbp_derive: field {} doesn't exist", lit_name),
                    ));
                }
            } else {
                return Err(Error::new_spanned(&fields, "lnpbp_derive: when using the wrap attribute on the struct you must specify the field name"));
            }
        }
    }
    Ok(res)
}

fn parse_field_attributes(fields: &Fields) -> Result<Vec<&Field>> {
    let mut res = Vec::with_capacity(fields.iter().len());
    for field in fields.iter() {
        for attr in &field.attrs {
            let mv = find_meta_value(attr, "wrap", "#[wrap = \"first_field\"]")?;
            if mv.found {
                if let Some(ref ident) = field.ident {
                    if let Some(lit) = mv.get_first_name() {
                        if ident != &lit {
                            return Err(Error::new_spanned(&field, format!("lnpbp_derive: The provided field name doesn't match the field name it's above: `{} != {}`", lit, ident)));
                        }
                    }
                    res.push(field)
                } else {
                    return Err(Error::new_spanned(&field, "lnpbp_derive doesn't yet support attributes on unnamed fields (Please file an issue)"));
                }
            }
        }
    }
    Ok(res)
}
