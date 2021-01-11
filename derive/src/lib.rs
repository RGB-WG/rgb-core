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

#![recursion_limit = "256"]
#![cfg_attr(test, deny(warnings))]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate quote;
#[macro_use]
extern crate syn;
extern crate proc_macro;

#[macro_use]
mod util;

mod lightning_encoding;
mod lnp_api;
mod strict_encoding;

use proc_macro::TokenStream;
use syn::DeriveInput;

#[proc_macro_derive(LnpApi, attributes(lnp_api, lnpbp_crate))]
pub fn derive_lnp_api(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    lnp_api::inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[proc_macro_derive(StrictEncode, attributes(lnpbp_crate))]
pub fn derive_strict_encode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    strict_encoding::encode_inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[proc_macro_derive(StrictDecode, attributes(lnpbp_crate))]
pub fn derive_strict_decode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    strict_encoding::decode_inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[proc_macro_derive(LightningEncode, attributes(lnpbp_crate, tlv))]
pub fn derive_lightning_encode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    lightning_encoding::encode_inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[proc_macro_derive(LightningDecode, attributes(lnpbp_crate, tlv))]
pub fn derive_lightning_decode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    lightning_encoding::decode_inner(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
