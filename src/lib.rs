// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2019 by
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

#![feature(
    never_type,
    associated_type_defaults,
    arbitrary_enum_discriminant,
    in_band_lifetimes,
    try_trait,
    pattern
)]
#![recursion_limit = "256"]
// Coding conventions
#![allow(incomplete_features, type_alias_bounds)]
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports
)]
// TODO: when we will be ready for the release #![deny(missing_docs)]
// TODO: when we will be ready for the release #![deny(dead_code)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate num_derive;

// Support for node & node clients development (include API helpers)
#[cfg(any(feature = "daemons", feature = "async"))]
#[macro_use]
extern crate async_trait;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

// Logging
#[cfg(feature = "log")]
// We need this since under some feature combinations log macros are not required
#[allow(unused_imports)]
#[macro_use]
extern crate log;

// Bitcoin-specific imports. We make them public while we use custom versions
// of the libs so downstream dependencies can use them directly from this lib
// TODO: Remove re-exporting of bitcoin crates on release
#[macro_use]
pub extern crate bitcoin;
#[macro_use]
pub extern crate bitcoin_hashes;
pub extern crate miniscript;

#[macro_use]
extern crate lnpbp_derive;

#[macro_use]
mod paradigms;
#[macro_use]
mod common;
mod lnpbps;
#[macro_use]
pub mod bp;
#[cfg(feature = "lnp")]
#[allow(dead_code, unused_variables)] // TODO: Remove attribute once LNP mod will be finalized
pub mod lnp;
#[cfg(feature = "rgb")]
pub mod rgb;

pub use common::*;
pub use lnpbps::*;
pub use paradigms::*;

lazy_static! {
    /// Global Secp256k1 context object
    pub static ref SECP256K1: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> = bitcoin::secp256k1::Secp256k1::new();
}
