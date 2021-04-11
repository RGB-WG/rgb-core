// RGB20 Library: fungible digital assets for bitcoin & lightning
// Written in 2020-2021 by
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
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    missing_docs
)]

//! RGB20 library for working with fungible asset types, operating under
//! schemata, defined with LNPBP-20 standard:
//! - Root RGB20 schema, returned by [`schema::schema()`] with id
//!   [`SCHEMA_ID_BECH32`]
//! - RGB20 subschema, returned by [`schema::subschema()`], prohibiting asset
//!   replacement procedure and having id [`SUBSCHEMA_ID_BECH32`]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate lnpbp;
#[macro_use]
extern crate rgb;

#[cfg(feature = "serde")]
extern crate serde_crate as serde;
#[cfg(feature = "serde")]
extern crate serde_with;

mod amount;
pub mod asset;
pub mod schema;
mod supply;
pub mod transitions;

pub use amount::{FractionalAmount, PreciseAmount};
pub use asset::Asset;
pub use schema::{SCHEMA_ID_BECH32, SUBSCHEMA_ID_BECH32};
pub use supply::{BurnReplace, Epoch, Issue, Supply, SupplyMeasure};
