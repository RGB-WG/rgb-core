// RGB20 Library: fungible digital assets for bitcoin & lightning
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
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
)]

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

pub mod allocation;
mod asset;
mod processor;
pub mod schema;

pub use allocation::{AllocatedValue, OutpointValue, UtxobValue};
pub use asset::{
    Allocation, Asset, Error, FractionalAmount, Issue, PreciseAmount, Supply,
    SupplyMeasure,
};
pub use processor::TransitionError;
