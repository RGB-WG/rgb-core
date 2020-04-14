// LNP/BP Rust Library
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

#![crate_name = "lnpbp"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]

#![feature(concat_idents)]
#![feature(never_type)]
#![feature(const_generics)]
#![feature(optin_builtin_traits)]
#![feature(associated_type_defaults)]
#![feature(const_fn)]

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(unused_imports)]
// TODO: when we will be ready for the release #![deny(missing_docs)]
// TODO: when we will be ready for the release #![deny(dead_code)]

#[macro_use]
pub extern crate derive_wrapper;
extern crate rand;
extern crate num_integer;
extern crate num_derive;
extern crate num_traits;
#[cfg(feature="use-log")]
#[macro_use]
extern crate log;
#[cfg(feature="use-tokio")]
extern crate tokio;
#[cfg(feature="use-daemons")]
#[macro_use]
extern crate async_trait;
#[macro_use]
pub extern crate bitcoin;
#[cfg(feature="use-lightning")]
pub extern crate lightning;
pub extern crate miniscript;
#[cfg(feature="use-bulletproofs")]
pub extern crate secp256k1zkp;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

#[macro_use]
pub mod common;
#[macro_use]
pub mod bp;
#[cfg(feature="use-lightning")]
pub mod lnp;
pub mod cmt;
#[cfg(feature="use-rgb")]
pub mod seals;
#[cfg(feature="use-rgb")]
#[macro_use]
pub mod csv;
#[cfg(feature="use-rgb")]
pub mod rgb;

pub use common::*;
