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

#![crate_name = "lnpbp"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]
#![feature(concat_idents)]
#![feature(never_type)]
#![feature(const_generics)]
#![feature(optin_builtin_traits)]
#![feature(associated_type_defaults)]
#![feature(const_fn)]
#![feature(arbitrary_enum_discriminant)]
#![feature(bool_to_option)]
#![feature(str_strip)]
#![feature(bindings_after_at)]
#![feature(in_band_lifetimes)]
#![recursion_limit = "256"]
// Coding conventions
#![allow(incomplete_features)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(unused_imports)]
// TODO: when we will be ready for the release #![deny(missing_docs)]
// TODO: when we will be ready for the release #![deny(dead_code)]

#[macro_use]
pub extern crate derive_wrapper;
extern crate num_derive;
extern crate num_traits;
extern crate rand;
#[macro_use]
pub extern crate bitcoin;

// Logging
#[cfg(feature = "log")]
#[macro_use]
extern crate log;

// Async IO, IPC & networking
#[cfg(not(feature = "tokio"))]
extern crate futures;
#[cfg(feature = "tokio")]
extern crate tokio;

// Support for node & node clients development (include API helpers)
#[cfg(any(feature = "daemons", feature = "async"))]
#[macro_use]
extern crate async_trait;
#[cfg(feature = "zmq")]
extern crate zmq;

// Lightning-network related functionality
#[cfg(feature = "lightning")]
pub extern crate lightning;
#[cfg(feature = "lightning_tokio")]
pub extern crate lightning_net_tokio;

pub extern crate miniscript;

// Buletproofs support
#[cfg(feature = "bulletproofs")]
pub extern crate secp256k1zkp;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

mod primitives;
#[macro_use]
mod common;
mod lnpbps;
#[macro_use]
pub mod bp;
#[cfg(feature = "lightning")]
pub mod lnp;
#[cfg(feature = "rgb")]
pub mod rgb;

pub use common::*;
pub use lnpbps::*;
pub use primitives::*;
