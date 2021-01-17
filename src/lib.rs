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
// TODO: when we will be ready for the release #![deny(missing_docs)]
// This is required because of incomplete rust async implementation and can be
// removed after async trait feature completion in rust compiler
#![cfg_attr(feature = "async", allow(where_clauses_object_safety))]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate num_derive;

extern crate chacha20poly1305;

// Support for node & node clients development (include API helpers)
#[cfg(feature = "async")]
#[macro_use]
extern crate async_trait;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

// Bitcoin-specific imports. We make them public while we use custom versions
// of the libs so downstream dependencies can use them directly from this lib
// TODO: Refactor re-exported bitcoin and hashes functionality
pub extern crate bitcoin;
pub use bitcoin::secp256k1;
#[macro_use]
pub extern crate bitcoin_hashes as hashes;
pub use hashes::hex;
pub extern crate miniscript;
#[cfg(feature = "bulletproofs")]
pub extern crate secp256k1zkp;

#[macro_use]
extern crate lnpbp_derive;

#[macro_use]
pub mod test_helpers;
#[macro_use]
mod paradigms;
mod standards;
#[macro_use]
pub mod bp;
#[cfg(feature = "lnp")]
#[allow(dead_code, unused_variables)]
// TODO: Remove attribute once LNP mod will be finalized
pub mod lnp;

pub use lnp::presentation::encoding as lightning_encoding;
pub use paradigms::{
    client_side_validation, commit_verify, single_use_seals, strict_encoding,
};
#[cfg(feature = "elgamal")]
pub use standards::elgamal;
pub use standards::{features, lnpbp1, lnpbp2, lnpbp3, lnpbp4};

lazy_static! {
    /// Global Secp256k1 context object
    pub static ref SECP256K1: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> =
        bitcoin::secp256k1::Secp256k1::new();

    pub static ref SECP256K1_PUBKEY_DUMB: bitcoin::secp256k1::PublicKey =
        bitcoin::secp256k1::PublicKey::from_secret_key(&SECP256K1, &bitcoin::secp256k1::key::ONE_KEY);
}
