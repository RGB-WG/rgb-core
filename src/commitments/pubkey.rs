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

//! Library for Secp256k1 elliptic curve based collision-resistant commitments, implementing
//! [LNPBPS-1](https://github.com/LNP-BP/lnpbps/blob/master/lnpbps-0001.md)
//!
//! NB: The library works with `secp256k1::PublicKey` and `secp256k1::SecretKey` keys, not
//! their wrapped bitcoin counterparts `bitcoin::PublickKey` and `bitcoin::PrivateKey`.

use std::ops::{Index, RangeFull};
use std::sync::Once;
use std::convert::TryInto;

use secp256k1::{PublicKey, Secp256k1, All};
use bitcoin::hashes::{Hmac, HmacEngine, sha256, Hash, HashEngine};

use crate::commitments::container::Container;
use crate::common::raw_representable::RawRepresentable;
use crate::commitments::tag::BitcoinTag;

const TAG: &'static str = "LNPBP-1";
static INIT: Once = Once::new();
static mut PREFIX: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[derive(Clone, PartialEq, Eq)]
pub struct PubkeyCommitment(PublicKey);

impl Container for PubkeyCommitment {
    type Message = Box<RawRepresentable>;

    fn commit(&mut self, msg: &Self::Message) {
        let ec: Secp256k1<All> = Secp256k1::new();
        INIT.call_once(|| unsafe {
            PREFIX = BitcoinTag::tag(TAG)[..].try_into()
                .expect("SHA256 length is 32 bytes always");
        });
        unsafe {
            let prefix = BitcoinTag::from_slice(&PREFIX)
                .expect("Can't fail since it reads hash value");
        }
        let origin = self.clone();
        let mut hmac_engine = HmacEngine::<sha256::Hash>::new(&origin.0.serialize());
        hmac_engine.input(&msg[..]);
        let factor = &Hmac::from_engine(hmac_engine)[..];
        self.0.add_exp_assign(&ec, factor)
            .expect("Key tweaking has resulted in point at infinity");
    }
}
