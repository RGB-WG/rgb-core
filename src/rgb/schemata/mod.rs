// LNP/BP Rust Library
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

use super::schema::Schema;

pub mod fungible;
pub mod collectibles;

pub use fungible::Rgb1;
pub use collectibles::Rgb2;


use num_traits::{ToPrimitive};
use num_derive::{ToPrimitive, FromPrimitive};


pub trait Schemata {
    fn get_schema() -> &'static Schema;
}


/// A set of recommended standard networks that can be used with different schemata
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive)]
#[display_from(Debug)]
pub enum Network {
    Mainnet = 0,
    Testnet = 1,
    Regtest = 2,
    Signet = 3,
    Liquid = 4,
}

impl Network {
    pub fn all() -> Vec<Network> {
        use Network::*;
        vec![ Mainnet, Testnet, Regtest, Signet, Liquid ]
    }

    pub fn all_u8() -> Vec<u8> {
        Self::all().into_iter().map(Network::into).collect()
    }
}

impl Into<u8> for Network {
    fn into(self) -> u8 {
        self.to_u8().expect("There are only 4 pre-defined enum values, so we can't overflow here")
    }
}
