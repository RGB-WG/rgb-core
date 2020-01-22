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


use std::convert::TryFrom;

use bitcoin::hash_types::Txid;


#[non_exhaustive]
#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum Error {
    VoutOverflow
}


#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, Default)]
#[display_from(Debug)]
pub struct Type(pub u16);


#[derive(Clone, PartialEq, PartialOrd, Debug, Display, Default)]
#[display_from(Debug)]
pub struct Seal {
    pub txid: Txid,
    pub vout: u16,

    block_height: Option<u32>,
    block_offset: Option<u16>,
}

impl Seal {
    pub fn from(txid: Txid, vout: u16) -> Self {
        Self {
            txid, vout,
            block_height: None,
            block_offset: None
        }
    }
}

impl TryFrom<bitcoin::OutPoint> for Seal {
    type Error = Error;
    fn try_from(outpoint: bitcoin::OutPoint) -> Result<Self, Self::Error> {
        let vout = outpoint.vout;
        if vout > std::u16::MAX as u32 {
            return Err(Error::VoutOverflow)
        }
        Ok(Self {
            txid: outpoint.txid, vout: outpoint.vout as u16,
            block_height: None, block_offset: None
        })
    }
}
