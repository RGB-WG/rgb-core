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


use std::io;

use num_traits::{ToPrimitive, FromPrimitive};
use bitcoin::consensus::encode as consensus;

use super::{Commitment, Error};


pub trait FromEnumPrimitive: FromPrimitive + ToPrimitive { }
pub trait FromConsensus: consensus::Encodable + consensus::Decodable { }

impl FromConsensus for u8 { }
impl FromConsensus for u16 { }
impl FromConsensus for u32 { }
impl FromConsensus for u64 { }
impl FromConsensus for i8 { }
impl FromConsensus for i16 { }
impl FromConsensus for i32 { }
impl FromConsensus for i64 { }

impl<T> Commitment for T where T: FromConsensus {
    #[inline]
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(self.consensus_encode(&mut e)?)
    }

    #[inline]
    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::consensus_decode(d)?)
    }
}


impl Commitment for usize {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        if *self > std::u16::MAX as usize {
            return Err(consensus::Error::OversizedVectorAllocation {
                requested: *self, max: std::u16::MAX as usize
            }.into())
        }

        let size = *self as u16;
        size.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        u16::commitment_deserialize(&mut d).map(|val| val as usize)
    }
}
