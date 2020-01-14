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
use super::commitment::*;

pub trait Network: Sized {
    fn network_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error>;
    fn network_deserialize<D: io::Read>(d: D) -> Result<Self, Error>;
}

impl<T> Network for T where T: Commitment {
    #[inline]
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.commitment_serialize(&mut e)
    }

    #[inline]
    fn network_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        Self::commitment_deserialize(d)
    }
}

#[inline]
pub fn network_serialize<T: Commitment + Network>(data: &T) -> Result<Vec<u8>, Error> {
    commitment_serialize(data)
}

#[inline]
pub fn network_deserialize<T: Commitment + Network>(data: &[u8]) -> Result<T, Error> {
    T::commitment_deserialize(data)
}
