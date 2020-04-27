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
use super::{network::*, Error};

pub trait Storage: Sized {
    fn storage_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error>;
    fn storage_deserialize<D: io::Read>(d: D) -> Result<Self, Error>;
}


impl<T> Storage for T where T: Network {
    #[inline]
    fn storage_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.network_serialize(&mut e)
    }

    #[inline]
    fn storage_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        Self::network_deserialize(d)
    }
}

#[inline]
pub fn storage_serialize<T: Storage + Network>(data: &T) -> Result<Vec<u8>, Error> {
    network_serialize(data)
}

#[inline]
pub fn storage_deserialize<T: Storage + Network>(data: &[u8]) -> Result<T, Error> {
    T::network_deserialize(data)
}
