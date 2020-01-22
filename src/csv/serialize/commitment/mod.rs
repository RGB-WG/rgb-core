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


#[macro_use]
pub mod macros;
pub mod primitives;
pub mod collections;

pub use macros::*;
pub use primitives::*;
pub use collections::*;

use std::io;

use super::Error;


pub trait Commitment: Sized {
    fn commitment_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error>;
    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error>;
}


pub fn commitment_serialize<T: Commitment>(data: &T) -> Result<Vec<u8>, Error> {
    let mut encoder = io::Cursor::new(vec![]);
    data.commitment_serialize(&mut encoder)?;
    Ok(encoder.into_inner())
}

pub fn commitment_deserialize<T: Commitment>(data: &[u8]) -> Result<T, Error> {
    let mut decoder = io::Cursor::new(data);
    let rv = T::commitment_deserialize(&mut decoder)?;
    let consumed = decoder.position() as usize;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
    }
}
