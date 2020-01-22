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

use super::Error;

pub trait Network: Sized {
    fn network_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error>;
    fn network_deserialize<D: io::Read>(d: D) -> Result<Self, Error>;
}

/* We have to use custom implementations due to rust language limitations on default trait
   implementations */
// TODO: Re-implement it as a proc macro
#[macro_export]
macro_rules! network_serialize_from_commitment {
    ($type:ty) => {
        impl $crate::csv::serialize::network::Network for $type {
            #[inline]
            fn network_serialize<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, $crate::csv::serialize::Error> {
                use $crate::csv::serialize::commitment::Commitment;
                self.commitment_serialize(&mut e)
            }

            #[inline]
            fn network_deserialize<D: ::std::io::Read>(d: D) -> Result<Self, $crate::csv::serialize::Error> {
                use $crate::csv::serialize::commitment::Commitment;
                Self::commitment_deserialize(d)
            }
        }
    };
}

#[inline]
pub fn network_serialize<T: Network>(data: &T) -> Result<Vec<u8>, Error> {
    let mut encoder = io::Cursor::new(vec![]);
    data.network_serialize(&mut encoder)?;
    Ok(encoder.into_inner())
}

#[inline]
pub fn network_deserialize<T: Network>(data: &[u8]) -> Result<T, Error> {
    let mut decoder = io::Cursor::new(data);
    let rv = T::network_deserialize(&mut decoder)?;
    let consumed = decoder.position() as usize;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
    }
}
