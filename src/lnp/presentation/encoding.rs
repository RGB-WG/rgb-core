// LNP/BP Core Library implementing LNPBP specifications & standards
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

use core::any::Any;
use std::io;
use std::sync::Arc;

pub trait Encode {
    fn encode<E: io::Write>(&self, e: E) -> usize;
}

pub trait Decode: Sized {
    type Error: std::error::Error;
    fn decode<D: io::Read>(d: D) -> Result<Self, Self::Error>;
}

pub trait Unmarshall<R, T>
where
    R: io::Read,
{
    type Error: std::error::Error;
    fn unmarshall(&self, reader: R) -> Result<T, Self::Error>;
}

pub type UnmarshallFn<R: io::Read, E: ::std::error::Error> =
    fn(reader: &mut R) -> Result<Arc<dyn Any>, E>;
