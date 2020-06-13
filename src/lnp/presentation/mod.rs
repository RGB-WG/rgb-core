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

mod encoding;
mod error;
pub mod message;
pub mod tlv;

pub use encoding::{Decode, Encode, Unmarshall, UnmarshallFn};
pub use error::{Error, UnknownTypeError};
pub use message::Message;

use amplify::Wrapper;
use core::ops::Rem;

pub trait EvenOdd
where
    Self: Wrapper,
    Self::Inner: Rem + From<u8>,
    <Self::Inner as Rem>::Output: Eq + From<u8>,
{
    #[inline]
    fn is_odd(&self) -> bool {
        !self.is_even()
    }

    #[inline]
    fn is_even(&self) -> bool {
        self.to_inner() % 2.into() == 0.into()
    }
}
