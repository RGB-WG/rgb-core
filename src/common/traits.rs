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

use std::ops::{Index, RangeFull};

pub trait AsBytes: Index<RangeFull, Output = [u8]> {
    fn as_bytes(&self) -> &[u8];
}

impl<T> AsBytes for T where T: Index<RangeFull, Output = [u8]> {
    fn as_bytes(&self) -> &[u8] { &self[..] }
}

pub trait Wrapper<T: Clone> {
    fn inner_ref(&self) -> &T;
}

#[macro_export]
macro_rules! impl_wrapper {
    ($type:ident, $inner:ident) => (
        #[derive(Clone, PartialEq, Eq)]
        pub struct $type($inner);
        impl Wrapper<$inner> for $type {
            #[inline]
            fn inner_ref(&self) -> &$inner { &self.0 }
        }
    )
}
