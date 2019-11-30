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

pub trait AsBytes: Eq + Index<RangeFull, Output = [u8]> {
    fn as_bytes(&self) -> &[u8];
}

impl<T> AsBytes for T where T: Eq + Index<RangeFull, Output = [u8]> {
    fn as_bytes(&self) -> &[u8] { &self[..] }
}


#[derive(Clone, PartialEq, Eq)]
pub struct Wrapper<T>(T);

impl<T> From<T> for Wrapper<T> {
    #[inline]
    fn from(x: T) -> Self { Self(x) }
}
/*
impl<T> Into<T> for Wrapper<T> {
    #[inline]
    fn into(self) -> T { self.0 }
}
*/