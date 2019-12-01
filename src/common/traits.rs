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

use std::ops::{Index, Range, RangeTo, RangeFrom, RangeFull};
use std::marker::PhantomData;

pub trait AsSlice: Eq {
    fn as_slice(&self) -> &[u8];
}

impl<T> AsSlice for T where T: Eq + Index<RangeFull, Output = [u8]> {
    fn as_slice(&self) -> &[u8] { &self[..] }
}


#[derive(Clone, PartialEq, Eq)]
pub struct Wrapper<T, Z>(T, PhantomData<Z>);

impl<T, Z> From<T> for Wrapper<T, Z> {
    #[inline]
    fn from(x: T) -> Self { Self(x, PhantomData::default()) }
}

impl<T, U, Z> Index<Range<usize>> for Wrapper<T, Z> where T: Index<Range<usize>, Output=[U]> {
    type Output = [U];

    #[inline]
    fn index(&self, index: Range<usize>) -> &[U] {
        &self.0[index]
    }
}

impl<T, U, Z> Index<RangeTo<usize>> for Wrapper<T, Z> where T: Index<RangeTo<usize>, Output=[U]> {
    type Output = [U];

    #[inline]
    fn index(&self, index: RangeTo<usize>) -> &[U] {
        &self.0[index]
    }
}

impl<T, U, Z> Index<RangeFrom<usize>> for Wrapper<T, Z> where T: Index<RangeFrom<usize>, Output=[U]> {
    type Output = [U];

    #[inline]
    fn index(&self, index: RangeFrom<usize>) -> &[U] {
        &self.0[index]
    }
}

impl<T, U, Z> Index<RangeFull> for Wrapper<T, Z> where T: Index<RangeFull, Output=[U]> {
    type Output = [U];

    #[inline]
    fn index(&self, _: RangeFull) -> &[U] {
        &self.0[..]
    }
}
