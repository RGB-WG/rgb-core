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


use core::borrow::{Borrow, BorrowMut};
use std::{
    ops::{Deref, DerefMut, Index, Range, RangeTo, RangeFrom, RangeFull},
    marker::PhantomData,
};


// TODO: Do a macro for simple wrapper type creations (automate phantom data generation)

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Wrapper<T, Z>(T, PhantomData<Z>);

impl<T, Z> Wrapper<T, Z> {
    #[inline]
    pub fn from_inner(inner: T) -> Self {
        Self::from(inner)
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T, Z> Borrow<T> for Wrapper<T, Z> {
    fn borrow(&self) -> &T {
        &self.0
    }
}

impl<T, Z> BorrowMut<T> for Wrapper<T, Z> {
    fn borrow_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T, Z> AsMut<T> for Wrapper<T, Z> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T, Z> AsRef<T> for Wrapper<T, Z> {
    #[inline]
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T, Z> Deref for Wrapper<T, Z> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, Z> DerefMut for Wrapper<T, Z> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

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
