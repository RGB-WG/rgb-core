// LNP/BP Core Library implementing LNPBP specifications & standards
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

pub trait AsSlice {
    fn as_slice(&self) -> &[u8];
}

impl<T> AsSlice for T where T: Index<RangeFull, Output = [u8]> {
    fn as_slice(&self) -> &[u8] { &self[..] }
}
