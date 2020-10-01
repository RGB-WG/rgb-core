// Rust language amplification library providing multiple generic trait
// implementations, type wrappers, derive macros and other language enhancements
//
// Written in 2019-2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//     Martin Habovstiak <martin.habovstiak@gmail.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::cmp::max;
use std::hash::{Hash, Hasher};
use std::io;
use std::ops::{BitAnd, BitOr, BitXor};

use crate::paradigms::strict_encoding::StrictDecode;
use crate::strict_encoding::StrictEncode;

/// A single feature flag, represented by it's number inside feature vector
pub type FlagNo = u16;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// Keeps a reference to a specific feature flag within [`Features`] vector
pub struct FlagRef<'a> {
    byte: &'a u8,
    bit: u8,
}

/// Structure holding a given set of features
#[derive(Clone)]
pub struct Features(Vec<u8>);

impl BitOr for Features {
    type Output = Self;
    fn bitor(self, mut rhs: Self) -> Self::Output {
        let mut lhs = self.shrunk();
        rhs.shrink();
        let size = max(lhs.capacity(), rhs.capacity());
        lhs.enlarge(size);
        rhs.enlarge(size);
        for i in 0..rhs.0.len() {
            rhs.0[i] = lhs.0[1] | rhs.0[i];
        }
        rhs
    }
}

impl BitAnd for Features {
    type Output = Self;
    fn bitand(self, mut rhs: Self) -> Self::Output {
        let mut lhs = self.shrunk();
        rhs.shrink();
        let size = max(lhs.capacity(), rhs.capacity());
        lhs.enlarge(size);
        rhs.enlarge(size);
        for i in 0..rhs.0.len() {
            rhs.0[i] = lhs.0[1] & rhs.0[i];
        }
        rhs
    }
}

impl BitXor for Features {
    type Output = Self;
    fn bitxor(self, mut rhs: Self) -> Self::Output {
        let mut lhs = self.shrunk();
        rhs.shrink();
        let size = max(lhs.capacity(), rhs.capacity());
        lhs.enlarge(size);
        rhs.enlarge(size);
        for i in 0..rhs.0.len() {
            rhs.0[i] = lhs.0[1] ^ rhs.0[i];
        }
        rhs
    }
}

impl Default for Features {
    fn default() -> Self {
        Features::new()
    }
}

impl PartialEq for Features {
    fn eq(&self, other: &Self) -> bool {
        self.shrunk().0 == other.shrunk().0
    }
}

impl Eq for Features {}

impl Hash for Features {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.shrunk().0.hash(state)
    }
}

impl StrictEncode for Features {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
        self.shrunk().0.strict_encode(e)
    }
}

impl StrictDecode for Features {
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
        Ok(Self(StrictDecode::strict_decode(d)?))
    }
}

impl Features {
    /// Constructs a features vector of zero feature flag set
    pub fn new() -> Features {
        Features(vec![])
    }

    /// Returns a shrunk copy of the self
    pub fn shrunk(&self) -> Self {
        let mut shrinked = self.clone();
        shrinked.shrink();
        shrinked
    }

    /// Creates an iterator for the current feature flags which have "set" state
    #[inline]
    pub fn iter(&self) -> AllSet {
        AllSet::new(&self)
    }

    /// Creates iterator over known set of the features
    #[inline]
    pub fn known_iter(&self, mut known: Features) -> FilteredIter {
        known.enlarge(self.capacity());
        FilteredIter::new(&self, known)
    }

    /// Creates iterator over unknown set of the features, i.e. features that
    /// **do not** match flags set in `known` parameter
    #[inline]
    pub fn unknown_iter(&self, mut known: Features) -> FilteredIter {
        known.enlarge(self.capacity());
        for byte in 1..self.capacity() {
            known.0[byte as usize] = !known.0[byte as usize];
        }
        FilteredIter::new(&self, known)
    }

    /// Returns how many features current structure can hold without
    /// re-allocation of the internal buffer
    #[inline]
    pub(self) fn capacity(&self) -> FlagNo {
        (self.0.len() * 8) as FlagNo
    }

    /// Changes the size of the internal buffer holding flags until it will be
    /// able to fit at least `upto` flags. Returns `true` if the operation was
    /// required and `false` if no resizing was needed and the internal buffer
    /// already had sufficient capacity
    #[inline]
    fn enlarge(&mut self, upto: FlagNo) -> bool {
        if upto <= self.capacity() {
            // We have nothing to do
            return false;
        }

        let old = self.0.clone();
        self.0 = vec![0u8; ((upto + 1) / 8) as usize];
        self.0.copy_from_slice(&old);
        return true;
    }

    /// Reduces the size of the internal buffer to the smallest capacity
    /// required to keep all currently set feature flags. Returns `true` if
    /// resize operation was required, or `false` otherwise, when the internal
    /// buffer already was of the smallest possible size
    #[inline]
    pub fn shrink(&mut self) -> bool {
        let capacity = self.capacity();
        let mut top = 1;
        while !self.is_set(capacity - top) && top < capacity {
            top += 1;
        }
        let used = ((top + 1) / 8) as usize;
        if used < self.0.len() {
            let old = self.0.clone();
            self.0 = vec![0u8; used as usize];
            self.0.copy_from_slice(&old[..used]);
            return true;
        }
        return false;
    }

    /// Returns reference to the byte responsible for the feature flag `flag_no`.
    /// If the maximum capacity is exceeded, returns [`Option::None`].
    #[inline]
    fn byte_at(&self, flag_no: FlagNo) -> Option<&u8> {
        if flag_no > self.capacity() {
            return None;
        }
        Some(&self.0[flag_no as usize / 8])
    }

    /// Returns mutable reference to the byte responsible for the feature flag
    /// `flag_no`. Does re-allocation of the internal buffer is the `flag_no`
    /// value exceeds current maximum flag capacity.
    #[inline]
    fn mut_byte_at(&mut self, flag_no: FlagNo) -> &mut u8 {
        self.enlarge(flag_no);
        &mut self.0[flag_no as usize / 8]
    }

    /// Returns whether a feature flag with `flag_no` is set (`true` or `false`)
    #[inline]
    pub fn is_set(&self, flag_no: FlagNo) -> bool {
        self.byte_at(flag_no)
            .map(|byte| (byte & (1 << (flag_no % 8))) > 0)
            .unwrap_or(false)
    }

    /// Sets the feature flag with number `flag_no`. Returns `true` if the flag
    /// was already set and `false` otherwise (i.e. previous value of the flag)
    #[inline]
    pub fn set(&mut self, flag_no: FlagNo) -> bool {
        let byte = self.mut_byte_at(flag_no);
        let mask = 1u8 << (flag_no % 8);
        let was = *byte & mask;
        *byte = *byte | mask;
        was > 0
    }

    /// Unsets the feature flag with number `flag_no`. Returns `true` if the
    /// flag was already set and `false` otherwise (i.e. previous value of the
    /// flag)
    #[inline]
    pub fn unset(&mut self, flag_no: FlagNo) -> bool {
        let byte = self.mut_byte_at(flag_no);
        let mask = 1u8 << (flag_no % 8);
        let was = *byte & mask;
        *byte = *byte & (!mask);
        was == 0
    }

    /// Inverts the feature flag with number `flag_no`
    #[inline]
    pub fn invert(&mut self, flag_no: FlagNo) {
        let byte = self.mut_byte_at(flag_no);
        let mask = 1u8 << (flag_no % 8);
        let was = *byte & mask;
        *byte = (*byte ^ was) | (mask ^ was);
    }
}

/// Iterator over all set feature flags
#[derive(Clone, PartialEq, Eq)]
pub struct AllSet<'a> {
    /// Reference to features object we iterate
    features: &'a Features,

    /// Offset of the last feature flag
    offset: FlagNo,
}

impl<'a> AllSet<'a> {
    /// Constructs an iterator over a given set of feature flags
    #[inline]
    pub fn new(features: &'a Features) -> Self {
        Self {
            features,
            offset: 0,
        }
    }
}

impl Iterator for AllSet<'_> {
    type Item = FlagNo;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.features.capacity() {
            if self.features.is_set(self.offset) {
                return Some(self.offset);
            }
            self.offset += 1;
        }
        None
    }
}

/// Iterator over a filtered set feature flags
#[derive(Clone, PartialEq, Eq)]
pub struct FilteredIter<'a> {
    /// Reference to features object we iterate
    features: &'a Features,

    /// Parameter defining a set of features which are known
    filter: Features,

    /// Offset of the last feature flag
    offset: FlagNo,
}

impl<'a> FilteredIter<'a> {
    /// Constructs an iterator over a given set of features with some filter for
    /// feature flags
    #[inline]
    pub fn new(features: &'a Features, filter: Features) -> Self {
        Self {
            features,
            filter,
            offset: 0,
        }
    }
}

impl Iterator for FilteredIter<'_> {
    type Item = FlagNo;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.features.capacity() {
            if self.features.is_set(self.offset) && self.filter.is_set(self.offset) {
                return Some(self.offset);
            }
            self.offset += 1;
        }
        None
    }
}
