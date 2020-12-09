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
use std::convert::{TryFrom, TryInto};
use std::fmt::{
    self, Binary, Debug, Display, Formatter, LowerHex, Octal, UpperHex,
};
use std::hash::{Hash, Hasher};
use std::io;
use std::ops::{BitAnd, BitOr, BitXor};
use std::str::FromStr;

use crate::paradigms::strict_encoding::{Error, StrictDecode};
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
pub struct FlagVec(Vec<u8>);

impl BitOr for FlagVec {
    type Output = Self;
    fn bitor(self, mut rhs: Self) -> Self::Output {
        let mut lhs = self.shrunk();
        rhs.shrink();
        let size = max(lhs.capacity(), rhs.capacity());
        lhs.enlarge(size);
        rhs.enlarge(size);
        for i in 0..rhs.0.len() {
            rhs.0[i] = lhs.0[i] | rhs.0[i];
        }
        rhs
    }
}

impl BitAnd for FlagVec {
    type Output = Self;
    fn bitand(self, mut rhs: Self) -> Self::Output {
        let mut lhs = self.shrunk();
        rhs.shrink();
        let size = max(lhs.capacity(), rhs.capacity());
        lhs.enlarge(size);
        rhs.enlarge(size);
        for i in 0..rhs.0.len() {
            rhs.0[i] = lhs.0[i] & rhs.0[i];
        }
        rhs
    }
}

impl BitXor for FlagVec {
    type Output = Self;
    fn bitxor(self, mut rhs: Self) -> Self::Output {
        let mut lhs = self.shrunk();
        rhs.shrink();
        let size = max(lhs.capacity(), rhs.capacity());
        lhs.enlarge(size);
        rhs.enlarge(size);
        for i in 0..rhs.0.len() {
            rhs.0[i] = lhs.0[i] ^ rhs.0[i];
        }
        rhs
    }
}

impl Default for FlagVec {
    fn default() -> Self {
        FlagVec::new()
    }
}

impl PartialEq for FlagVec {
    fn eq(&self, other: &Self) -> bool {
        self.shrunk().0 == other.shrunk().0
    }
}

impl Eq for FlagVec {}

impl Hash for FlagVec {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.shrunk().0.hash(state)
    }
}

impl Debug for FlagVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut shrunk = self.clone();
        if f.alternate() {
            f.write_str("flags:")?;
            shrunk.shrink();
        }
        for b in 0..shrunk.capacity() {
            write!(f, "{}", if self.is_set(b) { '1' } else { '0' })?;
        }
        Ok(())
    }
}

impl Display for FlagVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut shrunk = self.clone();
        let (p, n) = if f.alternate() {
            shrunk.shrink();
            ('#', '_')
        } else {
            ('+', '-')
        };
        for b in 0..shrunk.capacity() {
            write!(f, "{}", if shrunk.is_set(b) { p } else { n })?;
        }
        Ok(())
    }
}

impl LowerHex for FlagVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut shrunk = self.clone();
        if f.alternate() {
            f.write_str("0x")?;
            shrunk.shrink();
        }
        for b in shrunk.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl UpperHex for FlagVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut shrunk = self.clone();
        if f.alternate() {
            f.write_str("0x")?;
            shrunk.shrink();
        }
        for b in shrunk.0 {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl Binary for FlagVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut shrunk = self.clone();
        if f.alternate() {
            f.write_str("0b")?;
            shrunk.shrink();
        }
        for b in shrunk.0 {
            write!(f, "{:08b}", b)?;
        }
        Ok(())
    }
}

impl Octal for FlagVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut shrunk = self.clone();
        if f.alternate() {
            f.write_str("0o")?;
            shrunk.shrink();
        }
        for b in shrunk.0 {
            write!(f, "{:03o}", b)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display(Debug)]
pub struct ParseError;

impl FromStr for FlagVec {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut vec = Vec::with_capacity(s.len());
        for c in s.chars() {
            vec.push(match c {
                '1' | '+' | '*' | '#' => 1,
                '0' | '-' | '!' | '_' => 0,
                ' ' | '\n' | '\t' | '\r' => continue,
                _ => return Err(ParseError),
            })
        }
        vec.try_into()
    }
}

impl TryFrom<Vec<u8>> for FlagVec {
    type Error = ParseError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&value[..])
    }
}

impl TryFrom<&[u8]> for FlagVec {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut vec = FlagVec::with_capacity(value.len() as FlagNo);
        for (i, v) in value.iter().enumerate() {
            match v {
                1 => vec.set(i as FlagNo),
                0 => false,
                _ => return Err(ParseError),
            };
        }
        Ok(vec)
    }
}

impl StrictEncode for FlagVec {
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.shrunk().0.strict_encode(e)
    }
}

impl StrictDecode for FlagVec {
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self(StrictDecode::strict_decode(d)?))
    }
}

impl FlagVec {
    fn bits_to_bytes(bits: FlagNo) -> usize {
        if bits == 0 {
            0
        } else {
            ((bits - 1) / 8 + 1) as usize
        }
    }

    /// Constructs a features vector of zero feature flag set
    pub fn new() -> FlagVec {
        FlagVec(vec![])
    }

    /// Constructs a features vector of `upto` feature flag in unset state
    pub fn with_capacity(upto: FlagNo) -> Self {
        if upto == 0 {
            FlagVec::default()
        } else {
            FlagVec(vec![0u8; Self::bits_to_bytes(upto)])
        }
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
    pub fn known_iter(&self, mut known: FlagVec) -> FilteredIter {
        known.enlarge(self.capacity());
        FilteredIter::new(&self, known)
    }

    /// Creates iterator over unknown set of the features, i.e. features that
    /// **do not** match flags set in `known` parameter
    #[inline]
    pub fn unknown_iter(&self, mut known: FlagVec) -> FilteredIter {
        known.enlarge(self.capacity());
        for byte in 0..self.0.len() {
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
        self.0 = vec![0u8; Self::bits_to_bytes(upto)];
        self.0[..old.len()].copy_from_slice(&old);
        return true;
    }

    /// Reduces the size of the internal buffer to the smallest capacity
    /// required to keep all currently set feature flags. Returns `true` if
    /// resize operation was required, or `false` otherwise, when the internal
    /// buffer already was of the smallest possible size
    #[inline]
    pub fn shrink(&mut self) -> bool {
        let capacity = self.capacity();
        if capacity == 0 {
            return false;
        }
        let mut top = 1;
        while top < capacity && !self.is_set(capacity - top) {
            top += 1;
        }
        let top = capacity - top;
        let used = Self::bits_to_bytes(top);
        if used < self.0.len() {
            let old = self.0.clone();
            self.0 = vec![0u8; used as usize];
            self.0.copy_from_slice(&old[..used]);
            return true;
        }
        return false;
    }

    /// Returns reference to the byte responsible for the feature flag
    /// `flag_no`. If the maximum capacity is exceeded, returns
    /// [`Option::None`].
    #[inline]
    fn byte_at(&self, flag_no: FlagNo) -> Option<&u8> {
        if flag_no >= self.capacity() {
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
    /// flag was set before and `false` otherwise (i.e. previous value of the
    /// flag)
    #[inline]
    pub fn unset(&mut self, flag_no: FlagNo) -> bool {
        let byte = self.mut_byte_at(flag_no);
        let mask = 1u8 << (flag_no % 8);
        let was = *byte & mask;
        *byte = *byte & (!mask);
        was > 0
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
    features: &'a FlagVec,

    /// Offset of the last feature flag
    offset: FlagNo,
}

impl<'a> AllSet<'a> {
    /// Constructs an iterator over a given set of feature flags
    #[inline]
    pub fn new(features: &'a FlagVec) -> Self {
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
            self.offset += 1;
            if self.features.is_set(self.offset - 1) {
                return Some(self.offset - 1);
            }
        }
        None
    }
}

/// Iterator over a filtered set feature flags
#[derive(Clone, PartialEq, Eq)]
pub struct FilteredIter<'a> {
    /// Reference to features object we iterate
    features: &'a FlagVec,

    /// Parameter defining a set of features which are known
    filter: FlagVec,

    /// Offset of the last feature flag
    offset: FlagNo,
}

impl<'a> FilteredIter<'a> {
    /// Constructs an iterator over a given set of features with some filter for
    /// feature flags
    #[inline]
    pub fn new(features: &'a FlagVec, filter: FlagVec) -> Self {
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
            self.offset += 1;
            if self.features.is_set(self.offset - 1)
                && self.filter.is_set(self.offset - 1)
            {
                return Some(self.offset - 1);
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_flag_init() {
        let empty_vec = Vec::<FlagNo>::new();

        let f1 = FlagVec::default();
        let f2 = FlagVec::new();
        let f3 = FlagVec::with_capacity(0);
        assert_eq!(f1, f2);
        assert_eq!(f1, f3);
        assert_eq!(f2, f3);
        assert_eq!(f1.capacity(), 0);
        assert_eq!(f1.iter().collect::<Vec<_>>(), empty_vec);
        assert_eq!(f2.capacity(), 0);
        assert_eq!(f2.iter().collect::<Vec<_>>(), empty_vec);
        assert_eq!(f3.capacity(), 0);
        assert_eq!(f3.iter().collect::<Vec<_>>(), empty_vec);

        let f4 = FlagVec::with_capacity(10);
        assert_eq!(f1, f4);
        assert_eq!(f4.capacity(), 16);
        assert_eq!(f4.iter().collect::<Vec<_>>(), empty_vec);
    }

    #[test]
    fn test_flag_capacity() {
        let mut f1 = FlagVec::with_capacity(10);
        assert_eq!(f1.capacity(), 16);
        let mut f2 = f1.clone();
        assert_eq!(f2.capacity(), 16);
        f2 = f1.shrunk();
        f1.shrink();
        assert_eq!(f1.capacity(), 0);
        assert_eq!(f1, f2);
        f1.enlarge(20);
        assert_eq!(f1.capacity(), 24);
    }

    #[test]
    fn test_flag_ops() {
        let mut f1 = FlagVec::with_capacity(10);
        assert_eq!(f1.is_set(33), false);
        assert_eq!(f1.capacity(), 16);
        assert_eq!(f1.set(2), false);
        assert_eq!(f1.is_set(2), true);
        assert_eq!(f1.unset(2), true);
        assert_eq!(f1.is_set(2), false);
        assert_eq!(f1.set(7), false);
        f1.shrink();
        assert_eq!(f1.capacity(), 8);
        assert_eq!(f1.set(22), false);
        assert_eq!(f1.is_set(22), true);
        assert_eq!(f1.capacity(), 24);
        assert_eq!(f1.invert(22), ());
        assert_eq!(f1.is_set(22), false);
        assert_eq!(f1.capacity(), 24);
        f1.shrink();
        assert_eq!(f1.capacity(), 8);
    }

    #[test]
    fn test_fmt() {
        let mut f1 = FlagVec::from_str("-0-\t#__1 \n--\r+* +!").unwrap();
        assert_eq!(f1.is_set(0), false);
        assert_eq!(f1.is_set(1), false);
        assert_eq!(f1.is_set(2), false);
        assert_eq!(f1.is_set(3), true);
        assert_eq!(f1.is_set(4), false);
        assert_eq!(f1.is_set(5), false);
        assert_eq!(f1.is_set(6), true);
        assert_eq!(f1.is_set(7), false);
        assert_eq!(f1.is_set(8), false);
        assert_eq!(f1.is_set(9), true);
        assert_eq!(f1.is_set(10), true);
        assert_eq!(f1.is_set(11), true);
        assert_eq!(f1.is_set(12), false);
        assert_eq!(f1.capacity(), 16);
        assert_eq!(format!("{}", f1), "---+--+--+++----");
        assert_eq!(format!("{:#}", f1), "___#__#__###____");
        assert_eq!(format!("{:?}", f1), "0001001001110000");
        assert_eq!(format!("{:x}", f1), "480e");
        assert_eq!(format!("{:X}", f1), "480E");
        assert_eq!(format!("{:b}", f1), "0100100000001110");
        assert_eq!(format!("{:o}", f1), "110016");
        f1.enlarge(22);
        assert_eq!(format!("{}", f1), "---+--+--+++------------");
        assert_eq!(format!("{:#}", f1), "___#__#__###____");
        assert_eq!(format!("{:?}", f1), "000100100111000000000000");
        assert_eq!(format!("{:#?}", f1), "flags:0001001001110000");
        assert_eq!(format!("{:#x}", f1), "0x480e");
        assert_eq!(format!("{:#X}", f1), "0x480E");
        assert_eq!(format!("{:#b}", f1), "0b0100100000001110");
        assert_eq!(format!("{:#o}", f1), "0o110016");
    }

    #[test]
    fn test_filtered() {
        let f1 = FlagVec::from_str("---+--+--+++-").unwrap();
        let f2 = FlagVec::from_str("-+++-+---+-++--+").unwrap();
        assert_eq!(
            f2.iter().collect::<Vec<_>>(),
            vec![1u16, 2, 3, 5, 9, 11, 12, 15]
        );
        assert_eq!(
            f2.known_iter(f1.clone()).collect::<Vec<_>>(),
            vec![3u16, 9, 11]
        );
        assert_eq!(
            f2.unknown_iter(f1).collect::<Vec<_>>(),
            vec![1u16, 2, 5, 12, 15]
        );
    }

    #[test]
    fn test_binary_and() {
        let f1 = FlagVec::from_str("---+--+--+++-").unwrap();
        let f2 = FlagVec::from_str("-+++-+---+-++--+").unwrap();
        assert_eq!(
            f1.clone() & f2.clone(),
            FlagVec::from_str("---+-----+-+----").unwrap()
        );
    }

    #[test]
    fn test_binary_or() {
        let f1 = FlagVec::from_str("---+--+--+++-").unwrap();
        let f2 = FlagVec::from_str("-+++-+---+-++--+").unwrap();
        assert_eq!(
            f1.clone() | f2.clone(),
            FlagVec::from_str("-+++-++--++++--+").unwrap()
        );
    }

    #[test]
    fn test_binary_xor() {
        let f1 = FlagVec::from_str("---+--+--+++-").unwrap();
        let f2 = FlagVec::from_str("-+++-+---+-++--+").unwrap();
        assert_eq!(
            f1.clone() ^ f2.clone(),
            FlagVec::from_str("-++--++---+-+--+").unwrap()
        );
    }
}
