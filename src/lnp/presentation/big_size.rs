// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     rust-lightning contributors,
//     Rajarshi Maitra,
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

use amplify::Wrapper;
use bitcoin::consensus::ReadExt;
use std::io;

use super::encoding::{Error, LightningDecode, LightningEncode};

/// Lightning TLV uses a custom variable-length integer called BigSize. It is
/// similar to Bitcoin's variable-length integers except that it is serialized
/// in big-endian instead of little-endian.
///
/// BigSize specification is given at
/// https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#type-length-value-format
///
/// Like Bitcoin's variable-length integer, it exhibits ambiguity in that
/// certain values can be encoded in several different ways, which we must check
/// for at deserialization-time. Thus, if you're looking for an example of a
/// variable-length integer to use for your own project, move along, this is a
/// rather poor design.
#[derive(Wrapper, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, From)]
#[wrapper(
    FromStr,
    Display,
    Debug,
    Octal,
    LowerHex,
    UpperHex,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Shl,
    Shr,
    Not,
    BitAnd,
    BitOr,
    BitXor,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    RemAssign,
    ShlAssign,
    ShrAssign,
    BitAndAssign,
    BitOrAssign,
    BitXorAssign
)]
#[from(u8)]
#[from(u16)]
#[from(u32)]
#[from(u64)]
pub struct BigSize(u64);

impl From<usize> for BigSize {
    fn from(val: usize) -> Self {
        (val as u64).into()
    }
}

impl From<BigSize> for u8 {
    fn from(big_size: BigSize) -> Self {
        big_size.into_inner() as u8
    }
}

impl From<BigSize> for u16 {
    fn from(big_size: BigSize) -> Self {
        big_size.into_inner() as u16
    }
}

impl From<BigSize> for u32 {
    fn from(big_size: BigSize) -> Self {
        big_size.into_inner() as u32
    }
}

impl From<BigSize> for usize {
    fn from(big_size: BigSize) -> Self {
        big_size.into_inner() as usize
    }
}

impl LightningEncode for BigSize {
    fn lightning_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, io::Error> {
        let vec = match self.0 {
            0..=0xFC => vec![self.0 as u8],
            0xFD..=0xFFFF => {
                let mut result = (self.0 as u16).to_be_bytes().to_vec();
                result.insert(0, 0xFDu8);
                result
            }
            0x10000..=0xFFFFFFFF => {
                let mut result = (self.0 as u32).to_be_bytes().to_vec();
                result.insert(0, 0xFEu8);
                result
            }
            _ => {
                let mut result = (self.0 as u64).to_be_bytes().to_vec();
                result.insert(0, 0xFF);
                result
            }
        };
        e.write(&vec)?;
        Ok(vec.len())
    }
}

impl LightningDecode for BigSize {
    fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        match d.read_u8().map_err(|_| Error::BigSizeEof)? {
            0xFFu8 => {
                let mut x = [0u8; 8];
                d.read_exact(&mut x).map_err(|_| Error::BigSizeEof)?;
                let value = u64::from_be_bytes(x);
                if value < 0x100000000 {
                    Err(Error::BigSizeNotCanonical)
                } else {
                    Ok(BigSize(value as u64))
                }
            }
            0xFEu8 => {
                let mut x = [0u8; 4];
                d.read_exact(&mut x).map_err(|_| Error::BigSizeEof)?;
                let value = u32::from_be_bytes(x);
                if value < 0x10000 {
                    Err(Error::BigSizeNotCanonical)
                } else {
                    Ok(BigSize(value as u64))
                }
            }
            0xFDu8 => {
                let mut x = [0u8; 2];
                d.read_exact(&mut x).map_err(|_| Error::BigSizeEof)?;
                let value = u16::from_be_bytes(x);
                if value < 0xFD {
                    Err(Error::BigSizeNotCanonical)
                } else {
                    Ok(BigSize(value as u64))
                }
            }
            small => Ok(BigSize(small as u64)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Runs unit tests for BigSize structure.
    // Testing vectors taken from
    //https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#appendix-a-bigsize-test-vectors

    fn test_runner(value: u64, bytes: &[u8]) {
        let bigsize = BigSize(value);

        let encoded_bigsize = bigsize.lightning_serialize();

        assert_eq!(encoded_bigsize, bytes);

        let decoded_bigsize =
            BigSize::lightning_deserialize(&encoded_bigsize).unwrap();

        assert_eq!(decoded_bigsize, bigsize);
    }

    #[test]
    fn test_1() {
        test_runner(0, &[0x00]);
        test_runner(252, &[0xfc]);
        test_runner(253, &[0xfd, 0x00, 0xfd]);
        test_runner(65535, &[0xfd, 0xff, 0xff]);
        test_runner(65536, &[0xfe, 0x00, 0x01, 0x00, 0x00]);
        test_runner(4294967295, &[0xfe, 0xff, 0xff, 0xff, 0xff]);
        test_runner(
            4294967296,
            &[0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        );
        test_runner(
            18446744073709551615,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        );
    }

    #[should_panic(expected = "BigSizeNotCanonical")]
    #[test]
    fn test_canonical_value_error_1() {
        BigSize::lightning_deserialize(&[0xfd, 0x00, 0xfc]).unwrap();
    }

    #[should_panic(expected = "BigSizeNotCanonical")]
    #[test]
    fn test_canonical_value_error_2() {
        BigSize::lightning_deserialize(&[0xfe, 0x00, 0x00, 0xff, 0xff])
            .unwrap();
    }

    #[should_panic(expected = "BigSizeNotCanonical")]
    #[test]
    fn test_canonical_value_error_3() {
        BigSize::lightning_deserialize(&[
            0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        ])
        .unwrap();
    }

    #[should_panic(expected = "BigSizeEof")]
    #[test]
    fn test_eof_error_1() {
        BigSize::lightning_deserialize(&[0xfd, 0x00]).unwrap();
    }

    #[should_panic(expected = "BigSizeEof")]
    #[test]
    fn test_eof_error_2() {
        BigSize::lightning_deserialize(&[0xfe, 0xff, 0xff]).unwrap();
    }

    #[should_panic(expected = "BigSizeEof")]
    #[test]
    fn test_eof_error_3() {
        BigSize::lightning_deserialize(&[0xff, 0xff, 0xff, 0xff, 0xff])
            .unwrap();
    }

    #[should_panic(expected = "BigSizeEof")]
    #[test]
    fn test_eof_error_4() {
        BigSize::lightning_deserialize(&[0xfd]).unwrap();
    }

    #[should_panic(expected = "BigSizeEof")]
    #[test]
    fn test_eof_error_5() {
        BigSize::lightning_deserialize(&[0xfe]).unwrap();
    }

    #[should_panic(expected = "BigSizeEof")]
    #[test]
    fn test_eof_error_6() {
        BigSize::lightning_deserialize(&[0xff]).unwrap();
    }
}
