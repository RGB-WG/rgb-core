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

use super::{blind::OutpointHash, blind::OutpointReveal, Network, ShortId};
use crate::strict_encoding::{self, Error, StrictDecode, StrictEncode};
use bitcoin::hashes::{hash160, sha256, sha256d};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{secp256k1, util::bip32, OutPoint, Txid, XpubIdentifier};
use std::io;

impl strict_encoding::Strategy for Txid {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for OutpointHash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for XpubIdentifier {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}

impl strict_encoding::Strategy for sha256::Hash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for sha256d::Hash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for hash160::Hash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}

impl strict_encoding::Strategy for PartiallySignedTransaction {
    type Strategy = strict_encoding::strategies::BitcoinConsensus;
}

impl StrictEncode for secp256k1::PublicKey {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.serialize())?)
    }
}

impl StrictDecode for secp256k1::PublicKey {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        let mut buf = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::from_slice(&buf)
            .map_err(|_| Error::DataIntegrityError("invalid public key data".to_string()))?)
    }
}

impl StrictEncode for secp256k1::Signature {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        Ok(e.write(&self.serialize_compact())?)
    }
}

impl StrictDecode for secp256k1::Signature {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        let mut buf = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::from_compact(&buf).map_err(|_| {
            Error::DataIntegrityError("Invalid secp256k1 signature data".to_string())
        })?)
    }
}

impl StrictEncode for bitcoin::PublicKey {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        Ok(if self.compressed {
            e.write(&self.key.serialize())?
        } else {
            e.write(&self.key.serialize_uncompressed())?
        })
    }
}

impl StrictDecode for bitcoin::PublicKey {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        let marker = u8::strict_decode(&mut d)?;
        match marker {
            0x04 => {
                let mut buf = [0u8; secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
                buf[0] = marker;
                d.read_exact(&mut buf[1..])?;
                Ok(Self::from_slice(&buf).map_err(|_| {
                    Error::DataIntegrityError("Wrong public key data sequence".to_string())
                })?)
            }
            0x03 | 0x02 => {
                let mut buf = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
                buf[0] = marker;
                d.read_exact(&mut buf[1..])?;
                Ok(Self::from_slice(&buf).map_err(|_| {
                    Error::DataIntegrityError("Wrong public key data sequence".to_string())
                })?)
            }
            invalid_flag => Err(Error::DataIntegrityError(format!(
                "Invalid public key encoding flag {}; must be either 0x02, 0x03 or 0x4",
                invalid_flag
            ))),
        }
    }
}

impl StrictEncode for bitcoin::Network {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        Ok(self.magic().strict_encode(&mut e)?)
    }
}

impl StrictDecode for bitcoin::Network {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        let magic = u32::strict_decode(&mut d)?;
        Ok(Self::from_magic(magic).ok_or(Error::ValueOutOfRange(
            "bitcoin::Network".to_string(),
            0..0,
            magic as u64,
        ))?)
    }
}

impl StrictEncode for Network {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
        Ok(self.as_magic().strict_encode(e)?)
    }
}

impl StrictDecode for Network {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
        Ok(Self::from_magic(u32::strict_decode(d)?))
    }
}

impl StrictEncode for ShortId {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
        self.into_u64().strict_encode(e)
    }
}

impl StrictDecode for ShortId {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
        Ok(Self::from(u64::strict_decode(d)?))
    }
}

impl StrictEncode for OutPoint {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        Ok(strict_encode_list!(e; self.txid, self.vout))
    }
}

impl StrictDecode for OutPoint {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        Ok(Self {
            txid: Txid::strict_decode(&mut d)?,
            vout: u32::strict_decode(&mut d)?,
        })
    }
}

impl StrictEncode for OutpointReveal {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        Ok(strict_encode_list!(e; self.blinding, self.txid, self.vout))
    }
}

impl StrictDecode for OutpointReveal {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        Ok(Self {
            blinding: u32::strict_decode(&mut d)?,
            txid: Txid::strict_decode(&mut d)?,
            vout: u16::strict_decode(&mut d)?,
        })
    }
}

impl StrictEncode for bip32::ChildNumber {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        let (t, index) = match self {
            bip32::ChildNumber::Normal { index } => (0u8, index),
            bip32::ChildNumber::Hardened { index } => (1u8, index),
        };
        Ok(strict_encode_list!(e; t, index))
    }
}

impl StrictDecode for bip32::ChildNumber {
    type Error = Error;

    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        let t = u8::strict_decode(&mut d)?;
        let index = u32::strict_decode(&mut d)?;
        Ok(match t {
            0 => bip32::ChildNumber::Normal { index },
            1 => bip32::ChildNumber::Hardened { index },
            x => Err(Error::EnumValueNotKnown(
                "bip32::ChildNumber".to_string(),
                x,
            ))?,
        })
    }
}

impl StrictEncode for bip32::DerivationPath {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        let buf: Vec<bip32::ChildNumber> =
            self.into_iter().map(bip32::ChildNumber::clone).collect();
        Ok(buf.strict_encode(&mut e)?)
    }
}

impl StrictDecode for bip32::DerivationPath {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        Ok(Self::from(Vec::<bip32::ChildNumber>::strict_decode(
            &mut d,
        )?))
    }
}

impl StrictEncode for bip32::ChainCode {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        Ok(e.write(self.as_bytes())?)
    }
}

impl StrictDecode for bip32::ChainCode {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf)?;
        Ok(Self::from(&buf[..]))
    }
}

impl StrictEncode for bip32::Fingerprint {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        Ok(e.write(self.as_bytes())?)
    }
}

impl StrictDecode for bip32::Fingerprint {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        let mut buf = [0u8; 4];
        d.read_exact(&mut buf)?;
        Ok(Self::from(&buf[..]))
    }
}

impl StrictEncode for bip32::ExtendedPubKey {
    type Error = Error;

    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        Ok(strict_encode_list!(e; self.network,
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            self.public_key,
            self.chain_code))
    }
}

impl StrictDecode for bip32::ExtendedPubKey {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        Ok(Self {
            network: bitcoin::Network::strict_decode(&mut d)?,
            depth: u8::strict_decode(&mut d)?,
            parent_fingerprint: bip32::Fingerprint::strict_decode(&mut d)?,
            child_number: bip32::ChildNumber::strict_decode(&mut d)?,
            public_key: bitcoin::PublicKey::strict_decode(&mut d)?,
            chain_code: bip32::ChainCode::strict_decode(&mut d)?,
        })
    }
}
