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

use std::fmt::Display;
use std::io;
use std::str::FromStr;

use bitcoin::hashes::{hash160, hmac, sha256, sha256d, sha256t, sha512, Hash};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{
    secp256k1, util::bip32, BlockHash, OutPoint, PubkeyHash, Script,
    ScriptHash, SigHash, Transaction, TxIn, TxOut, Txid, WPubkeyHash,
    WScriptHash, Wtxid, XpubIdentifier,
};
#[cfg(feature = "ed25519-dalek")]
use ed25519_dalek::ed25519::signature::Signature;
use miniscript::descriptor::DescriptorSinglePub;
use miniscript::{policy, Miniscript, MiniscriptKey};

use super::bip32::{Decode, Encode};
use super::blind::OutpointHash;
use crate::strict_encoding::{self, Error, StrictDecode, StrictEncode};

impl strict_encoding::Strategy for Txid {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for Wtxid {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for BlockHash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for OutpointHash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for XpubIdentifier {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for PubkeyHash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for WPubkeyHash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for ScriptHash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for WScriptHash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for SigHash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}

impl strict_encoding::Strategy for sha256::Hash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for sha256d::Hash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl<T> strict_encoding::Strategy for sha256t::Hash<T>
where
    T: sha256t::Tag,
{
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for sha512::Hash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for hash160::Hash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl<T> strict_encoding::Strategy for hmac::Hmac<T>
where
    T: Hash,
{
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}

impl strict_encoding::Strategy for OutPoint {
    type Strategy = strict_encoding::strategies::BitcoinConsensus;
}
impl strict_encoding::Strategy for TxOut {
    type Strategy = strict_encoding::strategies::BitcoinConsensus;
}
impl strict_encoding::Strategy for TxIn {
    type Strategy = strict_encoding::strategies::BitcoinConsensus;
}
impl strict_encoding::Strategy for Transaction {
    type Strategy = strict_encoding::strategies::BitcoinConsensus;
}
impl strict_encoding::Strategy for PartiallySignedTransaction {
    type Strategy = strict_encoding::strategies::BitcoinConsensus;
}

impl StrictEncode for Script {
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        Ok(self.to_bytes().strict_encode(e)?)
    }
}

impl StrictDecode for Script {
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from(Vec::<u8>::strict_decode(d)?))
    }
}

#[cfg(feature = "ed25519-dalek")]
impl StrictEncode for ed25519_dalek::PublicKey {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.as_bytes()[..])?)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl StrictDecode for ed25519_dalek::PublicKey {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        d.read_exact(&mut buf)?;
        Ok(Self::from_bytes(&buf).map_err(|_| {
            Error::DataIntegrityError(
                "invalid Curve25519 public key data".to_string(),
            )
        })?)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl StrictEncode for ed25519_dalek::Signature {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.as_bytes())?)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl StrictDecode for ed25519_dalek::Signature {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        d.read_exact(&mut buf)?;
        Ok(Self::from_bytes(&buf).map_err(|_| {
            Error::DataIntegrityError(
                "invalid Ed25519 signature data".to_string(),
            )
        })?)
    }
}

impl StrictEncode for secp256k1::SecretKey {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self[..])?)
    }
}

impl StrictDecode for secp256k1::SecretKey {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::SECRET_KEY_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::from_slice(&buf).map_err(|_| {
            Error::DataIntegrityError("invalid private key data".to_string())
        })?)
    }
}

impl StrictEncode for secp256k1::PublicKey {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.serialize())?)
    }
}

impl StrictDecode for secp256k1::PublicKey {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::from_slice(&buf).map_err(|_| {
            Error::DataIntegrityError("invalid public key data".to_string())
        })?)
    }
}

impl StrictEncode for secp256k1::Signature {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.serialize_compact())?)
    }
}

impl StrictDecode for secp256k1::Signature {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::COMPACT_SIGNATURE_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::from_compact(&buf).map_err(|_| {
            Error::DataIntegrityError(
                "Invalid secp256k1 signature data".to_string(),
            )
        })?)
    }
}

impl StrictEncode for bitcoin::PublicKey {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(if self.compressed {
            e.write(&self.key.serialize())?
        } else {
            e.write(&self.key.serialize_uncompressed())?
        })
    }
}

impl StrictDecode for bitcoin::PublicKey {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
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
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(self.magic().strict_encode(&mut e)?)
    }
}

impl StrictDecode for bitcoin::Network {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let magic = u32::strict_decode(&mut d)?;
        Ok(Self::from_magic(magic).ok_or(Error::ValueOutOfRange(
            "bitcoin::Network",
            0..0,
            magic as u128,
        ))?)
    }
}

impl StrictEncode for bip32::ChildNumber {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let (t, index) = match self {
            bip32::ChildNumber::Normal { index } => (0u8, index),
            bip32::ChildNumber::Hardened { index } => (1u8, index),
        };
        Ok(strict_encode_list!(e; t, index))
    }
}

impl StrictDecode for bip32::ChildNumber {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
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
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let buf: Vec<bip32::ChildNumber> =
            self.into_iter().map(bip32::ChildNumber::clone).collect();
        Ok(buf.strict_encode(&mut e)?)
    }
}

impl StrictDecode for bip32::DerivationPath {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self::from(Vec::<bip32::ChildNumber>::strict_decode(
            &mut d,
        )?))
    }
}

impl StrictEncode for bip32::ChainCode {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(self.as_bytes())?)
    }
}

impl StrictDecode for bip32::ChainCode {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf)?;
        Ok(Self::from(&buf[..]))
    }
}

impl StrictEncode for bip32::Fingerprint {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(self.as_bytes())?)
    }
}

impl StrictDecode for bip32::Fingerprint {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 4];
        d.read_exact(&mut buf)?;
        Ok(Self::from(&buf[..]))
    }
}

impl StrictEncode for bip32::ExtendedPubKey {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.encode())?)
    }
}

impl StrictDecode for bip32::ExtendedPubKey {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 78];
        d.read_exact(&mut buf)?;
        Ok(bip32::ExtendedPubKey::decode(&buf).map_err(|_| {
            Error::DataIntegrityError(
                "Extended pubkey integrity is broken".to_string(),
            )
        })?)
    }
}

impl StrictEncode for bip32::ExtendedPrivKey {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.encode())?)
    }
}

impl StrictDecode for bip32::ExtendedPrivKey {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 78];
        d.read_exact(&mut buf)?;
        Ok(bip32::ExtendedPrivKey::decode(&buf).map_err(|_| {
            Error::DataIntegrityError(
                "Extended privkey integrity is broken".to_string(),
            )
        })?)
    }
}

impl StrictEncode for DescriptorSinglePub {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(strict_encode_list!(e; self.key, self.origin))
    }
}

impl StrictDecode for DescriptorSinglePub {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(strict_decode_self!(d; key, origin))
    }
}

impl<Pk> StrictEncode for policy::Concrete<Pk>
where
    Pk: MiniscriptKey,
{
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_string().strict_encode(e)
    }
}

impl<Pk> StrictDecode for policy::Concrete<Pk>
where
    Pk: MiniscriptKey,
    <Pk as FromStr>::Err: Display,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: Display,
{
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        String::strict_decode(d)?.parse().map_err(|_| {
            Error::DataIntegrityError(s!("Unparsable miniscript policy string"))
        })
    }
}

impl<Pk, Ctx> StrictEncode for Miniscript<Pk, Ctx>
where
    Pk: MiniscriptKey,
    Ctx: miniscript::ScriptContext,
{
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_string().strict_encode(e)
    }
}

impl<Pk, Ctx> StrictDecode for Miniscript<Pk, Ctx>
where
    Pk: MiniscriptKey,
    <Pk as FromStr>::Err: Display,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: Display,
    Ctx: miniscript::ScriptContext,
{
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        String::strict_decode(d)?.parse().map_err(|_| {
            Error::DataIntegrityError(s!("Unparsable miniscript string"))
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::{convert::TryFrom, str::FromStr};

    use bitcoin::{
        consensus, hashes::hex::FromHex, secp256k1::Message, BlockHash,
    };

    use super::*;
    use crate::bp::{blind::OutpointReveal, short_id, ShortId};
    use crate::strict_encoding::test::test_suite;

    pub(crate) fn encode_decode<T: StrictEncode + StrictDecode>(
        object: &T,
    ) -> Result<(T, usize), Error> {
        let mut encoded_object: Vec<u8> = vec![];
        let written = object.strict_encode(&mut encoded_object).unwrap();
        let decoded_object = T::strict_decode(&encoded_object[..]).unwrap();
        Ok((decoded_object, written))
    }

    #[test]
    fn test_encoding_network() {
        let mainnet_bytes = &[0xF9u8, 0xBEu8, 0xB4u8, 0xD9u8][..];
        let testnet_bytes = &[0x0Bu8, 0x11u8, 0x09u8, 0x07u8][..];
        let regtest_bytes = &[0xFAu8, 0xBFu8, 0xB5u8, 0xDAu8][..];

        let mainnet = bitcoin::Network::strict_decode(mainnet_bytes).unwrap();
        let testnet = bitcoin::Network::strict_decode(testnet_bytes).unwrap();
        let regtest = bitcoin::Network::strict_decode(regtest_bytes).unwrap();

        test_suite(&mainnet, &mainnet_bytes, 4);
        test_suite(&testnet, &testnet_bytes, 4);
        test_suite(&regtest, &regtest_bytes, 4);
    }

    #[test]
    #[should_panic]
    fn test_encoding_network_failure() {
        // Bitcoin Network structure do not support "Other" networks
        let random_bytes = &[0xA1u8, 0xA2u8, 0xA3u8, 0xA4u8][..];
        bitcoin::Network::strict_decode(random_bytes).unwrap();
    }

    #[test]
    fn test_encoding_pubkey() {
        static PK_BYTES_02: [u8; 33] = [
            0x02, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        static PK_BYTES_03: [u8; 33] = [
            0x03, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        static PK_BYTES_04: [u8; 65] = [
            0x04, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
            0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4, 0xf5, 0xc7, 0x9d,
            0x19, 0xeb, 0xfa, 0x57, 0xda, 0x7c, 0xff, 0x3a, 0xff, 0x6e, 0x81,
            0x9e, 0x4e, 0xe9, 0x71, 0xd8, 0x6b, 0x5e, 0x61, 0x87, 0x5d,
        ];
        static PK_BYTES_ONEKEY: [u8; 33] = [
            0x2, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
            0x62, 0x95, 0xce, 0x87, 0xb, 0x7, 0x2, 0x9b, 0xfc, 0xdb, 0x2d,
            0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];

        let pubkey_02 =
            bitcoin::PublicKey::strict_decode(&PK_BYTES_02[..]).unwrap();
        let pubkey_03 =
            bitcoin::PublicKey::strict_decode(&PK_BYTES_03[..]).unwrap();
        let pubkey_04 =
            bitcoin::PublicKey::strict_decode(&PK_BYTES_04[..]).unwrap();
        let pubkey_onekey =
            bitcoin::PublicKey::strict_decode(&PK_BYTES_ONEKEY[..]).unwrap();

        test_suite(&pubkey_02, &PK_BYTES_02, 33);
        test_suite(&pubkey_03, &PK_BYTES_03, 33);
        test_suite(&pubkey_04, &PK_BYTES_04, 65);
        test_suite(&pubkey_onekey, &PK_BYTES_ONEKEY, 33);
    }

    #[test]
    #[should_panic(expected = "UnexpectedEof")]
    fn test_garbagedata_pubkey() {
        static PK_BYTES_04: [u8; 60] = [
            0x04, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
            0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4, 0xf5, 0xc7, 0x9d,
            0x19, 0xeb, 0xfa, 0x57, 0xda, 0x7c, 0xff, 0x3a, 0xff, 0x6e, 0x81,
            0x9e, 0x4e, 0xe9, 0x71, 0xd8,
        ];
        bitcoin::PublicKey::strict_decode(&PK_BYTES_04[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_grabagedata_pubkey2() {
        static PK_BYTES_02: [u8; 33] = [
            0xa5, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        bitcoin::PublicKey::strict_decode(&PK_BYTES_02[..]).unwrap();
    }

    #[test]
    fn test_encode_signature() {
        let s = secp256k1::Secp256k1::new();

        static SIG_BYTES: [u8; 64] = [
            0xdf, 0x2b, 0x7, 0x1, 0x5f, 0x2e, 0x1, 0x67, 0x74, 0x18, 0x7e,
            0xad, 0x4a, 0x4f, 0x71, 0x9a, 0x14, 0xe3, 0xe1, 0xad, 0xa1, 0x78,
            0xd6, 0x6c, 0xce, 0xcf, 0xa4, 0x5b, 0x63, 0x30, 0x70, 0xc2, 0x43,
            0xa2, 0xd7, 0x6e, 0xe0, 0x5d, 0x63, 0x49, 0xfe, 0x98, 0x69, 0x6c,
            0x1c, 0x4d, 0x9a, 0x67, 0x11, 0x24, 0xde, 0x40, 0xc5, 0x31, 0x71,
            0xa4, 0xb2, 0x82, 0xb7, 0x69, 0xb7, 0xc6, 0x96, 0xcd,
        ];

        let privkey = secp256k1::SecretKey::from_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
            0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
        ])
        .unwrap();

        let pubkey = secp256k1::PublicKey::from_secret_key(&s, &privkey);
        let msg = Message::from_slice(&[1u8; 32]).unwrap();

        let sig = s.sign(&msg, &privkey);
        let decoded_sig = test_suite(&sig, &SIG_BYTES, 64);

        assert!(s.verify(&msg, &decoded_sig, &pubkey).is_ok());
    }

    #[test]
    #[should_panic(expected = "UnexpectedEof")]
    fn test_garbagedata_sig() {
        static SIG_BYTES: [u8; 58] = [
            0xdf, 0x2b, 0x7, 0x1, 0x5f, 0x2e, 0x1, 0x67, 0x74, 0x18, 0x7e,
            0xad, 0x4a, 0x4f, 0x71, 0x9a, 0x14, 0xe3, 0xe1, 0xad, 0xa1, 0x78,
            0xd6, 0x6c, 0xce, 0xcf, 0xa4, 0x5b, 0x63, 0x30, 0x70, 0xc2, 0x43,
            0xa2, 0xd7, 0x6e, 0xe0, 0x5d, 0x63, 0x49, 0xfe, 0x98, 0x69, 0x6c,
            0x1c, 0x4d, 0x9a, 0x67, 0x11, 0x24, 0xde, 0x40, 0xc5, 0x31, 0x71,
            0xa4, 0xb2, 0x82,
        ];
        secp256k1::Signature::strict_decode(&SIG_BYTES[..]).unwrap();
    }

    #[test]
    fn test_encoding_shortids() {
        static SHORT_ONCHAINBLOCK: [u8; 8] =
            [0x0, 0x0, 0x0, 0x0, 0x20, 0x97, 0xcc, 0x9];
        static SHORT_ONCHAINTX: [u8; 8] =
            [0x0, 0x0, 0x5, 0x0, 0x20, 0x97, 0xcc, 0x9];
        static SHORT_ONCHAINTXINPUT: [u8; 8] =
            [0x6, 0x0, 0x5, 0x0, 0x20, 0x97, 0xcc, 0x9];
        static SHORT_ONCHAINTXOUT: [u8; 8] =
            [0x6, 0x0, 0x5, 0x80, 0x20, 0x97, 0xcc, 0x9];
        static SHORT_OFFCHAINTX: [u8; 8] =
            [0x0, 0x00, 0x53, 0xc6, 0x31, 0x13, 0xed, 0x80];
        static SHORT_OFFCHAINTXIN: [u8; 8] =
            [0x6, 0x0, 0x53, 0xc6, 0x31, 0x13, 0xed, 0x80];
        static SHORT_OFFCHAINTXOUT: [u8; 8] =
            [0x6, 0x0, 0x53, 0xc6, 0x31, 0x13, 0xed, 0x80];

        let block_checksum = short_id::BlockChecksum::from(
            BlockHash::from_hex("00000000000000000000fc48ad6e814097387355463c9ba4fdf8ecc2df34b52f")
                .unwrap(),
        );
        let tx_checksum = short_id::TxChecksum::from(
            Txid::from_hex("217861d1a487f8e7140b9da48385e3e5d64d1ffdcd8edf0afc6818ed1331c653")
                .unwrap(),
        );
        let height = 642199u32;
        let tx_index = 5u16;
        let input_index = 5u16;
        let output_index = 5u16;

        // Test OnchainBlock
        let des = short_id::Descriptor::OnchainBlock {
            block_height: height,
            block_checksum: block_checksum,
        };
        let short_id = ShortId::try_from(des).unwrap();
        // TOD0: descriptor validity fails
        //short_id.get_descriptor().try_validity().unwrap();
        test_suite(&short_id, &SHORT_ONCHAINBLOCK, 8);

        // test ShortId for OnchainTransaction
        let des = short_id::Descriptor::OnchainTransaction {
            block_height: height,
            block_checksum: block_checksum,
            tx_index: tx_index,
        };
        let short_id = ShortId::try_from(des).unwrap();
        test_suite(&short_id, &SHORT_ONCHAINTX, 8);

        // test ShortId for OnchainTxInput
        let des = short_id::Descriptor::OnchainTxInput {
            block_height: height,
            block_checksum: block_checksum,
            tx_index: tx_index,
            input_index: input_index,
        };
        let short_id = ShortId::try_from(des).unwrap();
        test_suite(&short_id, &SHORT_ONCHAINTXINPUT, 8);

        // test ShortId for OnchainTxOutput
        let des = short_id::Descriptor::OnchainTxOutput {
            block_height: height,
            block_checksum: block_checksum,
            tx_index: tx_index,
            output_index: output_index,
        };
        let short_id = ShortId::try_from(des).unwrap();
        test_suite(&short_id, &SHORT_ONCHAINTXOUT, 8);

        // test ShortId for OffchainTransaction
        let des = short_id::Descriptor::OffchainTransaction {
            tx_checksum: tx_checksum,
        };
        let short_id = ShortId::try_from(des).unwrap();
        test_suite(&short_id, &SHORT_OFFCHAINTX, 8);

        // test ShortId for OffchainTxInput
        let des = short_id::Descriptor::OffchainTxInput {
            tx_checksum: tx_checksum,
            input_index: input_index,
        };
        let short_id = ShortId::try_from(des).unwrap();
        test_suite(&short_id, &SHORT_OFFCHAINTXIN, 8);

        // test ShortId for OffchainTxOutput
        let des = short_id::Descriptor::OffchainTxOutput {
            tx_checksum: tx_checksum,
            output_index: output_index,
        };
        let short_id = ShortId::try_from(des).unwrap();
        test_suite(&short_id, &SHORT_OFFCHAINTXOUT, 8);
    }

    #[test]
    fn test_encoding_outpoint() {
        static OUTPOINT: [u8; 36] = [
            0x53, 0xc6, 0x31, 0x13, 0xed, 0x18, 0x68, 0xfc, 0xa, 0xdf, 0x8e,
            0xcd, 0xfd, 0x1f, 0x4d, 0xd6, 0xe5, 0xe3, 0x85, 0x83, 0xa4, 0x9d,
            0xb, 0x14, 0xe7, 0xf8, 0x87, 0xa4, 0xd1, 0x61, 0x78, 0x21, 0x4,
            0x0, 0x0, 0x0,
        ];
        static OUTPOINT_NULL: [u8; 36] = [
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff,
        ];

        let txid = Txid::from_hex(
            "217861d1a487f8e7140b9da48385e3e5d64d1ffdcd8edf0afc6818ed1331c653",
        )
        .unwrap();
        let vout = 4u32;

        // test random and null outpoints
        let outpoint = OutPoint::new(txid, vout);
        let decoded_outpoint = test_suite(&outpoint, &OUTPOINT, 36);
        let null = OutPoint::null();
        let decoded_null = test_suite(&null, &OUTPOINT_NULL, 36);

        // test random and null revealed outpoints
        // test_suite cannot be used here because blinding factor is random.
        let outpoint_reveal = OutpointReveal::from(decoded_outpoint);
        let (decoded, written) = encode_decode(&outpoint_reveal).unwrap();
        assert_eq!(written, 44);
        assert_eq!(decoded, outpoint_reveal);

        let null = OutpointReveal::from(decoded_null);
        let (decoded, written) = encode_decode(&null).unwrap();
        assert_eq!(written, 44);
        assert_eq!(decoded, null);

        // test random and null outpoint hash
        // test_suite cannot be used here because blinding factor is random.
        let random = OutpointHash::from(decoded_outpoint);
        let (decoded, written) = encode_decode(&random).unwrap();
        assert_eq!(written, 32);
        assert_eq!(decoded, random);

        let null = OutpointHash::from(decoded_null);
        let (decoded_null, written) = encode_decode(&null).unwrap();
        assert_eq!(written, 32);
        assert_eq!(decoded_null, null);
    }

    #[test]
    #[should_panic(expected = "UnexpectedEof")]
    fn test_garbagedata_outpoint() {
        static OUTPOINT: [u8; 32] = [
            0x53, 0xc6, 0x31, 0x13, 0xed, 0x18, 0x68, 0xfc, 0xa, 0xdf, 0x8e,
            0xcd, 0xfd, 0x1f, 0x4d, 0xd6, 0xe5, 0xe3, 0x85, 0x83, 0xa4, 0x9d,
            0xb, 0x14, 0xe7, 0xf8, 0x87, 0xa4, 0xd1, 0x61, 0x78, 0x21,
        ];
        OutPoint::strict_decode(&OUTPOINT[..]).unwrap();
    }

    #[test]
    fn test_tx() {
        let tx_segwit_bytes = Vec::from_hex(
            "02000000000101595895ea20179de87052b4046dfe6fd515860505d6511a9004cf\
            12a1f93cac7c0100000000ffffffff01deb807000000000017a9140f3444e271620\
            c736808aa7b33e370bd87cb5a078702483045022100fb60dad8df4af2841adc0346\
            638c16d0b8035f5e3f3753b88db122e70c79f9370220756e6633b17fd2710e62634\
            7d28d60b0a2d6cbb41de51740644b9fb3ba7751040121028fa937ca8cba2197a37c\
            007176ed8941055d3bcb8627d085e94553e62f057dcc00000000"
        ).unwrap();
        let tx_legacy1_bytes = Vec::from_hex(
            "ffffff7f0100000000000000000000000000000000000000000000000000000000\
            000000000000000000ffffffff0100f2052a01000000434104678afdb0fe5548271\
            967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f355\
            04e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
        ).unwrap();
        let tx_legacy2_bytes = Vec::from_hex(
            "000000800100000000000000000000000000000000000000000000000000000000\
            000000000000000000ffffffff0100f2052a01000000434104678afdb0fe5548271\
            967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f355\
            04e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
        ).unwrap();

        let tx_segwit: Transaction =
            consensus::deserialize(&tx_segwit_bytes).unwrap();
        let tx_legacy1: Transaction =
            consensus::deserialize(&tx_legacy1_bytes).unwrap();
        let tx_legacy2: Transaction =
            consensus::deserialize(&tx_legacy2_bytes).unwrap();

        assert_eq!(
            strict_encoding::strict_serialize(&tx_segwit).unwrap(),
            tx_segwit_bytes
        );
        assert_eq!(
            strict_encoding::strict_serialize(&tx_legacy1).unwrap(),
            tx_legacy1_bytes
        );
        assert_eq!(
            strict_encoding::strict_serialize(&tx_legacy2).unwrap(),
            tx_legacy2_bytes
        );
        test_suite(&tx_segwit, &tx_segwit_bytes, tx_segwit_bytes.len());
        test_suite(&tx_legacy1, &tx_legacy1_bytes, tx_legacy1_bytes.len());
        test_suite(&tx_legacy2, &tx_legacy2_bytes, tx_legacy2_bytes.len());
    }

    #[test]
    fn test_txin() {
        let txin_bytes = Vec::from_hex(
            "a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece01\
            0000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71\
            bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b17\
            36ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc31\
            0711c06c7f3e097c9447c52ffffffff"
        ).unwrap();
        let txin: TxIn = consensus::deserialize(&txin_bytes).unwrap();
        assert_eq!(
            strict_encoding::strict_serialize(&txin).unwrap(),
            txin_bytes
        );
        test_suite(&txin, &txin_bytes, txin_bytes.len());
    }

    #[test]
    fn test_txout() {
        let txout_segwit_bytes = Vec::from_hex(
            "0000000000000000160014d9a1665bea770cb6ec4809943f1e8ad67a31191f",
        )
        .unwrap();
        let txout_legacy_bytes = Vec::from_hex(
            "000000000000000017a91413f5fb72e7a31fcac98df27c77217b02abdb47fd87",
        )
        .unwrap();

        let txout_segwit: TxOut =
            consensus::deserialize(&txout_segwit_bytes).unwrap();
        let txout_legacy: TxOut =
            consensus::deserialize(&txout_legacy_bytes).unwrap();

        assert_eq!(
            strict_encoding::strict_serialize(&txout_segwit).unwrap(),
            txout_segwit_bytes
        );
        assert_eq!(
            strict_encoding::strict_serialize(&txout_legacy).unwrap(),
            txout_legacy_bytes
        );
        test_suite(
            &txout_segwit,
            &txout_segwit_bytes,
            txout_segwit_bytes.len(),
        );
        test_suite(
            &txout_legacy,
            &txout_legacy_bytes,
            txout_legacy_bytes.len(),
        );
    }

    #[test]
    fn test_psbt() {
        let psbt_bytes = Vec::from_hex(
            "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566\
            cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a91\
            4d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a914\
            3545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda50101000\
            00000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f\
            9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985fffff\
            fff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b4\
            0100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff020\
            0c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac\
            72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587024\
            7304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a\
            5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02\
            db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e\
            7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0\
            c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20\
            167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4\
            ea169393380734464f84f2ab300000000000000"
        ).unwrap();

        let psbt: PartiallySignedTransaction =
            consensus::deserialize(&psbt_bytes).unwrap();

        assert_eq!(
            strict_encoding::strict_serialize(&psbt).unwrap(),
            psbt_bytes
        );
        test_suite(&psbt, &psbt_bytes, psbt_bytes.len());
    }

    #[test]
    fn test_encoding_extendedpubkey() {
        static EXT_PUBKEY1: [u8; 78] = [
            4, 136, 178, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 135, 61, 255, 129, 192,
            47, 82, 86, 35, 253, 31, 229, 22, 126, 172, 58, 85, 160, 73, 222,
            61, 49, 75, 180, 46, 226, 39, 255, 237, 55, 213, 8, 3, 57, 163, 96,
            19, 48, 21, 151, 218, 239, 65, 251, 229, 147, 160, 44, 197, 19,
            208, 181, 85, 39, 236, 45, 241, 5, 14, 46, 143, 244, 156, 133, 194,
        ];

        static EXT_PUBKEY2: [u8; 78] = [
            4, 136, 178, 30, 3, 190, 245, 162, 249, 128, 0, 0, 2, 4, 70, 107,
            156, 200, 225, 97, 233, 102, 64, 156, 165, 41, 134, 197, 132, 240,
            126, 157, 200, 31, 115, 93, 182, 131, 195, 255, 110, 199, 177, 80,
            63, 3, 87, 191, 225, 227, 65, 208, 28, 105, 254, 86, 84, 48, 153,
            86, 203, 234, 81, 104, 34, 251, 168, 166, 1, 116, 58, 1, 42, 120,
            150, 238, 141, 194,
        ];

        let ext_pubkey1 = bip32::ExtendedPubKey::from_str(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ2\
            9ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        )
        .unwrap();
        test_suite(&ext_pubkey1, &EXT_PUBKEY1, 78);

        let ext_pubkey2 = bip32::ExtendedPubKey::from_str(
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJP\
            MM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        )
        .unwrap();
        test_suite(&ext_pubkey2, &EXT_PUBKEY2, 78);
    }

    #[test]
    fn test_encoding_script() {
        static OP_RETURN: [u8; 40] = [
            0x26, 0x0, 0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0x20, 0x28, 0xf,
            0x53, 0xf2, 0xd2, 0x16, 0x63, 0xca, 0xc8, 0x9e, 0x6b, 0xd2, 0xad,
            0x19, 0xed, 0xba, 0xbb, 0x4, 0x8c, 0xda, 0x8, 0xe7, 0x3e, 0xd1,
            0x9e, 0x92, 0x68, 0xd0, 0xaf, 0xea, 0x2a,
        ];
        static P2PK: [u8; 37] = [
            0x23, 0x0, 0x21, 0x2, 0x34, 0xe6, 0xa7, 0x9c, 0x53, 0x59, 0xc6,
            0x13, 0x76, 0x2d, 0x53, 0x7e, 0xe, 0x19, 0xd8, 0x6c, 0x77, 0xc1,
            0x66, 0x6d, 0x8c, 0x9a, 0xb0, 0x50, 0xf2, 0x3a, 0xcd, 0x19, 0x8e,
            0x97, 0xf9, 0x3e, 0xac,
        ];

        static P2PKH: [u8; 27] = [
            0x19, 0x0, 0x76, 0xa9, 0x14, 0xaa, 0xca, 0x99, 0x1e, 0x29, 0x8a,
            0xb8, 0x66, 0xab, 0x60, 0xff, 0x45, 0x22, 0x1b, 0x45, 0x8c, 0x70,
            0x33, 0x36, 0x5a, 0x88, 0xac,
        ];
        static P2SH: [u8; 25] = [
            0x17, 0x0, 0xa9, 0x14, 0x4d, 0xa3, 0x4a, 0xe8, 0x19, 0x9d, 0xbf,
            0x68, 0x4f, 0xe9, 0x7a, 0xf8, 0x70, 0x3f, 0x12, 0xe9, 0xf7, 0xaa,
            0xe6, 0x62, 0x87,
        ];
        static P2WPKH: [u8; 24] = [
            0x16, 0x0, 0x0, 0x14, 0xaa, 0xca, 0x99, 0x1e, 0x29, 0x8a, 0xb8,
            0x66, 0xab, 0x60, 0xff, 0x45, 0x22, 0x1b, 0x45, 0x8c, 0x70, 0x33,
            0x36, 0x5a,
        ];
        static P2WSH: [u8; 36] = [
            0x22, 0x0, 0x0, 0x20, 0x9d, 0x27, 0x71, 0x75, 0x73, 0x7f, 0xb5,
            0x0, 0x41, 0xe7, 0x5f, 0x64, 0x1a, 0xcf, 0x94, 0xd1, 0xd, 0xf9,
            0xb9, 0x72, 0x1d, 0xb8, 0xff, 0xfe, 0x87, 0x4a, 0xb5, 0x7f, 0x8f,
            0xfb, 0x6, 0x2e,
        ];

        // OP_RETURN
        let op_return = Script::strict_decode(&OP_RETURN[..]).unwrap();
        let decode_opreturn = test_suite(&op_return, &OP_RETURN, 40);
        assert!(decode_opreturn.is_op_return());

        // P2PK
        let p2pk = Script::strict_decode(&P2PK[..]).unwrap();
        let decode_p2pk = test_suite(&p2pk, &P2PK, 37);
        assert!(decode_p2pk.is_p2pk());

        //P2PKH
        let p2pkh = Script::strict_decode(&P2PKH[..]).unwrap();
        let decode_p2pkh = test_suite(&p2pkh, &P2PKH, 27);
        assert!(decode_p2pkh.is_p2pkh());

        //P2SH
        let p2sh = Script::strict_decode(&P2SH[..]).unwrap();
        let decode_p2sh = test_suite(&p2sh, &P2SH, 25);
        assert!(decode_p2sh.is_p2sh());

        //P2WPKH
        let p2wpkh = Script::strict_decode(&P2WPKH[..]).unwrap();
        let decode_p2wpkh = test_suite(&p2wpkh, &P2WPKH, 24);
        assert!(decode_p2wpkh.is_v0_p2wpkh());

        //P2WSH
        let p2wsh = Script::strict_decode(&P2WSH[..]).unwrap();
        let decoded_p2wsh = test_suite(&p2wsh, &P2WSH, 36);
        assert!(decoded_p2wsh.is_v0_p2wsh());
    }
}
