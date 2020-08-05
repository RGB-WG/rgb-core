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

use std::io;

use bitcoin::hashes::{hash160, sha256, sha256d, sha512};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{secp256k1, util::bip32, OutPoint, Script, Txid, XpubIdentifier};

use super::{blind::OutpointHash, blind::OutpointReveal, Network, ShortId};
use crate::strict_encoding::{self, Error, StrictDecode, StrictEncode};

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
impl strict_encoding::Strategy for sha512::Hash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl strict_encoding::Strategy for hash160::Hash {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}

impl strict_encoding::Strategy for PartiallySignedTransaction {
    type Strategy = strict_encoding::strategies::BitcoinConsensus;
}

impl StrictEncode for Script {
    type Error = Error;

    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        Ok(self.to_bytes().strict_encode(e)?)
    }
}

impl StrictDecode for Script {
    type Error = Error;

    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
        Ok(Self::from(Vec::<u8>::strict_decode(d)?))
    }
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
        let mut buf = [0u8; secp256k1::constants::COMPACT_SIGNATURE_SIZE];
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
            magic as u128,
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
            blinding: u64::strict_decode(&mut d)?,
            txid: Txid::strict_decode(&mut d)?,
            vout: u32::strict_decode(&mut d)?,
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::bp::{short_id::Descriptor, BlockChecksum, TxChecksum};
    use bitcoin::{hashes::hex::FromHex, secp256k1::Message, BlockHash, Network};
    //use rand::{thread_rng, RngCore};
    use std::{convert::TryFrom, fmt::Debug, str::FromStr};

    fn encode_decode<T: StrictEncode + StrictDecode>(object: &T) -> Result<(T, usize), Error> {
        let mut encoded_object: Vec<u8> = vec![];
        let written = object.strict_encode(&mut encoded_object).unwrap();
        let decoded_object = T::strict_decode(&encoded_object[..]).unwrap();
        Ok((decoded_object, written))
    }

    fn test_suite<T: StrictEncode + StrictDecode + PartialEq + Debug>(
        object: &T,
        test_vec: &[u8],
        test_size: usize,
    ) -> Result<T, Error> {
        let mut encoded_object: Vec<u8> = vec![];
        let write_1 = object.strict_encode(&mut encoded_object).unwrap();
        let decoded_object = T::strict_decode(&encoded_object[..]).unwrap();
        assert_eq!(write_1, test_size);
        assert_eq!(decoded_object, *object);
        encoded_object.clear();
        let write_2 = decoded_object.strict_encode(&mut encoded_object).unwrap();
        assert_eq!(encoded_object, test_vec);
        assert_eq!(write_2, test_size);
        Ok(decoded_object)
    }

    #[test]
    fn test_encoding_network() {
        let mainnet_bytes = &[0xF9u8, 0xBEu8, 0xB4u8, 0xD9u8][..];
        let testnet_bytes = &[0x0Bu8, 0x11u8, 0x09u8, 0x07u8][..];
        let regtest_bytes = &[0xFAu8, 0xBFu8, 0xB5u8, 0xDAu8][..];
        let signet_bytes = &[0x7Eu8, 0xC6u8, 0x53u8, 0xA5u8][..];
        //let random_bytes = &[0xA1u8, 0xA2u8, 0xA3u8, 0xA4u8][..];

        let mainnet = Network::strict_decode(mainnet_bytes).unwrap();
        let testnet = Network::strict_decode(testnet_bytes).unwrap();
        let regtest = Network::strict_decode(regtest_bytes).unwrap();
        let signet = Network::strict_decode(signet_bytes).unwrap();
        //let other = Network::strict_decode(random_bytes).unwrap();

        assert!(test_suite(&mainnet, &mainnet_bytes, 4).is_ok());
        assert!(test_suite(&testnet, &testnet_bytes, 4).is_ok());
        assert!(test_suite(&regtest, &regtest_bytes, 4).is_ok());
        assert!(test_suite(&signet, &signet_bytes, 4).is_ok());
        // TODO: Network::Other failing the below assertion
        //assert!(test_suite(&other, &random_bytes, 4).is_ok());
    }

    #[test]
    fn test_encoding_pubkey() {
        static PK_BYTES_02: [u8; 33] = [
            0x02, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82, 0x6d, 0xc6, 0x1c,
            0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32,
            0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        static PK_BYTES_03: [u8; 33] = [
            0x03, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82, 0x6d, 0xc6, 0x1c,
            0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32,
            0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        static PK_BYTES_04: [u8; 65] = [
            0x04, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82, 0x6d, 0xc6, 0x1c,
            0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32,
            0x5a, 0x0f, 0x46, 0x79, 0xef, 0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4, 0xf5,
            0xc7, 0x9d, 0x19, 0xeb, 0xfa, 0x57, 0xda, 0x7c, 0xff, 0x3a, 0xff, 0x6e, 0x81, 0x9e,
            0x4e, 0xe9, 0x71, 0xd8, 0x6b, 0x5e, 0x61, 0x87, 0x5d,
        ];
        static PK_BYTES_ONEKEY: [u8; 33] = [
            0x2, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0xb, 0x7, 0x2, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];

        let pubkey_02 = bitcoin::PublicKey::strict_decode(&PK_BYTES_02[..]).unwrap();
        let pubkey_03 = bitcoin::PublicKey::strict_decode(&PK_BYTES_03[..]).unwrap();
        let pubkey_04 = bitcoin::PublicKey::strict_decode(&PK_BYTES_04[..]).unwrap();
        let pubkey_onekey = bitcoin::PublicKey::strict_decode(&PK_BYTES_ONEKEY[..]).unwrap();

        assert!(test_suite(&pubkey_02, &PK_BYTES_02, 33).is_ok());
        assert!(test_suite(&pubkey_03, &PK_BYTES_03, 33).is_ok());
        assert!(test_suite(&pubkey_04, &PK_BYTES_04, 65).is_ok());
        assert!(test_suite(&pubkey_onekey, &PK_BYTES_ONEKEY, 33).is_ok());
    }

    #[test]
    #[should_panic(expected = "UnexpectedEof")]
    fn test_garbagedata_pubkey() {
        static PK_BYTES_04: [u8; 60] = [
            0x04, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82, 0x6d, 0xc6, 0x1c,
            0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32,
            0x5a, 0x0f, 0x46, 0x79, 0xef, 0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4, 0xf5,
            0xc7, 0x9d, 0x19, 0xeb, 0xfa, 0x57, 0xda, 0x7c, 0xff, 0x3a, 0xff, 0x6e, 0x81, 0x9e,
            0x4e, 0xe9, 0x71, 0xd8,
        ];
        bitcoin::PublicKey::strict_decode(&PK_BYTES_04[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_grabagedata_pubkey2() {
        static PK_BYTES_02: [u8; 33] = [
            0xa5, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82, 0x6d, 0xc6, 0x1c,
            0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32,
            0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        bitcoin::PublicKey::strict_decode(&PK_BYTES_02[..]).unwrap();
    }

    #[test]
    fn test_encode_signature() {
        let s = secp256k1::Secp256k1::new();

        static SIG_BYTES: [u8; 64] = [
            0xdf, 0x2b, 0x7, 0x1, 0x5f, 0x2e, 0x1, 0x67, 0x74, 0x18, 0x7e, 0xad, 0x4a, 0x4f, 0x71,
            0x9a, 0x14, 0xe3, 0xe1, 0xad, 0xa1, 0x78, 0xd6, 0x6c, 0xce, 0xcf, 0xa4, 0x5b, 0x63,
            0x30, 0x70, 0xc2, 0x43, 0xa2, 0xd7, 0x6e, 0xe0, 0x5d, 0x63, 0x49, 0xfe, 0x98, 0x69,
            0x6c, 0x1c, 0x4d, 0x9a, 0x67, 0x11, 0x24, 0xde, 0x40, 0xc5, 0x31, 0x71, 0xa4, 0xb2,
            0x82, 0xb7, 0x69, 0xb7, 0xc6, 0x96, 0xcd,
        ];

        let privkey = secp256k1::SecretKey::from_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x40,
        ])
        .unwrap();

        let pubkey = secp256k1::PublicKey::from_secret_key(&s, &privkey);
        let msg = Message::from_slice(&[1u8; 32]).unwrap();

        let sig = s.sign(&msg, &privkey);
        let decoded_sig = test_suite(&sig, &SIG_BYTES, 64).unwrap();

        assert!(s.verify(&msg, &decoded_sig, &pubkey).is_ok());
    }

    #[test]
    #[should_panic(expected = "UnexpectedEof")]
    fn test_garbagedata_sig() {
        static SIG_BYTES: [u8; 58] = [
            0xdf, 0x2b, 0x7, 0x1, 0x5f, 0x2e, 0x1, 0x67, 0x74, 0x18, 0x7e, 0xad, 0x4a, 0x4f, 0x71,
            0x9a, 0x14, 0xe3, 0xe1, 0xad, 0xa1, 0x78, 0xd6, 0x6c, 0xce, 0xcf, 0xa4, 0x5b, 0x63,
            0x30, 0x70, 0xc2, 0x43, 0xa2, 0xd7, 0x6e, 0xe0, 0x5d, 0x63, 0x49, 0xfe, 0x98, 0x69,
            0x6c, 0x1c, 0x4d, 0x9a, 0x67, 0x11, 0x24, 0xde, 0x40, 0xc5, 0x31, 0x71, 0xa4, 0xb2,
            0x82,
        ];
        secp256k1::Signature::strict_decode(&SIG_BYTES[..]).unwrap();
    }

    #[test]
    fn test_encoding_shortids() {
        static SHORT_ONCHAINBLOCK: [u8; 8] = [0x0, 0x0, 0x0, 0x0, 0x20, 0x97, 0xcc, 0x9];
        static SHORT_ONCHAINTX: [u8; 8] = [0x0, 0x0, 0x5, 0x0, 0x20, 0x97, 0xcc, 0x9];
        static SHORT_ONCHAINTXINPUT: [u8; 8] = [0x6, 0x0, 0x5, 0x0, 0x20, 0x97, 0xcc, 0x9];
        static SHORT_ONCHAINTXOUT: [u8; 8] = [0x6, 0x0, 0x5, 0x80, 0x20, 0x97, 0xcc, 0x9];
        static SHORT_OFFCHAINTX: [u8; 8] = [0x0, 0x00, 0x53, 0xc6, 0x31, 0x13, 0xed, 0x80];
        static SHORT_OFFCHAINTXIN: [u8; 8] = [0x6, 0x0, 0x53, 0xc6, 0x31, 0x13, 0xed, 0x80];
        static SHORT_OFFCHAINTXOUT: [u8; 8] = [0x6, 0x0, 0x53, 0xc6, 0x31, 0x13, 0xed, 0x80];

        let block_checksum = BlockChecksum::from(
            BlockHash::from_hex("00000000000000000000fc48ad6e814097387355463c9ba4fdf8ecc2df34b52f")
                .unwrap(),
        );
        let tx_checksum = TxChecksum::from(
            Txid::from_hex("217861d1a487f8e7140b9da48385e3e5d64d1ffdcd8edf0afc6818ed1331c653")
                .unwrap(),
        );
        let height = 642199u32;
        let tx_index = 5u16;
        let input_index = 5u16;
        let output_index = 5u16;

        // Test OnchainBlock
        let des = Descriptor::OnchainBlock {
            block_height: height,
            block_checksum: block_checksum,
        };
        let short_id = ShortId::try_from(des).unwrap();
        // TOD0: descriptor validity fails
        //short_id.get_descriptor().try_validity().unwrap();
        assert!(test_suite(&short_id, &SHORT_ONCHAINBLOCK, 8).is_ok());

        // test ShortId for OnchainTransaction
        let des = Descriptor::OnchainTransaction {
            block_height: height,
            block_checksum: block_checksum,
            tx_index: tx_index,
        };
        let short_id = ShortId::try_from(des).unwrap();
        assert!(test_suite(&short_id, &SHORT_ONCHAINTX, 8).is_ok());

        // test ShortId for OnchainTxInput
        let des = Descriptor::OnchainTxInput {
            block_height: height,
            block_checksum: block_checksum,
            tx_index: tx_index,
            input_index: input_index,
        };
        let short_id = ShortId::try_from(des).unwrap();
        assert!(test_suite(&short_id, &SHORT_ONCHAINTXINPUT, 8).is_ok());

        // test ShortId for OnchainTxOutput
        let des = Descriptor::OnchainTxOutput {
            block_height: height,
            block_checksum: block_checksum,
            tx_index: tx_index,
            output_index: output_index,
        };
        let short_id = ShortId::try_from(des).unwrap();
        assert!(test_suite(&short_id, &SHORT_ONCHAINTXOUT, 8).is_ok());

        // test ShortId for OffchainTransaction
        let des = Descriptor::OffchainTransaction {
            tx_checksum: tx_checksum,
        };
        let short_id = ShortId::try_from(des).unwrap();
        assert!(test_suite(&short_id, &SHORT_OFFCHAINTX, 8).is_ok());

        // test ShortId for OffchainTxInput
        let des = Descriptor::OffchainTxInput {
            tx_checksum: tx_checksum,
            input_index: input_index,
        };
        let short_id = ShortId::try_from(des).unwrap();
        assert!(test_suite(&short_id, &SHORT_OFFCHAINTXIN, 8).is_ok());

        // test ShortId for OffchainTxOutput
        let des = Descriptor::OffchainTxOutput {
            tx_checksum: tx_checksum,
            output_index: output_index,
        };
        let short_id = ShortId::try_from(des).unwrap();
        assert!(test_suite(&short_id, &SHORT_OFFCHAINTXOUT, 8).is_ok());
    }

    #[test]
    fn test_encoding_outpoint() {
        static OUTPOINT: [u8; 36] = [
            0x53, 0xc6, 0x31, 0x13, 0xed, 0x18, 0x68, 0xfc, 0xa, 0xdf, 0x8e, 0xcd, 0xfd, 0x1f,
            0x4d, 0xd6, 0xe5, 0xe3, 0x85, 0x83, 0xa4, 0x9d, 0xb, 0x14, 0xe7, 0xf8, 0x87, 0xa4,
            0xd1, 0x61, 0x78, 0x21, 0x4, 0x0, 0x0, 0x0,
        ];
        static OUTPOINT_NULL: [u8; 36] = [
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff,
            0xff, 0xff,
        ];

        let txid =
            Txid::from_hex("217861d1a487f8e7140b9da48385e3e5d64d1ffdcd8edf0afc6818ed1331c653")
                .unwrap();
        let vout = 4u32;

        // test random and null outpoints
        let outpoint = OutPoint::new(txid, vout);
        let decoded_outpoint = test_suite(&outpoint, &OUTPOINT, 36).unwrap();
        let null = OutPoint::null();
        let decoded_null = test_suite(&null, &OUTPOINT_NULL, 36).unwrap();

        // test random and null rvealed outpoints
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
            0x53, 0xc6, 0x31, 0x13, 0xed, 0x18, 0x68, 0xfc, 0xa, 0xdf, 0x8e, 0xcd, 0xfd, 0x1f,
            0x4d, 0xd6, 0xe5, 0xe3, 0x85, 0x83, 0xa4, 0x9d, 0xb, 0x14, 0xe7, 0xf8, 0x87, 0xa4,
            0xd1, 0x61, 0x78, 0x21,
        ];
        OutPoint::strict_decode(&OUTPOINT[..]).unwrap();
    }

    #[test]
    fn test_encoding_extendedpubkey() {
        static EXT_PUBKEY1: [u8; 79] = [
            0xf9, 0xbe, 0xb4, 0xd9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x39,
            0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0, 0x2c,
            0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x5, 0xe, 0x2e, 0x8f, 0xf4, 0x9c,
            0x85, 0xc2, 0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56, 0x23, 0xfd, 0x1f, 0xe5,
            0x16, 0x7e, 0xac, 0x3a, 0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4, 0x2e, 0xe2,
            0x27, 0xff, 0xed, 0x37, 0xd5, 0x8,
        ];

        static EXT_PUBKEY2: [u8; 79] = [
            0xf9, 0xbe, 0xb4, 0xd9, 0x3, 0xbe, 0xf5, 0xa2, 0xf9, 0x1, 0x2, 0x0, 0x0, 0x0, 0x3,
            0x57, 0xbf, 0xe1, 0xe3, 0x41, 0xd0, 0x1c, 0x69, 0xfe, 0x56, 0x54, 0x30, 0x99, 0x56,
            0xcb, 0xea, 0x51, 0x68, 0x22, 0xfb, 0xa8, 0xa6, 0x1, 0x74, 0x3a, 0x1, 0x2a, 0x78, 0x96,
            0xee, 0x8d, 0xc2, 0x4, 0x46, 0x6b, 0x9c, 0xc8, 0xe1, 0x61, 0xe9, 0x66, 0x40, 0x9c,
            0xa5, 0x29, 0x86, 0xc5, 0x84, 0xf0, 0x7e, 0x9d, 0xc8, 0x1f, 0x73, 0x5d, 0xb6, 0x83,
            0xc3, 0xff, 0x6e, 0xc7, 0xb1, 0x50, 0x3f,
        ];

        let ext_pubkey1 = bip32::ExtendedPubKey::from_str("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8").unwrap();
        assert!(test_suite(&ext_pubkey1, &EXT_PUBKEY1, 79).is_ok());

        let ext_pubkey2 = bip32::ExtendedPubKey::from_str("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5").unwrap();
        assert!(test_suite(&ext_pubkey2, &EXT_PUBKEY2, 79).is_ok());
    }

    #[test]
    fn test_encoding_script() {
        static OP_RETURN: [u8; 40] = [
            0x26, 0x0, 0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0x20, 0x28, 0xf, 0x53, 0xf2, 0xd2, 0x16,
            0x63, 0xca, 0xc8, 0x9e, 0x6b, 0xd2, 0xad, 0x19, 0xed, 0xba, 0xbb, 0x4, 0x8c, 0xda, 0x8,
            0xe7, 0x3e, 0xd1, 0x9e, 0x92, 0x68, 0xd0, 0xaf, 0xea, 0x2a,
        ];
        static P2PK: [u8; 37] = [
            0x23, 0x0, 0x21, 0x2, 0x34, 0xe6, 0xa7, 0x9c, 0x53, 0x59, 0xc6, 0x13, 0x76, 0x2d, 0x53,
            0x7e, 0xe, 0x19, 0xd8, 0x6c, 0x77, 0xc1, 0x66, 0x6d, 0x8c, 0x9a, 0xb0, 0x50, 0xf2,
            0x3a, 0xcd, 0x19, 0x8e, 0x97, 0xf9, 0x3e, 0xac,
        ];

        static P2PKH: [u8; 27] = [
            0x19, 0x0, 0x76, 0xa9, 0x14, 0xaa, 0xca, 0x99, 0x1e, 0x29, 0x8a, 0xb8, 0x66, 0xab,
            0x60, 0xff, 0x45, 0x22, 0x1b, 0x45, 0x8c, 0x70, 0x33, 0x36, 0x5a, 0x88, 0xac,
        ];
        static P2SH: [u8; 25] = [
            0x17, 0x0, 0xa9, 0x14, 0x4d, 0xa3, 0x4a, 0xe8, 0x19, 0x9d, 0xbf, 0x68, 0x4f, 0xe9,
            0x7a, 0xf8, 0x70, 0x3f, 0x12, 0xe9, 0xf7, 0xaa, 0xe6, 0x62, 0x87,
        ];
        static P2WPKH: [u8; 24] = [
            0x16, 0x0, 0x0, 0x14, 0xaa, 0xca, 0x99, 0x1e, 0x29, 0x8a, 0xb8, 0x66, 0xab, 0x60, 0xff,
            0x45, 0x22, 0x1b, 0x45, 0x8c, 0x70, 0x33, 0x36, 0x5a,
        ];
        static P2WSH: [u8; 36] = [
            0x22, 0x0, 0x0, 0x20, 0x9d, 0x27, 0x71, 0x75, 0x73, 0x7f, 0xb5, 0x0, 0x41, 0xe7, 0x5f,
            0x64, 0x1a, 0xcf, 0x94, 0xd1, 0xd, 0xf9, 0xb9, 0x72, 0x1d, 0xb8, 0xff, 0xfe, 0x87,
            0x4a, 0xb5, 0x7f, 0x8f, 0xfb, 0x6, 0x2e,
        ];

        // OP_RETURN
        let op_return = Script::strict_decode(&OP_RETURN[..]).unwrap();
        let decode_opreturn = test_suite(&op_return, &OP_RETURN, 40).unwrap();
        assert!(decode_opreturn.is_op_return());

        // P2PK
        let p2pk = Script::strict_decode(&P2PK[..]).unwrap();
        let decode_p2pk = test_suite(&p2pk, &P2PK, 37).unwrap();
        assert!(decode_p2pk.is_p2pk());

        //P2PKH
        let p2pkh = Script::strict_decode(&P2PKH[..]).unwrap();
        let decode_p2pkh = test_suite(&p2pkh, &P2PKH, 27).unwrap();
        assert!(decode_p2pkh.is_p2pkh());

        //P2SH
        let p2sh = Script::strict_decode(&P2SH[..]).unwrap();
        let decode_p2sh = test_suite(&p2sh, &P2SH, 25).unwrap();
        assert!(decode_p2sh.is_p2sh());

        //P2WPKH
        let p2wpkh = Script::strict_decode(&P2WPKH[..]).unwrap();
        let decode_p2wpkh = test_suite(&p2wpkh, &P2WPKH, 24).unwrap();
        assert!(decode_p2wpkh.is_v0_p2wpkh());

        //P2WSH
        let p2wsh = Script::strict_decode(&P2WSH[..]).unwrap();
        let decoded_p2wsh = test_suite(&p2wsh, &P2WSH, 36).unwrap();
        assert!(decoded_p2wsh.is_v0_p2wsh());
    }
}
