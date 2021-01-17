// LNP/BP Rust Library
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

//! This mod represents **atomic rational values** (or, simply just **value**),
//! it a value representing a portion of something whole with a certain fixed
//! level of precision (atomicity). Such values are commonly used to represent
//! some coins of fungible tokens, where each coin or token consists of an
//! integer number of atomic subdivisions of the total supply (like satoshis in
//! bitcoin represent just a portion, i.e. fixed-percision rational number, of
//! the total possible bitcoin supply). Such numbers demonstrate constant
//! properties regarding their total sum and, thus, can be made confidential
//! using elliptic curve homomorphic cryptography such as Pedesen commitments.

use core::cmp::Ordering;
use core::ops::Add;
use std::io;

// We do not import particular modules to keep aware with namespace prefixes
// that we do not use the standard secp256k1zkp library
pub use lnpbp::secp256k1zkp::pedersen;
use lnpbp::secp256k1zkp::rand::{Rng, RngCore};
use lnpbp::secp256k1zkp::{self};

use lnpbp::client_side_validation::{
    commit_strategy, CommitEncode, CommitEncodeWithStrategy, Conceal,
};
use lnpbp::commit_verify::CommitVerify;

use super::{ConfidentialState, RevealedState, SECP256K1_ZKP};

pub type AtomicValue = u64;

/// Proof for Pedersen commitment: a blinding key
pub type BlindingFactor = lnpbp::secp256k1zkp::key::SecretKey;

#[derive(Clone, PartialEq, Eq, Debug, Display, AsAny)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
pub struct Revealed {
    pub value: AtomicValue,
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serde_helpers::to_hex",
            deserialize_with = "serde_helpers::from_hex"
        )
    )]
    pub blinding: BlindingFactor,
}

impl Revealed {
    pub fn with_amount<R: Rng + RngCore>(
        amount: AtomicValue,
        rng: &mut R,
    ) -> Self {
        Self {
            value: amount,
            blinding: BlindingFactor::new(&SECP256K1_ZKP, rng),
        }
    }
}

impl RevealedState for Revealed {}

impl Conceal for Revealed {
    type Confidential = Confidential;

    fn conceal(&self) -> Confidential {
        Confidential::commit(self)
    }
}
impl CommitEncodeWithStrategy for Revealed {
    type Strategy = commit_strategy::UsingConceal;
}

impl PartialOrd for Revealed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.value.partial_cmp(&other.value) {
            None => None,
            Some(Ordering::Equal) => {
                self.blinding.0.partial_cmp(&other.blinding.0)
            }
            other => other,
        }
    }
}

impl Ord for Revealed {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.value.cmp(&other.value) {
            Ordering::Equal => self.blinding.0.cmp(&other.blinding.0),
            other => other,
        }
    }
}

#[derive(Clone, Debug, Display, AsAny, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
pub struct Confidential {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::bech32::to_bech32_str",
            deserialize_with = "crate::bech32::from_bech32_str"
        )
    )]
    pub commitment: pedersen::Commitment,
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::bech32::to_bech32_str",
            deserialize_with = "crate::bech32::from_bech32_str"
        )
    )]
    pub bulletproof: pedersen::RangeProof,
}

impl ConfidentialState for Confidential {}

impl CommitEncode for Confidential {
    fn commit_encode<E: io::Write>(self, mut e: E) -> usize {
        self.commitment.commit_encode(&mut e)
            + self.bulletproof.commit_encode(&mut e)
    }
}

impl PartialOrd for Confidential {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (&self.commitment.0[..]).partial_cmp(&other.commitment.0[..]) {
            None => None,
            Some(Ordering::Equal) => {
                self.bulletproof.proof[0..self.bulletproof.plen].partial_cmp(
                    &other.bulletproof.proof[0..other.bulletproof.plen],
                )
            }
            other => other,
        }
    }
}

impl Ord for Confidential {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.commitment.0.cmp(&other.commitment.0) {
            Ordering::Equal => self.bulletproof.proof[0..self.bulletproof.plen]
                .cmp(&other.bulletproof.proof[0..other.bulletproof.plen]),
            other => other,
        }
    }
}

// The normal notion of the equivalence operator is to compare the _value_
// behind any data structure. However, here we compare not the value we
// are committing to, but the commitment itself. This is different to the
// design of the original Bulletproof designers, but is appropriate for the
// goals of RGB project and client-side validation paradigm
impl PartialEq for Confidential {
    fn eq(&self, other: &Self) -> bool {
        let plen = self.bulletproof.plen;
        self.commitment.0.to_vec() == other.commitment.0.to_vec()
            && self.bulletproof.proof[..plen] == other.bulletproof.proof[..plen]
    }
}

impl CommitVerify<Revealed> for Confidential {
    fn commit(revealed: &Revealed) -> Self {
        let blinding = revealed.blinding.clone();
        let value = revealed.value;

        let commitment = SECP256K1_ZKP
            .commit(value, blinding.clone())
            .expect("Internal inconsistency in Grin secp256k1zkp library Pedersen commitments");
        let bulletproof = SECP256K1_ZKP.bullet_proof(
            value,
            blinding.clone(),
            blinding.clone(),
            blinding.clone(),
            None,
            None,
        );
        Confidential {
            commitment,
            bulletproof,
        }
    }
}

impl Eq for Confidential {}

impl Add<pedersen::Commitment> for Confidential {
    type Output = pedersen::Commitment;

    fn add(self, other: pedersen::Commitment) -> Self::Output {
        SECP256K1_ZKP
            .commit_sum(vec![self.commitment, other], vec![])
            .expect("Failed to add Pedersen commitments")
    }
}

impl Confidential {
    pub fn zero_pedersen_commitment() -> pedersen::Commitment {
        SECP256K1_ZKP
            .commit_value(0)
            .expect("Internal inconsistency in Grin secp256k1zkp library Pedersen commitments")
    }

    pub fn verify_bullet_proof(
        &self,
    ) -> Result<pedersen::ProofRange, secp256k1zkp::Error> {
        SECP256K1_ZKP.verify_bullet_proof(
            self.commitment.clone(),
            self.bulletproof.clone(),
            None,
        )
    }

    pub fn verify_commit_sum(
        positive: Vec<pedersen::Commitment>,
        negative: Vec<pedersen::Commitment>,
    ) -> bool {
        SECP256K1_ZKP.verify_commit_sum(positive, negative)
    }
}

mod strict_encoding {
    use super::*;
    use crate::data::strict_encoding::EncodingTag;
    use lnpbp::strict_encoding::{Error, StrictDecode, StrictEncode};
    use std::io;

    impl StrictEncode for Revealed {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            Ok(
                strict_encode_list!(e; EncodingTag::U64, self.value, self.blinding),
            )
        }
    }

    impl StrictDecode for Revealed {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let format = EncodingTag::strict_decode(&mut d)?;
            Ok(match format {
                EncodingTag::U64 => Self {
                    value: AtomicValue::strict_decode(&mut d)?,
                    blinding: BlindingFactor::strict_decode(&mut d)?,
                },
                _ => Err(Error::UnsupportedDataStructure(
                    "We support only homomorphic commitments to U64 data",
                ))?,
            })
        }
    }
}

// TODO: Remove this once bitcion will adopt new bitcoin_num crate
#[cfg(feature = "serde")]
pub(crate) mod serde_helpers {
    //! Serde serialization helpers

    use bitcoin::hashes::hex::{FromHex, ToHex};
    use lnpbp::secp256k1zkp;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes `buffer` to a lowercase hex string.
    pub fn to_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serializer.serialize_str(&buffer.as_ref().to_hex())
    }

    /// Deserializes a lowercase hex string to a `Vec<u8>`.
    pub fn from_hex<'de, D>(
        deserializer: D,
    ) -> Result<secp256k1zkp::SecretKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|string| {
            secp256k1zkp::SecretKey::from_slice(
                &crate::contract::SECP256K1_ZKP,
                &Vec::<u8>::from_hex(&string).map_err(|_| {
                    D::Error::custom("wrong hex data for SecretKey")
                })?[..],
            )
            .map_err(|err| Error::custom(err.to_string()))
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::test::test_confidential;
    use super::*;
    use lnpbp::strict_encoding::{StrictDecode, StrictEncode};
    use lnpbp::test_helpers::*;

    static AMOUNT_65: [u8; 43] = [
        0x3, 0x41, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0xa6, 0x2b,
        0x27, 0xae, 0x5a, 0xf, 0x8c, 0x59, 0x5a, 0xfc, 0x8b, 0x55, 0xe5, 0x5f,
        0x72, 0xd7, 0x29, 0x1, 0x55, 0xfa, 0x68, 0x25, 0xe6, 0x3f, 0x62, 0x73,
        0x54, 0xab, 0xfd, 0x11, 0x2e, 0xf5,
    ];
    static CONFIDENTIAL_COMMITMENT: [u8; 67] = [
        33, 0, 9, 125, 114, 210, 222, 31, 130, 153, 18, 25, 95, 36, 15, 61,
        229, 94, 29, 100, 154, 171, 251, 47, 128, 135, 176, 29, 117, 78, 198,
        19, 187, 56, 251, 119, 47, 229, 218, 135, 170, 85, 106, 36, 197, 219,
        244, 78, 213, 210, 148, 100, 236, 123, 67, 180, 184, 7, 119, 195, 36,
        249, 250, 21, 247, 143, 218,
    ];
    static CONFIDENTIAL_AMOUNT: [u8; 712] = [
        0x21, 0x0, 0x9, 0x7d, 0x72, 0xd2, 0xde, 0x1f, 0x82, 0x99, 0x12, 0x19,
        0x5f, 0x24, 0xf, 0x3d, 0xe5, 0x5e, 0x1d, 0x64, 0x9a, 0xab, 0xfb, 0x2f,
        0x80, 0x87, 0xb0, 0x1d, 0x75, 0x4e, 0xc6, 0x13, 0xbb, 0x38, 0xfb, 0xa3,
        0x2, 0xe5, 0x88, 0x54, 0x82, 0xd, 0xaa, 0x2e, 0x54, 0xd1, 0x7e, 0xc1,
        0x46, 0xc0, 0xbe, 0x33, 0x1d, 0x39, 0xb, 0x0, 0x39, 0x32, 0xbd, 0x9c,
        0x16, 0x7e, 0x90, 0x70, 0x39, 0xbd, 0x30, 0xa0, 0xb7, 0x1, 0xfc, 0xa7,
        0x3b, 0xbd, 0x64, 0x69, 0xab, 0xd6, 0x5e, 0x56, 0xeb, 0x8f, 0x63, 0x4e,
        0xeb, 0x4e, 0xa7, 0xc4, 0x39, 0xe2, 0xf1, 0x74, 0x2c, 0x27, 0x17, 0xd,
        0xd2, 0x83, 0xfa, 0x30, 0x1b, 0x9, 0x3f, 0xb, 0xef, 0xce, 0x5e, 0x8d,
        0xab, 0xb0, 0xc5, 0xab, 0x5, 0x85, 0x25, 0xf3, 0xb6, 0xc2, 0xe4, 0xac,
        0x9f, 0xdc, 0xc8, 0x1f, 0xe8, 0xb4, 0x76, 0x2, 0x70, 0x1c, 0x76, 0x61,
        0xc, 0xd, 0x87, 0x31, 0xb5, 0x21, 0x23, 0xf6, 0x68, 0xf6, 0x96, 0x66,
        0x1, 0xc1, 0xc3, 0xc7, 0x51, 0xc5, 0xe9, 0xb1, 0x27, 0x98, 0xcb, 0x78,
        0x82, 0x97, 0x9f, 0x3b, 0x21, 0xd2, 0x4e, 0xb6, 0xb4, 0x34, 0x5c, 0x84,
        0xa0, 0xe9, 0x85, 0x8, 0x71, 0x7c, 0x85, 0x33, 0x87, 0x79, 0x1f, 0x60,
        0xa4, 0xe1, 0x63, 0x6c, 0xbb, 0x88, 0xeb, 0x61, 0xca, 0xaf, 0xc5, 0xc7,
        0xab, 0xfd, 0xeb, 0x61, 0x44, 0xb9, 0xcd, 0x69, 0xb1, 0xa8, 0xf4, 0xcc,
        0x45, 0x6a, 0x84, 0x55, 0x43, 0x28, 0x2e, 0x4f, 0x40, 0x3, 0x8a, 0x93,
        0x3a, 0xd6, 0xd4, 0x79, 0xe5, 0x94, 0x41, 0x4c, 0xcf, 0xa7, 0xab, 0x53,
        0x5, 0x99, 0xe7, 0xc4, 0x2c, 0x93, 0xac, 0xd, 0x4, 0x79, 0xfb, 0xdc,
        0x34, 0xcd, 0xe3, 0xb0, 0x14, 0x98, 0x1a, 0x94, 0xbf, 0xfa, 0x82, 0x50,
        0xd7, 0x42, 0x67, 0x86, 0x83, 0xc5, 0x29, 0x97, 0x69, 0xa, 0xc9, 0x5a,
        0x12, 0x70, 0x77, 0xa0, 0x85, 0x3f, 0x65, 0xe9, 0x3, 0xe, 0x98, 0x6a,
        0xa4, 0x13, 0xdc, 0x57, 0xc5, 0x42, 0x14, 0x38, 0x2, 0x1f, 0x15, 0xeb,
        0x71, 0x86, 0xa, 0x6a, 0xc0, 0x8, 0x98, 0x14, 0xbd, 0xa7, 0x5e, 0xd6,
        0x7e, 0x85, 0x50, 0x5, 0x4b, 0xfd, 0x73, 0x8f, 0x5e, 0x46, 0x1b, 0x4d,
        0xab, 0x85, 0x3f, 0xda, 0x56, 0x6d, 0x67, 0xca, 0x34, 0x2c, 0xc8, 0x91,
        0xac, 0x61, 0xbc, 0xb1, 0xfa, 0xa0, 0x18, 0x9c, 0x95, 0x3a, 0xa1, 0xa5,
        0x27, 0x58, 0x1, 0x7, 0xf5, 0xbf, 0x9, 0x92, 0x9e, 0xc6, 0x91, 0xae,
        0xe0, 0x53, 0x4e, 0x84, 0x13, 0x36, 0x53, 0xd9, 0x4b, 0xd6, 0xf, 0xc,
        0x6a, 0xf0, 0x2f, 0x7d, 0xf6, 0x7d, 0xe2, 0x44, 0x13, 0xab, 0x0, 0xed,
        0x3b, 0xe8, 0x18, 0x97, 0x81, 0x56, 0x7a, 0x2a, 0x1, 0xd2, 0x73, 0x98,
        0x3e, 0x44, 0x80, 0xd4, 0x7d, 0xc9, 0x7c, 0x3, 0xc4, 0x63, 0xab, 0xc2,
        0x4d, 0x48, 0xb0, 0x1, 0xba, 0xe4, 0xfd, 0x6c, 0xb1, 0x13, 0x56, 0xaf,
        0xc6, 0xc4, 0xa5, 0x86, 0xf2, 0xa6, 0x9e, 0x10, 0x2f, 0x42, 0x64, 0x3a,
        0x66, 0x90, 0xf5, 0x3f, 0x4e, 0x29, 0x92, 0xbb, 0x7c, 0xce, 0x16, 0x9d,
        0x83, 0x14, 0x24, 0x39, 0x37, 0x16, 0x69, 0x52, 0xef, 0xa1, 0xed, 0xe0,
        0x49, 0x96, 0x6a, 0xc3, 0xc9, 0xf8, 0xbf, 0x74, 0xff, 0x50, 0xbc, 0x3c,
        0xf1, 0x96, 0x75, 0x63, 0x87, 0xfc, 0x74, 0xd9, 0xe9, 0xcf, 0xe1, 0x75,
        0x70, 0xf, 0xf9, 0x3f, 0xf2, 0xbb, 0xc, 0x42, 0xd4, 0x5e, 0x4b, 0x12,
        0x7a, 0xaf, 0x30, 0x34, 0xf2, 0x13, 0x13, 0x63, 0xd8, 0xad, 0xd2, 0xc0,
        0x74, 0xf5, 0xde, 0x1f, 0xf4, 0x32, 0xcc, 0x7e, 0xbf, 0x87, 0x4f, 0x49,
        0x82, 0x87, 0x93, 0xec, 0x3e, 0x35, 0x3, 0xbf, 0xa1, 0x40, 0xc0, 0xb,
        0xa9, 0xaf, 0x35, 0x83, 0x3c, 0xc6, 0x5, 0xf1, 0xa8, 0xd5, 0xe0, 0x64,
        0x9c, 0xd0, 0xf, 0xe2, 0x30, 0x20, 0x1c, 0xd4, 0xa5, 0x7c, 0xf8, 0x2a,
        0xfb, 0xc7, 0x89, 0xdb, 0xb9, 0x19, 0x7f, 0x6d, 0xbc, 0xf8, 0x91, 0xac,
        0x81, 0x5d, 0xe5, 0x51, 0xa8, 0x9f, 0x89, 0x88, 0xe, 0x14, 0x1, 0x49,
        0xe, 0x69, 0xb4, 0xf1, 0x4c, 0xc4, 0x2f, 0x4d, 0xe8, 0x4e, 0x41, 0x75,
        0x32, 0x3, 0xa7, 0x2, 0x2c, 0xf0, 0xb7, 0x9b, 0xe9, 0x4b, 0xfc, 0x97,
        0x94, 0xea, 0x85, 0xd2, 0x9b, 0x36, 0x9e, 0x2a, 0xac, 0x2c, 0x9c, 0x72,
        0x43, 0x52, 0x78, 0x20, 0x88, 0x3a, 0xf2, 0xa5, 0x97, 0x10, 0x5f, 0xcc,
        0xbc, 0x18, 0x35, 0x15, 0xde, 0x2f, 0x28, 0x4d, 0x56, 0x8d, 0x35, 0x10,
        0x5e, 0xdc, 0x47, 0xe4, 0x20, 0x8, 0x7e, 0xaa, 0x24, 0x7e, 0x8a, 0x54,
        0x46, 0xdd, 0x63, 0x7a, 0xc4, 0xfa, 0x82, 0x77, 0x8f, 0x49, 0x89, 0x14,
        0x72, 0x33, 0xf1, 0x7a, 0xd1, 0x31, 0xfe, 0x12, 0x29, 0x7, 0x7, 0x3d,
        0xca, 0xd8, 0xc4, 0xcf, 0x1a, 0xaa, 0xd7, 0xdd, 0x42, 0x15, 0xac, 0x9,
        0x91, 0x6e, 0xbd, 0xd8, 0xfa, 0x78, 0x58, 0xb6, 0x53, 0x6, 0x7d, 0xf1,
        0x6f, 0xaf, 0xd3, 0xa3, 0xd9, 0x81, 0xea, 0x35, 0x59, 0x4a, 0xb6, 0xd1,
        0x8e, 0x72, 0x0, 0x12, 0x67, 0xbf, 0xe, 0x42, 0x93, 0xbf, 0x1d, 0x10,
        0x75, 0xc0, 0xf6, 0x9c,
    ];

    static AMOUNT_64: [u8; 43] = [
        0x3, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0xab, 0xe8,
        0x9d, 0x73, 0xbd, 0x1c, 0x25, 0x6d, 0x3c, 0x94, 0x94, 0xda, 0x5, 0xcc,
        0x29, 0x7e, 0x34, 0xc3, 0xed, 0xfb, 0x6, 0xdb, 0x6f, 0xe4, 0xdf, 0x6f,
        0x28, 0x6e, 0x5d, 0xf6, 0xce, 0xfe,
    ];

    static COMMIT_SUM: [u8; 35] = [
        0x21, 0x0, 0x9, 0x36, 0x2d, 0xe0, 0xe6, 0x5f, 0x65, 0x31, 0xe9, 0x60,
        0x5, 0xcc, 0xf7, 0x15, 0x2c, 0x7d, 0xa9, 0x16, 0x8a, 0x2f, 0x32, 0x25,
        0x52, 0xa2, 0x9b, 0xe0, 0xb5, 0xc, 0x19, 0xc2, 0x4d, 0x98, 0x95,
    ];

    #[test]
    fn test_amount() {
        // Test encoding decoding
        test_encode!((AMOUNT_65, Revealed));
        test_encode!((CONFIDENTIAL_AMOUNT, Confidential));

        // Test commitment
        test_confidential::<Revealed>(
            &AMOUNT_65,
            &CONFIDENTIAL_AMOUNT,
            &CONFIDENTIAL_COMMITMENT,
        );

        // Test comparison
        let revealed_64 = Revealed::strict_decode(&AMOUNT_64[..]).unwrap();
        let old_revealed = Revealed::strict_decode(&AMOUNT_65[..]).unwrap();
        assert_eq!(revealed_64.cmp(&old_revealed), Ordering::Less);
        assert_eq!(
            revealed_64.partial_cmp(&old_revealed).unwrap(),
            Ordering::Less
        );
        let coded_conf =
            Confidential::strict_decode(&CONFIDENTIAL_AMOUNT[..]).unwrap();
        let old_conf = old_revealed.conceal();
        let new_conf = revealed_64.conceal();
        assert_eq!(coded_conf, old_conf);
        assert_ne!(old_conf, new_conf);
        assert_eq!(old_conf.cmp(&new_conf), Ordering::Greater);
        assert_eq!(old_conf.partial_cmp(&new_conf).unwrap(), Ordering::Greater);

        // Test confidential addition
        assert!(coded_conf.verify_bullet_proof().is_ok());
        let new_commit = new_conf.commitment;
        let sum = old_conf.add(new_commit);
        let commit_sum =
            secp256k1zkp::pedersen::Commitment::strict_decode(&COMMIT_SUM[..])
                .unwrap();
        assert_eq!(sum, commit_sum);
    }

    #[test]
    fn test_commit_sum() {
        let positive = [1u64, 2u64, 3u64, 4u64, 5u64];
        let negative = [7u64, 8u64];

        // Generate random blinding factors
        let mut rng = secp256k1zkp::rand::thread_rng();
        // We do not need the last one since it is auto-generated to
        // zero-balance the rest
        let count = positive.len() + negative.len() - 1;
        let mut blinding_factors = Vec::<_>::with_capacity(count + 1);
        for _ in 0..count {
            blinding_factors
                .push(BlindingFactor::new(&SECP256K1_ZKP, &mut rng));
        }

        let positive_factors = blinding_factors[..positive.len()].to_vec();
        let negative_factors = blinding_factors[positive.len()..].to_vec();

        let correction = SECP256K1_ZKP
            .blind_sum(positive_factors, negative_factors)
            .unwrap();

        blinding_factors.push(correction);

        // Create Revealed amounts with corrected blinding factors
        let mut amounts = positive.to_vec();
        amounts.extend(negative.iter());

        let commitments: Vec<secp256k1zkp::pedersen::Commitment> = amounts
            .into_iter()
            .zip(blinding_factors.iter())
            .map(|(amount, blinding_factor)| {
                Revealed {
                    value: amount,
                    blinding: blinding_factor.clone(),
                }
                .conceal()
                .commitment
            })
            .collect();

        assert!(Confidential::verify_commit_sum(
            commitments[..positive.len()].to_vec(),
            commitments[positive.len()..].to_vec()
        ));

        // Create Revealed amounts with wrong positive values
        let wrong_positive = [1u64, 5u64, 3u64, 4u64, 5u64];
        let mut amounts = wrong_positive.to_vec();
        amounts.extend(negative.iter());

        // Create commitments with wrong positive values
        let wrong_commitments: Vec<secp256k1zkp::pedersen::Commitment> =
            amounts
                .into_iter()
                .zip(blinding_factors.iter())
                .map(|(amount, blinding_factor)| {
                    Revealed {
                        value: amount,
                        blinding: blinding_factor.clone(),
                    }
                    .conceal()
                    .commitment
                })
                .collect();

        // Ensure commit sum verification fails for wrong positive values
        assert!(!Confidential::verify_commit_sum(
            wrong_commitments[..positive.len()].to_vec(),
            wrong_commitments[positive.len()..].to_vec()
        ));
    }

    #[test]
    fn test_zero_commmit() {
        let zero_commit = Confidential::zero_pedersen_commitment();

        let mut handmade_bytes = [0x21u8, 0x0u8, 0x08u8].to_vec();
        handmade_bytes.extend([0x0u8; 32].iter());
        let handmade_commit =
            secp256k1zkp::pedersen::Commitment::strict_decode(
                &handmade_bytes[..],
            )
            .unwrap();

        assert_eq!(handmade_commit, zero_commit);
    }

    #[test]
    #[should_panic(expected = "UnsupportedDataStructure")]
    fn test_revealed_panic() {
        Revealed::strict_decode(&CONFIDENTIAL_AMOUNT[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_garbage_conf() {
        let mut data = CONFIDENTIAL_AMOUNT.clone();
        data[0] = 0x36 as u8;
        Confidential::strict_decode(&data[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_pederson() {
        let mut bytes = COMMIT_SUM.clone().to_vec();
        bytes[0] = 0x23u8;
        bytes.append(&mut [0u8, 0u8].to_vec());
        secp256k1zkp::pedersen::Commitment::strict_decode(&bytes[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_blinding() {
        let blind = Revealed::strict_decode(&AMOUNT_64[..]).unwrap().blinding;

        let mut buff = vec![];
        blind.strict_encode(&mut buff).unwrap();

        buff[0] = 0x10u8;

        secp256k1zkp::key::SecretKey::strict_decode(&buff[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_rangeproof() {
        let proof = Confidential::strict_decode(&CONFIDENTIAL_AMOUNT[..])
            .unwrap()
            .bulletproof;

        let mut buff = vec![];
        proof.strict_encode(&mut buff).unwrap();

        let mut pad = vec![0u8; 4465];
        buff.append(&mut pad);
        buff[0] = 0x14u8;
        buff[1] = 0x14u8;

        secp256k1zkp::pedersen::RangeProof::strict_decode(&buff[..]).unwrap();
    }
}
