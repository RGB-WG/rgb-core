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

use core::cmp::Ordering;
use core::ops::Add;
use rand::{Rng, RngCore};

// We do not import particular modules to keep aware with namespace prefixes
// that we do not use the standard secp256k1zkp library
pub use secp256k1zkp::pedersen;
use secp256k1zkp::*;

use super::{data, ConfidentialState, RevealedState, SECP256K1_ZKP};
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, Conceal};
use crate::commit_verify::CommitVerify;

pub type Amount = u64;

/// Proof for Pedersen commitment: a blinding key
pub type BlindingFactor = secp256k1zkp::key::SecretKey;

#[derive(Clone, PartialEq, Eq, Debug, Display, AsAny)]
#[display_from(Debug)]
pub struct Revealed {
    pub amount: Amount,
    pub blinding: BlindingFactor,
}

impl Revealed {
    pub fn with_amount<R: Rng + RngCore>(amount: Amount, rng: &mut R) -> Self {
        // TODO: Use single shared instance
        Self {
            amount,
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
        match self.amount.partial_cmp(&other.amount) {
            None => None,
            Some(Ordering::Equal) => self.blinding.0.partial_cmp(&other.blinding.0),
            other => other,
        }
    }
}

impl Ord for Revealed {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.amount.cmp(&other.amount) {
            Ordering::Equal => self.blinding.0.cmp(&other.blinding.0),
            other => other,
        }
    }
}

#[derive(Clone, Debug, Display, AsAny)]
#[display_from(Debug)]
pub struct Confidential {
    pub commitment: pedersen::Commitment,
    pub bulletproof: pedersen::RangeProof,
}

impl ConfidentialState for Confidential {}

impl CommitEncodeWithStrategy for Confidential {
    type Strategy = commit_strategy::UsingStrict;
}

impl PartialOrd for Confidential {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (&self.commitment.0).partial_cmp(&other.commitment.0) {
            None => None,
            Some(Ordering::Equal) => self.bulletproof.proof[0..self.bulletproof.plen]
                .partial_cmp(&other.bulletproof.proof[0..other.bulletproof.plen]),
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
        let value = revealed.amount;

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

    pub fn verify_bullet_proof(&self) -> Result<pedersen::ProofRange, secp256k1zkp::Error> {
        SECP256K1_ZKP.verify_bullet_proof(self.commitment.clone(), self.bulletproof.clone(), None)
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
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use data::strict_encoding::EncodingTag;
    use std::io;

    mod zkp {
        use super::*;

        impl StrictEncode for BlindingFactor {
            type Error = Error;

            fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
                self.0.as_ref().strict_encode(e)
            }
        }

        impl StrictDecode for BlindingFactor {
            type Error = Error;

            fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
                let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);
                let data = Vec::<u8>::strict_decode(d)?;
                Self::from_slice(&secp, &data).map_err(|_| {
                    Error::DataIntegrityError(
                        "Wrong private key data in pedersen commitment private key".to_string(),
                    )
                })
            }
        }

        impl StrictEncode for secp256k1zkp::pedersen::Commitment {
            type Error = Error;

            #[inline]
            fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
                self.0.as_ref().strict_encode(e)
            }
        }

        impl StrictDecode for secp256k1zkp::pedersen::Commitment {
            type Error = Error;

            #[inline]
            fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
                let data = Vec::<u8>::strict_decode(d)?;
                if data.len() != secp256k1zkp::constants::PEDERSEN_COMMITMENT_SIZE {
                    Err(Error::DataIntegrityError(format!(
                        "Wrong size of Pedersen commitment: {}",
                        data.len()
                    )))?
                }
                Ok(Self::from_vec(data))
            }
        }

        impl StrictEncode for secp256k1zkp::pedersen::RangeProof {
            type Error = Error;

            #[inline]
            fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
                self.proof[..self.plen].as_ref().strict_encode(e)
            }
        }

        impl StrictDecode for secp256k1zkp::pedersen::RangeProof {
            type Error = Error;

            #[inline]
            fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
                use secp256k1zkp::constants::MAX_PROOF_SIZE;
                let data = Vec::<u8>::strict_decode(d)?;
                match data.len() {
                    len if len < MAX_PROOF_SIZE => {
                        let mut buf = [0; MAX_PROOF_SIZE];
                        buf[..len].copy_from_slice(&data);
                        Ok(Self {
                            proof: buf,
                            plen: len,
                        })
                    }
                    invalid_len => Err(Error::DataIntegrityError(format!(
                        "Wrong bulletproof data size: expected no more than {}, got {}",
                        MAX_PROOF_SIZE, invalid_len
                    ))),
                }
            }
        }
    }

    impl StrictEncode for Confidential {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e; self.commitment, self.bulletproof))
        }
    }

    impl StrictDecode for Confidential {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            Ok(Self {
                commitment: pedersen::Commitment::strict_decode(&mut d)?,
                bulletproof: pedersen::RangeProof::strict_decode(&mut d)?,
            })
        }
    }

    impl StrictEncode for Revealed {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e; EncodingTag::U64, self.amount, self.blinding))
        }
    }

    impl StrictDecode for Revealed {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let format = EncodingTag::strict_decode(&mut d)?;
            Ok(match format {
                EncodingTag::U64 => Self {
                    amount: Amount::strict_decode(&mut d)?,
                    blinding: BlindingFactor::strict_decode(&mut d)?,
                },
                _ => Err(Error::UnsupportedDataStructure(
                    "We support only homomorphic commitments to U64 data".to_string(),
                ))?,
            })
        }
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use core::fmt::{self, Formatter};
    use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
    use serde::ser::{SerializeStruct, Serializer};
    use serde::{Deserialize, Serialize};

    impl Serialize for Revealed {
        fn serialize<S>(
            &self,
            serializer: S,
        ) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
        where
            S: Serializer,
        {
            let mut state = serializer.serialize_struct("amount::Revealed", 2)?;
            state.serialize_field("amount", &self.amount)?;
            state.serialize_field("blinding", &self.blinding.0)?;
            state.end()
        }
    }

    impl Deserialize<'de> for Revealed {
        fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
        where
            D: Deserializer<'de>,
        {
            enum Field {
                Amount,
                Blinding,
            };

            impl<'de> Deserialize<'de> for Field {
                fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    struct FieldVisitor;

                    impl<'de> Visitor<'de> for FieldVisitor {
                        type Value = Field;

                        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                            formatter.write_str("`amount` or `blinding`")
                        }

                        fn visit_str<E>(self, value: &str) -> Result<Field, E>
                        where
                            E: de::Error,
                        {
                            match value {
                                "amount" => Ok(Field::Amount),
                                "blinding" => Ok(Field::Blinding),
                                _ => Err(de::Error::unknown_field(value, FIELDS)),
                            }
                        }
                    }

                    deserializer.deserialize_identifier(FieldVisitor)
                }
            }

            struct RevealedVisitor;
            impl<'de> Visitor<'de> for RevealedVisitor {
                type Value = Revealed;

                fn expecting(&self, formatter: &mut Formatter<'a>) -> fmt::Result {
                    formatter.write_str("struct Revealed")
                }

                fn visit_seq<A>(
                    self,
                    mut seq: A,
                ) -> Result<Self::Value, <A as SeqAccess<'de>>::Error>
                where
                    A: SeqAccess<'de>,
                {
                    Ok(Revealed {
                        amount: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(0, &self))?,
                        blinding: seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(0, &self))?,
                    })
                }

                fn visit_map<A>(
                    self,
                    mut map: A,
                ) -> Result<Self::Value, <A as MapAccess<'de>>::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut amount = None;
                    let mut blinding = None;
                    while let Some(key) = map.next_key()? {
                        match key {
                            Field::Amount => {
                                if amount.is_some() {
                                    return Err(de::Error::duplicate_field("amount"));
                                }
                                amount = Some(map.next_value()?);
                            }
                            Field::Blinding => {
                                if blinding.is_some() {
                                    return Err(de::Error::duplicate_field("blinding"));
                                }
                                blinding = Some(map.next_value()?);
                            }
                        }
                    }
                    let amount = amount.ok_or_else(|| de::Error::missing_field("amount"))?;
                    let blinding = secp256k1zkp::key::SecretKey(
                        blinding.ok_or_else(|| de::Error::missing_field("blinding"))?,
                    );
                    Ok(Revealed { amount, blinding })
                }
            }

            const FIELDS: &'static [&'static str] = &["amount", "blinding"];
            deserializer.deserialize_struct("amount::Revealed", FIELDS, RevealedVisitor)
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::test_helpers::*;
    use super::*;
    use crate::strict_encoding::{StrictDecode, StrictEncode};

    static AMOUNT_65: [u8; 43] = [
        0x3, 0x41, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0xa6, 0x2b, 0x27, 0xae, 0x5a, 0xf,
        0x8c, 0x59, 0x5a, 0xfc, 0x8b, 0x55, 0xe5, 0x5f, 0x72, 0xd7, 0x29, 0x1, 0x55, 0xfa, 0x68,
        0x25, 0xe6, 0x3f, 0x62, 0x73, 0x54, 0xab, 0xfd, 0x11, 0x2e, 0xf5,
    ];
    static CONFIDENTIAL_AMOUNT: [u8; 712] = [
        0x21, 0x0, 0x9, 0x7d, 0x72, 0xd2, 0xde, 0x1f, 0x82, 0x99, 0x12, 0x19, 0x5f, 0x24, 0xf,
        0x3d, 0xe5, 0x5e, 0x1d, 0x64, 0x9a, 0xab, 0xfb, 0x2f, 0x80, 0x87, 0xb0, 0x1d, 0x75, 0x4e,
        0xc6, 0x13, 0xbb, 0x38, 0xfb, 0xa3, 0x2, 0xe5, 0x88, 0x54, 0x82, 0xd, 0xaa, 0x2e, 0x54,
        0xd1, 0x7e, 0xc1, 0x46, 0xc0, 0xbe, 0x33, 0x1d, 0x39, 0xb, 0x0, 0x39, 0x32, 0xbd, 0x9c,
        0x16, 0x7e, 0x90, 0x70, 0x39, 0xbd, 0x30, 0xa0, 0xb7, 0x1, 0xfc, 0xa7, 0x3b, 0xbd, 0x64,
        0x69, 0xab, 0xd6, 0x5e, 0x56, 0xeb, 0x8f, 0x63, 0x4e, 0xeb, 0x4e, 0xa7, 0xc4, 0x39, 0xe2,
        0xf1, 0x74, 0x2c, 0x27, 0x17, 0xd, 0xd2, 0x83, 0xfa, 0x30, 0x1b, 0x9, 0x3f, 0xb, 0xef,
        0xce, 0x5e, 0x8d, 0xab, 0xb0, 0xc5, 0xab, 0x5, 0x85, 0x25, 0xf3, 0xb6, 0xc2, 0xe4, 0xac,
        0x9f, 0xdc, 0xc8, 0x1f, 0xe8, 0xb4, 0x76, 0x2, 0x70, 0x1c, 0x76, 0x61, 0xc, 0xd, 0x87,
        0x31, 0xb5, 0x21, 0x23, 0xf6, 0x68, 0xf6, 0x96, 0x66, 0x1, 0xc1, 0xc3, 0xc7, 0x51, 0xc5,
        0xe9, 0xb1, 0x27, 0x98, 0xcb, 0x78, 0x82, 0x97, 0x9f, 0x3b, 0x21, 0xd2, 0x4e, 0xb6, 0xb4,
        0x34, 0x5c, 0x84, 0xa0, 0xe9, 0x85, 0x8, 0x71, 0x7c, 0x85, 0x33, 0x87, 0x79, 0x1f, 0x60,
        0xa4, 0xe1, 0x63, 0x6c, 0xbb, 0x88, 0xeb, 0x61, 0xca, 0xaf, 0xc5, 0xc7, 0xab, 0xfd, 0xeb,
        0x61, 0x44, 0xb9, 0xcd, 0x69, 0xb1, 0xa8, 0xf4, 0xcc, 0x45, 0x6a, 0x84, 0x55, 0x43, 0x28,
        0x2e, 0x4f, 0x40, 0x3, 0x8a, 0x93, 0x3a, 0xd6, 0xd4, 0x79, 0xe5, 0x94, 0x41, 0x4c, 0xcf,
        0xa7, 0xab, 0x53, 0x5, 0x99, 0xe7, 0xc4, 0x2c, 0x93, 0xac, 0xd, 0x4, 0x79, 0xfb, 0xdc,
        0x34, 0xcd, 0xe3, 0xb0, 0x14, 0x98, 0x1a, 0x94, 0xbf, 0xfa, 0x82, 0x50, 0xd7, 0x42, 0x67,
        0x86, 0x83, 0xc5, 0x29, 0x97, 0x69, 0xa, 0xc9, 0x5a, 0x12, 0x70, 0x77, 0xa0, 0x85, 0x3f,
        0x65, 0xe9, 0x3, 0xe, 0x98, 0x6a, 0xa4, 0x13, 0xdc, 0x57, 0xc5, 0x42, 0x14, 0x38, 0x2,
        0x1f, 0x15, 0xeb, 0x71, 0x86, 0xa, 0x6a, 0xc0, 0x8, 0x98, 0x14, 0xbd, 0xa7, 0x5e, 0xd6,
        0x7e, 0x85, 0x50, 0x5, 0x4b, 0xfd, 0x73, 0x8f, 0x5e, 0x46, 0x1b, 0x4d, 0xab, 0x85, 0x3f,
        0xda, 0x56, 0x6d, 0x67, 0xca, 0x34, 0x2c, 0xc8, 0x91, 0xac, 0x61, 0xbc, 0xb1, 0xfa, 0xa0,
        0x18, 0x9c, 0x95, 0x3a, 0xa1, 0xa5, 0x27, 0x58, 0x1, 0x7, 0xf5, 0xbf, 0x9, 0x92, 0x9e,
        0xc6, 0x91, 0xae, 0xe0, 0x53, 0x4e, 0x84, 0x13, 0x36, 0x53, 0xd9, 0x4b, 0xd6, 0xf, 0xc,
        0x6a, 0xf0, 0x2f, 0x7d, 0xf6, 0x7d, 0xe2, 0x44, 0x13, 0xab, 0x0, 0xed, 0x3b, 0xe8, 0x18,
        0x97, 0x81, 0x56, 0x7a, 0x2a, 0x1, 0xd2, 0x73, 0x98, 0x3e, 0x44, 0x80, 0xd4, 0x7d, 0xc9,
        0x7c, 0x3, 0xc4, 0x63, 0xab, 0xc2, 0x4d, 0x48, 0xb0, 0x1, 0xba, 0xe4, 0xfd, 0x6c, 0xb1,
        0x13, 0x56, 0xaf, 0xc6, 0xc4, 0xa5, 0x86, 0xf2, 0xa6, 0x9e, 0x10, 0x2f, 0x42, 0x64, 0x3a,
        0x66, 0x90, 0xf5, 0x3f, 0x4e, 0x29, 0x92, 0xbb, 0x7c, 0xce, 0x16, 0x9d, 0x83, 0x14, 0x24,
        0x39, 0x37, 0x16, 0x69, 0x52, 0xef, 0xa1, 0xed, 0xe0, 0x49, 0x96, 0x6a, 0xc3, 0xc9, 0xf8,
        0xbf, 0x74, 0xff, 0x50, 0xbc, 0x3c, 0xf1, 0x96, 0x75, 0x63, 0x87, 0xfc, 0x74, 0xd9, 0xe9,
        0xcf, 0xe1, 0x75, 0x70, 0xf, 0xf9, 0x3f, 0xf2, 0xbb, 0xc, 0x42, 0xd4, 0x5e, 0x4b, 0x12,
        0x7a, 0xaf, 0x30, 0x34, 0xf2, 0x13, 0x13, 0x63, 0xd8, 0xad, 0xd2, 0xc0, 0x74, 0xf5, 0xde,
        0x1f, 0xf4, 0x32, 0xcc, 0x7e, 0xbf, 0x87, 0x4f, 0x49, 0x82, 0x87, 0x93, 0xec, 0x3e, 0x35,
        0x3, 0xbf, 0xa1, 0x40, 0xc0, 0xb, 0xa9, 0xaf, 0x35, 0x83, 0x3c, 0xc6, 0x5, 0xf1, 0xa8,
        0xd5, 0xe0, 0x64, 0x9c, 0xd0, 0xf, 0xe2, 0x30, 0x20, 0x1c, 0xd4, 0xa5, 0x7c, 0xf8, 0x2a,
        0xfb, 0xc7, 0x89, 0xdb, 0xb9, 0x19, 0x7f, 0x6d, 0xbc, 0xf8, 0x91, 0xac, 0x81, 0x5d, 0xe5,
        0x51, 0xa8, 0x9f, 0x89, 0x88, 0xe, 0x14, 0x1, 0x49, 0xe, 0x69, 0xb4, 0xf1, 0x4c, 0xc4,
        0x2f, 0x4d, 0xe8, 0x4e, 0x41, 0x75, 0x32, 0x3, 0xa7, 0x2, 0x2c, 0xf0, 0xb7, 0x9b, 0xe9,
        0x4b, 0xfc, 0x97, 0x94, 0xea, 0x85, 0xd2, 0x9b, 0x36, 0x9e, 0x2a, 0xac, 0x2c, 0x9c, 0x72,
        0x43, 0x52, 0x78, 0x20, 0x88, 0x3a, 0xf2, 0xa5, 0x97, 0x10, 0x5f, 0xcc, 0xbc, 0x18, 0x35,
        0x15, 0xde, 0x2f, 0x28, 0x4d, 0x56, 0x8d, 0x35, 0x10, 0x5e, 0xdc, 0x47, 0xe4, 0x20, 0x8,
        0x7e, 0xaa, 0x24, 0x7e, 0x8a, 0x54, 0x46, 0xdd, 0x63, 0x7a, 0xc4, 0xfa, 0x82, 0x77, 0x8f,
        0x49, 0x89, 0x14, 0x72, 0x33, 0xf1, 0x7a, 0xd1, 0x31, 0xfe, 0x12, 0x29, 0x7, 0x7, 0x3d,
        0xca, 0xd8, 0xc4, 0xcf, 0x1a, 0xaa, 0xd7, 0xdd, 0x42, 0x15, 0xac, 0x9, 0x91, 0x6e, 0xbd,
        0xd8, 0xfa, 0x78, 0x58, 0xb6, 0x53, 0x6, 0x7d, 0xf1, 0x6f, 0xaf, 0xd3, 0xa3, 0xd9, 0x81,
        0xea, 0x35, 0x59, 0x4a, 0xb6, 0xd1, 0x8e, 0x72, 0x0, 0x12, 0x67, 0xbf, 0xe, 0x42, 0x93,
        0xbf, 0x1d, 0x10, 0x75, 0xc0, 0xf6, 0x9c,
    ];

    static AMOUNT_64: [u8; 43] = [
        0x3, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0xab, 0xe8, 0x9d, 0x73, 0xbd,
        0x1c, 0x25, 0x6d, 0x3c, 0x94, 0x94, 0xda, 0x5, 0xcc, 0x29, 0x7e, 0x34, 0xc3, 0xed, 0xfb,
        0x6, 0xdb, 0x6f, 0xe4, 0xdf, 0x6f, 0x28, 0x6e, 0x5d, 0xf6, 0xce, 0xfe,
    ];

    static COMMIT_SUM: [u8; 35] = [
        0x21, 0x0, 0x9, 0x36, 0x2d, 0xe0, 0xe6, 0x5f, 0x65, 0x31, 0xe9, 0x60, 0x5, 0xcc, 0xf7,
        0x15, 0x2c, 0x7d, 0xa9, 0x16, 0x8a, 0x2f, 0x32, 0x25, 0x52, 0xa2, 0x9b, 0xe0, 0xb5, 0xc,
        0x19, 0xc2, 0x4d, 0x98, 0x95,
    ];

    #[test]
    fn test_amount() {
        // Test encoding decoding
        test_encode!((AMOUNT_65, Revealed));
        test_encode!((CONFIDENTIAL_AMOUNT, Confidential));

        // Test commitment
        assert!(test_confidential::<Revealed>(&AMOUNT_65, &CONFIDENTIAL_AMOUNT).is_ok());

        // Test comparison
        let revealed_64 = Revealed::strict_decode(&AMOUNT_64[..]).unwrap();
        let old_revealed = Revealed::strict_decode(&AMOUNT_65[..]).unwrap();
        assert_eq!(revealed_64.cmp(&old_revealed), Ordering::Less);
        assert_eq!(
            revealed_64.partial_cmp(&old_revealed).unwrap(),
            Ordering::Less
        );
        let coded_conf = Confidential::strict_decode(&CONFIDENTIAL_AMOUNT[..]).unwrap();
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
            secp256k1zkp::pedersen::Commitment::strict_decode(&COMMIT_SUM[..]).unwrap();
        assert_eq!(sum, commit_sum);
    }

    #[test]
    fn test_commit_sum() {
        let positive = [1u64, 2u64, 3u64, 4u64, 5u64];
        let negative = [7u64, 8u64];

        // Generate random blinding factors
        let mut rng = rand::thread_rng();
        // We do not need the last one since it is auto-generated to zero-balance the rest
        let count = positive.len() + negative.len() - 1;
        let mut blinding_factors = Vec::<_>::with_capacity(count + 1);
        for _ in 0..count {
            blinding_factors.push(BlindingFactor::new(&SECP256K1_ZKP, &mut rng));
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
            .map(|amount| {
                Revealed {
                    amount,
                    blinding: blinding_factors.pop().unwrap(),
                }
                .conceal()
                .commitment
            })
            .collect();

        // Test still fails
        assert_eq!(
            Confidential::verify_commit_sum(
                commitments[..positive.len()].to_vec(),
                commitments[positive.len()..].to_vec()
            ),
            false
        );
    }

    #[test]
    fn test_zero_commmit() {
        let zero_commit = Confidential::zero_pedersen_commitment();

        let mut handmade_bytes = [0x21u8, 0x0u8, 0x08u8].to_vec();
        handmade_bytes.extend([0x0u8; 32].iter());
        let handmade_commit =
            secp256k1zkp::pedersen::Commitment::strict_decode(&handmade_bytes[..]).unwrap();

        assert_eq!(handmade_commit, zero_commit);
    }

    #[test]
    #[should_panic(expected = "UnsupportedDataStructure")]
    fn test_revealed_panic() {
        Revealed::strict_decode(&CONFIDENTIAL_AMOUNT[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "EnumValueNotKnown")]
    fn test_garbage() {
        test_garbage!((AMOUNT_65, Revealed));
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_garbage_conf() {
        test_garbage!((CONFIDENTIAL_AMOUNT, Confidential));
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
