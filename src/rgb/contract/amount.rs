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

impl PartialOrd for Confidential {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (&self.commitment.0).partial_cmp(&other.commitment.0[..]) {
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
