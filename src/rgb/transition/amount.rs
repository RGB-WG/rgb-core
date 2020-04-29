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

use std::ops::Add;

// We do not import particular modules to keep aware with namespace prefixes that we do not use
// the standard secp256k1zkp library
pub use secp256k1zkp::pedersen;
use secp256k1zkp::*;

use crate::commit_verify::EmbedCommitVerify;

// TODO: Convert Amount into a wrapper type later
//wrapper!(Amount, u64, doc="64-bit data for amounts");
pub type Amount = u64;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct AmountCommitment {
    pub commitment: pedersen::Commitment,
    pub bulletproof: pedersen::RangeProof,
}

// The normal notion of the equivalence operator is to compare the _value_
// behind any data structure. However, here we compare not the value we
// are committing to, but the commitment itself. This is different to the
// design of the original Bulletproof designers, but is appropriate for the
// goals of RGB project and client-side validation paradigm
impl PartialEq for AmountCommitment {
    fn eq(&self, other: &Self) -> bool {
        let plen = self.bulletproof.plen;
        self.commitment.0.to_vec() == other.commitment.0.to_vec()
            && self.bulletproof.proof[..plen] == other.bulletproof.proof[..plen]
    }
}

impl Eq for AmountCommitment {}

/// Proof for Pedersen commitment: a blinding key
pub type BlindingFactor = secp256k1zkp::key::SecretKey;

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub enum ConfidentialAmount {
    Partial(AmountCommitment),
    Revealed(AmountCommitment, BlindingFactor),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display_from(Debug)]
pub enum Error {
    #[derive_from(secp256k1zkp::Error)]
    ZkpLibraryError,
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display_from(Debug)]
pub enum BlindingContainer {
    BlindingFactor(BlindingFactor),
    BlindingSet(Vec<BlindingFactor>),
}

// TODO: Refactor EmbedCommitVerify so that Container type will not be an
//       associated type but rather a generic parameter
impl EmbedCommitVerify<Amount> for ConfidentialAmount {
    type Container = BlindingContainer;
    type Error = Error;

    fn embed_commit(container: &Self::Container, amount: &Amount) -> Result<Self, Self::Error> {
        match container {
            BlindingContainer::BlindingFactor(blinding) => {
                let blinding = blinding.clone();
                let value = *amount;

                // TODO: Initialize only once and keep reference
                let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);
                let commitment = secp.commit(value, blinding.clone())?;
                let bulletproof = secp.bullet_proof(
                    value,
                    blinding.clone(),
                    blinding.clone(),
                    blinding.clone(),
                    None,
                    None,
                );
                Ok(ConfidentialAmount::Revealed(
                    AmountCommitment {
                        commitment,
                        bulletproof,
                    },
                    blinding,
                ))
            }
            BlindingContainer::BlindingSet(blinding_factors) => {
                let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);
                let factors = blinding_factors.clone();
                let blinding = secp.blind_sum(vec![secp256k1zkp::key::ONE_KEY], factors)?;
                Self::embed_commit(&BlindingContainer::BlindingFactor(blinding), amount)
            }
        }
    }
}

impl ConfidentialAmount {
    pub fn zero_pedersen_commitment() -> Result<pedersen::Commitment, Error> {
        let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);
        Ok(secp.commit_value(0)?)
    }
}

impl Add<pedersen::Commitment> for AmountCommitment {
    type Output = pedersen::Commitment;

    fn add(self, other: pedersen::Commitment) -> Self::Output {
        let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);

        secp.commit_sum(vec![self.commitment, other], vec![])
            .expect("Failed to add Pedersen commitments")
    }
}

impl AmountCommitment {
    pub fn verify_bullet_proof(&self) -> Result<pedersen::ProofRange, secp256k1zkp::Error> {
        let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);

        secp.verify_bullet_proof(self.commitment.clone(), self.bulletproof.clone(), None)
    }

    pub fn verify_commit_sum(
        positive: Vec<pedersen::Commitment>,
        negative: Vec<pedersen::Commitment>,
    ) -> bool {
        let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);

        secp.verify_commit_sum(positive, negative)
    }
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use std::io;

    mod zkp {
        use super::*;

        impl StrictEncode for secp256k1zkp::key::SecretKey {
            type Error = Error;

            fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
                self.0.as_ref().strict_encode(e)
            }
        }

        impl StrictDecode for secp256k1zkp::key::SecretKey {
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

    impl StrictEncode for AmountCommitment {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e; self.commitment, self.bulletproof))
        }
    }

    impl StrictDecode for AmountCommitment {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            Ok(Self {
                commitment: pedersen::Commitment::strict_decode(&mut d)?,
                bulletproof: pedersen::RangeProof::strict_decode(&mut d)?,
            })
        }
    }

    impl StrictEncode for ConfidentialAmount {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(match self {
                ConfidentialAmount::Partial(amount_commitment) => {
                    strict_encode_list!(e; 0u8, amount_commitment)
                }
                ConfidentialAmount::Revealed(amount_commitment, blinding_factor) => {
                    strict_encode_list!(e; 1u8, amount_commitment, blinding_factor)
                }
            })
        }
    }

    impl StrictDecode for ConfidentialAmount {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let format = u8::strict_decode(&mut d)?;
            let amount_commitment = AmountCommitment::strict_decode(&mut d)?;
            Ok(match format {
                0u8 => ConfidentialAmount::Partial(amount_commitment),
                1u8 => ConfidentialAmount::Revealed(
                    amount_commitment,
                    BlindingFactor::strict_decode(&mut d)?,
                ),
                invalid => Err(Error::EnumValueNotKnown(
                    "ConfidentialAmount".to_string(),
                    invalid,
                ))?,
            })
        }
    }
}
