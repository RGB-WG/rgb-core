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

use std::collections::BTreeMap;
use std::io;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::rand::{thread_rng, Rng};
use bitcoin::util::uint::Uint256;

use crate::commit_verify::CommitVerify;
use crate::strict_encoding::{self, StrictDecode, StrictEncode};

/// Source data for creation of multi-message commitments according to LNPBP-4 procedure
pub type MultiMsg = BTreeMap<sha256::Hash, sha256::Hash>;
pub type Lnpbp4Hash = sha256::Hash;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub struct MultimsgCommitmentItem {
    pub protocol: Option<sha256::Hash>,
    pub commitment: Lnpbp4Hash,
}

impl MultimsgCommitmentItem {
    pub fn new(protocol: Option<sha256::Hash>, commitment: Lnpbp4Hash) -> Self {
        Self {
            protocol,
            commitment,
        }
    }
}

/// Multimessage commitment data according to LNPBP-4 specification
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub struct MultimsgCommitment {
    pub commitments: Vec<MultimsgCommitmentItem>,
    pub entropy: Option<u64>,
}

impl CommitVerify<MultiMsg> for MultimsgCommitment {
    fn commit(multimsg: &MultiMsg) -> Self {
        const SORT_LIMIT: usize = 2 << 16;

        let mut n = multimsg.len();
        // We use some minimum number of items, to increase privacy
        n = n.max(3);
        let ordered = loop {
            let mut ordered = BTreeMap::<usize, (sha256::Hash, sha256::Hash)>::new();
            // TODO: Modify arithmetics in LNPBP-4 spec
            if multimsg.into_iter().all(|(protocol, digest)| {
                let rem = Uint256::from_be_bytes(protocol.into_inner())
                    % Uint256::from_u64(n as u64).expect("Bitcoin U256 struct is broken");
                ordered
                    .insert(rem.low_u64() as usize, (protocol.clone(), digest.clone()))
                    .is_none()
            }) {
                break ordered;
            }
            n += 1;
            if n > SORT_LIMIT {
                // TODO: Convert this in a error returned by the function
                panic!(
                    "Memory allocation limit exceeded while trying to sort multi-message commitment"
                );
            }
        };

        let entropy = {
            let mut rng = thread_rng();
            rng.gen::<u64>()
        };
        let entropy_digest = {
            let mut engine = sha256::Hash::engine();
            engine.input(&entropy.to_le_bytes());
            sha256::Hash::from_engine(engine)
        };

        let mut commitments = Vec::<_>::with_capacity(n);
        for i in 0..n {
            match ordered.get(&i) {
                None => {
                    let mut engine = sha256::Hash::engine();
                    engine.input(&i.to_le_bytes());
                    engine.input(&entropy_digest[..]);
                    commitments.push(MultimsgCommitmentItem::new(
                        None,
                        sha256::Hash::from_engine(engine),
                    ))
                }
                Some((contract_id, commitment)) => {
                    commitments.push(MultimsgCommitmentItem::new(Some(*contract_id), *commitment))
                }
            }
        }

        Self {
            commitments,
            entropy: Some(entropy),
        }
    }
}

impl StrictEncode for MultimsgCommitmentItem {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Ok(strict_encode_list!(e; self.protocol, self.commitment))
    }
}

impl StrictDecode for MultimsgCommitmentItem {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self {
            protocol: Option::<sha256::Hash>::strict_decode(&mut d)?,
            commitment: Lnpbp4Hash::strict_decode(&mut d)?,
        })
    }
}

impl StrictEncode for MultimsgCommitment {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Ok(strict_encode_list!(e; self.commitments, self.entropy))
    }
}

impl StrictDecode for MultimsgCommitment {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self {
            commitments: Vec::<MultimsgCommitmentItem>::strict_decode(&mut d)?,
            entropy: Option::<u64>::strict_decode(&mut d)?,
        })
    }
}
