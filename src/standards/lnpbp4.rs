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

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::rand::{thread_rng, Rng};
use bitcoin::util::uint::Uint256;

use crate::commit_verify::TryCommitVerify;

/// Source data for creation of multi-message commitments according to LNPBP-4
/// procedure
pub type MultiMsg = BTreeMap<sha256::Hash, sha256::Hash>;
pub type Lnpbp4Hash = sha256::Hash;

#[derive(Copy, Clone, Error, Debug, Display)]
#[display(Debug)]
pub struct TooManyMessagesError;

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[strict_crate(crate)]
#[display(Debug)]
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
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[strict_crate(crate)]
#[display(Debug)]
pub struct MultimsgCommitment {
    pub commitments: Vec<MultimsgCommitmentItem>,
    pub entropy: Option<u64>,
}

impl TryCommitVerify<MultiMsg> for MultimsgCommitment {
    type Error = TooManyMessagesError;

    fn try_commit(multimsg: &MultiMsg) -> Result<Self, TooManyMessagesError> {
        const SORT_LIMIT: usize = 2 << 16;

        let mut n = multimsg.len();
        // We use some minimum number of items, to increase privacy
        n = n.max(3);
        let ordered = loop {
            let mut ordered =
                BTreeMap::<usize, (sha256::Hash, sha256::Hash)>::new();
            // TODO: Modify arithmetics in LNPBP-4 spec
            //       <https://github.com/LNP-BP/LNPBPs/issues/19>
            if multimsg.into_iter().all(|(protocol, digest)| {
                let rem = Uint256::from_be_bytes(protocol.into_inner())
                    % Uint256::from_u64(n as u64)
                        .expect("Bitcoin U256 struct is broken");
                ordered
                    .insert(
                        rem.low_u64() as usize,
                        (protocol.clone(), digest.clone()),
                    )
                    .is_none()
            }) {
                break ordered;
            }
            n += 1;
            if n > SORT_LIMIT {
                // Memory allocation limit exceeded while trying to sort
                // multi-message commitment
                return Err(TooManyMessagesError);
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
                    commitments.push(MultimsgCommitmentItem::new(
                        Some(*contract_id),
                        *commitment,
                    ))
                }
            }
        }

        Ok(Self {
            commitments,
            entropy: Some(entropy),
        })
    }
}
