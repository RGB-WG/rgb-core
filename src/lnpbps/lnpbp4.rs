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

use rand::Rng;
use std::collections::BTreeMap;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::util::uint::Uint256;

use crate::commit_verify::CommitVerify;

/// Source data for creation of multi-message commitments according to LNPBP-4 procedure
pub type MultiMsg = BTreeMap<sha256::Hash, sha256::Hash>;
pub type Lnpbp4Hash = sha256::Hash;

/// Multimessage commitment data according to LNPBP-4 specification
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub struct MultimsgCommitment {
    pub commitments: Vec<(Option<sha256::Hash>, Lnpbp4Hash)>,
    pub entropy: Option<u64>,
}

impl CommitVerify<MultiMsg> for MultimsgCommitment {
    fn commit(multimsg: &MultiMsg) -> Self {
        const SORT_LIMIT: usize = 2 << 16;

        let mut n = multimsg.len();
        let ordered = loop {
            let mut ordered = BTreeMap::<usize, (sha256::Hash, sha256::Hash)>::new();
            // TODO: Modify arithmetics in LNPBP-4 spec
            if multimsg.into_iter().all(|(hash, digest)| {
                let rem = Uint256::from_be_bytes(hash.into_inner())
                    % Uint256::from_u64(n as u64).expect("Bitcoin U256 struct is broken");
                ordered
                    .insert(rem.low_u64() as usize, (hash.clone(), digest.clone()))
                    .is_none()
            }) {
                break ordered;
            }
            n += 1;
            if n > SORT_LIMIT {
                panic!(
                    "Memory allocation limit exceeded while trying to sort multi-message commitment"
                );
            }
        };

        let entropy = {
            let mut rng = rand::thread_rng();
            rng.gen::<u64>()
        };
        let entropy_digest = {
            let mut engine = sha256::Hash::engine();
            engine.input(&entropy.to_le_bytes());
            sha256::Hash::from_engine(engine)
        };

        let mut commitments = vec![];
        for i in 1..=n {
            match ordered.get(&i) {
                None => {
                    let mut engine = sha256::Hash::engine();
                    engine.input(&i.to_le_bytes());
                    engine.input(&entropy_digest[..]);
                    commitments.push((None, sha256::Hash::from_engine(engine)))
                }
                Some((contract_id, commitment)) => {
                    commitments.push((Some(*contract_id), *commitment))
                }
            }
        }
        Self {
            commitments,
            entropy: Some(entropy),
        }
    }
}
