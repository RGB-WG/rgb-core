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

use crate::commit_verify::CommitVerify;
use bitcoin::hashes::{sha256, sha256d, Hash, HashEngine};
use rand::Rng;
use std::collections::BTreeMap;

/// Source data for creation of multimessage commitments according to LNPBP-4 procedure
type MultiMsg = BTreeMap<u64, sha256::Hash>;

/// Multimessage commitment data according to LNPBP-4 specification
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub struct MultimsgCommitment {
    data: Vec<u8>,
    entropy: u64,
}

impl CommitVerify<MultiMsg> for MultimsgCommitment {
    fn commit(multimsg: &MultiMsg) -> Self {
        const SORT_LIMIT: u64 = 2 << 16;

        let mut n = multimsg.len() as u64;
        let ordered = loop {
            let mut ordered = MultiMsg::new();
            // TODO: Modify arythmetics in LNPBP-4 spec
            if multimsg
                .into_iter()
                .all(|(sort_code, digest)| ordered.insert(sort_code % n, digest.clone()).is_none())
            {
                break ordered;
            }
            n += 1;
            if n > SORT_LIMIT {
                panic!(
                    "Memory allocation limit exceeded while trying to sort multimessage commitment"
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
        let mut data: Vec<u8> = vec![];
        for i in 1..=n {
            match ordered.get(&i) {
                Some(digest) => data.extend_from_slice(&digest[..]),
                None => {
                    let mut engine = sha256d::Hash::engine();
                    engine.input(&i.to_le_bytes());
                    engine.input(&entropy_digest[..]);
                    data.extend_from_slice(&sha256d::Hash::from_engine(engine)[..])
                }
            }
        }
        Self { data, entropy }
    }
}
