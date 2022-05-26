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

#[cfg(feature = "wallet")]
use std::collections::BTreeMap;

#[cfg(feature = "wallet")]
use amplify::Wrapper;
#[cfg(feature = "wallet")]
use bitcoin_hashes::Hash;
#[cfg(feature = "wallet")]
use bp::dbc::anchor::Error;
#[cfg(feature = "wallet")]
use commit_verify::{Message, TaggedHash};
#[cfg(feature = "wallet")]
use wallet::psbt::Psbt;

use bp::dbc::Anchor;
use commit_verify::multi_commit::ProtocolId;

#[cfg(feature = "wallet")]
use crate::NodeId;
use crate::{reveal, ContractId, RevealedByMerge};

pub const PSBT_PREFIX: &'static [u8] = b"RGB";
pub const PSBT_OUT_PUBKEY: u8 = 0x1;
pub const PSBT_OUT_TWEAK: u8 = 0x2;

pub trait ConcealAnchors {
    fn conceal_anchors(&mut self) -> usize {
        self.conceal_anchors_except(&vec![])
    }
    fn conceal_anchors_except(&mut self, contracts: &[ContractId]) -> usize;
}

impl ConcealAnchors for Anchor {
    fn conceal_anchors_except(&mut self, contracts: &[ContractId]) -> usize {
        self.conceal_except(
            &contracts
                .iter()
                .copied()
                .map(ProtocolId::from)
                .collect::<Vec<_>>(),
        )
    }
}

impl RevealedByMerge for Anchor {
    fn revealed_by_merge(self, other: Self) -> Result<Self, reveal::Error> {
        self.merge(other).map_err(reveal::Error::from)
    }
}

#[cfg(feature = "wallet")]
pub trait AnchorExt {
    fn commit(
        psbt: &mut Psbt,
        transitions: BTreeMap<ContractId, NodeId>,
    ) -> Result<Anchor, Error>;
}

#[cfg(feature = "wallet")]
impl AnchorExt for Anchor {
    fn commit(
        psbt: &mut Psbt,
        transitions: BTreeMap<ContractId, NodeId>,
    ) -> Result<Anchor, Error> {
        let messages = transitions
            .iter()
            .map(|(contract_id, node_id)| {
                let protocol_id =
                    ProtocolId::from_inner(contract_id.to_bytes());
                let message = Message::from_inner(node_id.to_bytes());
                (protocol_id, message)
            })
            .collect::<BTreeMap<_, _>>();

        let anchor = Anchor::commit(psbt, messages)?;

        // TODO: Add contracts and state transition proprietary keys

        Ok(anchor)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::contract::{Genesis, Node};
    use crate::NodeId;
    use bitcoin::consensus::deserialize;
    use bitcoin::psbt::raw::ProprietaryKey;
    use bitcoin::util::psbt::PartiallySignedTransaction;
    use std::collections::BTreeMap;
    use strict_encoding::StrictDecode;

    static GENESIS: [u8; 2447] = include!("../../test/genesis.in");

    static PSBT: [u8; 462] = include!("../../test/test_transaction.psbt");

    #[test]
    fn test_psbt() {
        // Create some dummy NodeId and ContractId for the test
        let genesis = Genesis::strict_decode(&GENESIS[..]).unwrap();

        let contract_id = genesis.contract_id();

        let node_id = genesis.node_id();

        // Get the test psbt
        let mut source_psbt: PartiallySignedTransaction =
            deserialize(&PSBT[..]).unwrap();

        // Modify test psbt to include Proprietary Key information
        for output in &mut source_psbt.outputs.iter_mut() {
            if let Some(key) = output.bip32_derivation.keys().next() {
                let key = key.clone();
                output.proprietary.insert(
                    ProprietaryKey {
                        prefix: b"RGB".to_vec(),
                        subtype: PSBT_OUT_PUBKEY,
                        key: vec![],
                    },
                    key.serialize().to_vec(),
                );
            }
        }

        // Copy witness psbt for future assertion
        let witness_psbt = source_psbt.clone();

        // Create the transition map for commitment
        let mut map: BTreeMap<ContractId, NodeId> = BTreeMap::new();
        map.insert(contract_id, node_id);

        // Check number of output remains same
        assert_eq!(
            source_psbt.unsigned_tx.output.len(),
            witness_psbt.unsigned_tx.output.len()
        );

        // Check output values remains unchanged
        assert_eq!(
            source_psbt.unsigned_tx.output[0].value,
            witness_psbt.unsigned_tx.output[0].value
        );
        assert_eq!(
            source_psbt.unsigned_tx.output[1].value,
            witness_psbt.unsigned_tx.output[1].value
        );
    }
}
