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

use crate::{reveal, ContractId, RevealedByMerge};
use bp::dbc::Anchor;
use commit_verify::ConsensusCommit;

pub const PSBT_PREFIX: &'static [u8] = b"RGB";
pub const PSBT_OUT_PUBKEY: u8 = 0x1;
pub const PSBT_OUT_TWEAK: u8 = 0x2;

pub trait ConcealAnchors {
    fn conceal_anchors(&mut self) -> usize {
        self.conceal_anchors_except(&vec![])
    }
    fn conceal_anchors_except(&mut self, protocols: &Vec<ContractId>) -> usize;
}

impl ConcealAnchors for Anchor {
    fn conceal_anchors_except(&mut self, protocols: &Vec<ContractId>) -> usize {
        self.commitment.entropy = None;
        self.commitment
            .commitments
            .iter_mut()
            .fold(0usize, |count, item| match item.protocol {
                Some(protocol) if !protocols.contains(&protocol.into()) => {
                    item.protocol = None;
                    count + 1
                }
                _ => count,
            })
    }
}

impl RevealedByMerge for Anchor {
    fn revealed_by_merge(mut self, other: Self) -> Result<Self, reveal::Error> {
        if self.consensus_commit() != other.consensus_commit() {
            return Err(reveal::Error::AnchorsMismatch);
        }

        self.commitment.entropy =
            self.commitment.entropy.or(other.commitment.entropy);

        self.commitment
            .commitments
            .iter_mut()
            .zip(other.commitment.commitments)
            .for_each(|(item, other)| {
                item.protocol = item.protocol.or(other.protocol)
            });

        Ok(self)
    }
}

/*
impl Anchor {
    pub fn commit(
        transitions: BTreeMap<ContractId, NodeId>,
        psbt: &mut Psbt,
    ) -> Result<(Vec<Self>, HashMap<ContractId, usize>), Error> {
        // TODO #52: Adjust fee if the output does not contain a key marked for
        //       tweaking
        let fee = psbt.fee()?;

        let tx = &mut psbt.global.unsigned_tx;
        let num_outs = tx.output.len() as u64;

        // Compute which transition commitments must go into which output and
        // assemble them in per-output-packs of ContractId: Transition
        // commitment type
        let per_output_sources = transitions.into_iter().fold(
            HashMap::<usize, BTreeMap<ProtocolId, Message>>::new(),
            |mut data, (contract_id, node_id)| {
                let id = Uint256::from_be_bytes(*contract_id.as_slice());
                let vout = id % Uint256::from_u64(num_outs).unwrap();
                let vout = ((vout.low_u64() + fee as u64) % num_outs) as usize;
                data.entry(vout).or_insert(BTreeMap::default()).insert(
                    (*contract_id.as_slice()).into(),
                    Message::from_inner(*node_id.as_slice()),
                );
                data
            },
        );

        let mut anchors: Vec<Anchor> = vec![];
        let mut contract_anchor_map = HashMap::<ContractId, usize>::new();
        for (vout, messages) in per_output_sources {
            let multi_source = MultiSource {
                min_length: ANCHOR_MIN_COMMITMENTS,
                messages,
            };
            let mm_commitment = MultiCommitBlock::try_commit(&multi_source)?;

            let psbt_out = psbt
                .outputs
                .get(vout)
                .ok_or(Error::NoRequiredOutputInformation(vout))?
                .clone();
            let tx_out = &tx.output[vout];

            let pubkey = secp256k1::PublicKey::from_slice(
                psbt_out
                    .proprietary
                    .get(&ProprietaryKey {
                        prefix: PSBT_PREFIX.to_vec(),
                        subtype: PSBT_OUT_PUBKEY,
                        key: vec![],
                    })
                    .ok_or(Error::NoRequiredPubkey(vout))?,
            )
            .map_err(|_| Error::WrongPubkeyData)?;
            // TODO #53: (new) Add support for Taproot parsing
            let script_source = match psbt_out
                .redeem_script
                .as_ref()
                .or_else(|| psbt_out.witness_script.as_ref())
            {
                None => ScriptEncodeData::SinglePubkey,
                Some(script) => {
                    ScriptEncodeData::LockScript(script.clone().into())
                }
            };
            // TODO #54: (new) Move parsing of the output+input into Descriptor
            //      impl
            // TODO #54: (new) With miniscript stabilization
            //      refactor this to use it
            let method = if psbt_out.redeem_script.is_some() {
                ScriptEncodeMethod::ScriptHash
            } else if psbt_out.witness_script.is_some() {
                ScriptEncodeMethod::WScriptHash
            } else {
                // TODO #55: (new) Check PSBT whether pubkey output is witness
                //      and return error otherwise
                ScriptEncodeMethod::WPubkeyHash
            };

            let mut container = TxoutContainer {
                value: tx_out.value,
                script_container: SpkContainer {
                    pubkey,
                    method,
                    source: script_source,
                    tag: *LNPBP4_TAG,
                    tweaking_factor: None,
                },
                tweaking_factor: None,
            };

            let mm_buffer: Vec<u8> = mm_commitment
                .clone()
                .commitments
                .into_iter()
                .map(|item| item.message.into_inner().to_vec())
                .flatten()
                .collect();
            let mm_digest = sha256::Hash::commit(&mm_buffer);
            let commitment =
                TxoutCommitment::embed_commit(&mut container, &mm_digest)
                    .unwrap();

            *(&mut tx.output[vout]) = commitment.into_inner().clone();
            psbt.outputs
                .get_mut(vout)
                .map(|output| {
                    // TODO #56: Provide full state transition information for the
                    //       signer with serialized `Roll`
                    output.proprietary.insert(
                        ProprietaryKey {
                            prefix: PSBT_PREFIX.to_vec(),
                            subtype: PSBT_OUT_TWEAK,
                            key: vec![]
                        },
                        container.tweaking_factor.expect(
                            "Tweaking factor always present after commitment procedure"
                        )[..].to_vec())
                });

            multi_source.messages.iter().for_each(|(id, _)| {
                let contract_id = ContractId::from_hash(
                    sha256d::Hash::from_inner(*id.as_inner()),
                );
                contract_anchor_map.insert(contract_id, anchors.len());
            });
            anchors.push(Anchor {
                txid: tx.txid(),
                commitment: mm_commitment,
                proof: container.into_proof(),
            });
        }

        Ok((anchors, contract_anchor_map))
    }

    pub fn validate(&self, contract_id: &ContractId, node_id: &NodeId) -> bool {
        let id = Uint256::from_be_bytes(*contract_id.as_slice());
        let len = Uint256::from_u64(self.commitment.commitments.len() as u64)
            .unwrap();
        let pos = (id % len).low_u64() as usize;
        self.commitment
            .commitments
            .get(pos)
            .expect("Index modulo length can't exceed array length")
            .message
            == Message::from_inner(*node_id.as_slice())
    }

    pub fn verify(
        &self,
        contract_id: &ContractId,
        tx: &Transaction,
        fee: u64,
    ) -> bool {
        let id = Uint256::from_be_bytes(*contract_id.as_slice());
        let protocol_factor =
            id % Uint256::from_u64(tx.output.len() as u64).unwrap();
        let protocol_factor = protocol_factor.low_u64() as u32;

        // TODO #57: Refactor multimessage commitments
        let mm_buffer: Vec<u8> = self
            .commitment
            .clone()
            .commitments
            .into_iter()
            .map(|item| item.message.into_inner().to_vec())
            .flatten()
            .collect();
        let mm_digest = sha256::Hash::commit(&mm_buffer);

        let supplement = TxSupplement {
            protocol_factor,
            fee,
            tag: *LNPBP4_TAG,
        };

        self.verify_internal(tx, supplement, mm_digest)
            .map_err(|_| -> Result<bool, dbc::Error> { Ok(false) })
            .unwrap()
    }

    fn verify_internal(
        &self,
        tx: &Transaction,
        supplement: TxSupplement,
        value: sha256::Hash,
    ) -> Result<bool, dbc::Error> {
        // TODO #58: Refactor using bp::seals
        let container =
            TxContainer::reconstruct(&self.proof, &supplement, &tx)?;
        let commitment = TxCommitment::from(tx.clone());
        commitment.verify(&container, &value)
    }

    #[inline]
    pub fn anchor_id(&self) -> AnchorId {
        self.clone().consensus_commit()
    }

    pub fn conceal_except(&mut self, contract_id: ContractId) -> usize {
        self.commitment.entropy = None;
        self.commitment.commitments.iter_mut().fold(
            0usize,
            |mut count, item| {
                if item.protocol != Some((*contract_id.as_slice()).into()) {
                    item.protocol = None;
                    count += 1;
                }
                count
            },
        )
    }
}
 */

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
        let mut witness_psbt = source_psbt.clone();

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
