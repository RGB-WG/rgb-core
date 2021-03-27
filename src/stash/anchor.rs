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

#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use amplify::{DumbDefault, Wrapper};
use bitcoin::hashes::{sha256, sha256d, sha256t, Hash};
use bitcoin::secp256k1;
use bitcoin::util::psbt::raw::ProprietaryKey;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::util::uint::Uint256;
use bitcoin::{Transaction, Txid};

use lnpbp::client_side_validation::{
    commit_strategy, CommitEncodeWithStrategy, ConsensusCommit,
};
use lnpbp::commit_verify::{CommitVerify, EmbedCommitVerify, TryCommitVerify};
use lnpbp::dbc::{
    self, Container, Proof, ScriptEncodeData, ScriptEncodeMethod, SpkContainer,
    TxCommitment, TxContainer, TxSupplement, TxoutCommitment, TxoutContainer,
};
use lnpbp::lnpbp4::{MessageMap, MultimsgCommitment, TooManyMessagesError};
use lnpbp::strict_encoding::{strategies, Strategy};
use lnpbp::TaggedHash;
use wallet::psbt::{Fee, FeeError};

use crate::{reveal, ContractId, NodeId, RevealedByMerge};

pub const PSBT_PREFIX: &'static [u8] = b"RGB";
pub const PSBT_OUT_PUBKEY: u8 = 0x1;
pub const PSBT_OUT_TWEAK: u8 = 0x2;

lazy_static! {
    static ref LNPBP4_TAG: bitcoin::hashes::sha256::Hash =
        sha256::Hash::hash(b"LNPBP4");
}

static MIDSTATE_ANCHOR_ID: [u8; 32] = [
    0x2b, 0x17, 0xab, 0x6a, 0x88, 0x35, 0xf6, 0x62, 0x86, 0xc1, 0xa6, 0x14,
    0x36, 0x18, 0xc, 0x1f, 0xf, 0x80, 0x96, 0x1b, 0x47, 0x70, 0xe5, 0xf5, 0x45,
    0x45, 0xe4, 0x28, 0x45, 0x47, 0xbf, 0xe9,
];

/// Tag used for [`AnchorId`] hash type
pub struct AnchorIdTag;

impl sha256t::Tag for AnchorIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_ANCHOR_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Unique anchor identifier equivalent to the anchor commitment hash
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From,
)]
#[wrapper(
    Debug, Display, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull
)]
pub struct AnchorId(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    sha256t::Hash<AnchorIdTag>,
);

impl<MSG> CommitVerify<MSG> for AnchorId
where
    MSG: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &MSG) -> AnchorId {
        AnchorId::hash(msg)
    }
}

impl Strategy for AnchorId {
    type Strategy = strategies::Wrapped;
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// Details of output #{0} are required, but were not provided in PSBT
    NoRequiredOutputInformation(usize),

    /// Explicit public key must be given for output number #{0}
    NoRequiredPubkey(usize),

    /// Unable to estimate fee: {0}
    #[from]
    FeeEstimationError(FeeError),

    /// Incorrect public key data: {0}
    #[from(secp256k1::Error)]
    WrongPubkeyData,

    /// Too many state transitions for commitment; can't fit into a single
    /// anchor
    #[from(TooManyMessagesError)]
    SizeLimit,
}

pub trait ConcealAnchors {
    fn conceal_anchors(&mut self) -> usize {
        self.conceal_anchors_except(&vec![])
    }
    fn conceal_anchors_except(&mut self, protocols: &Vec<ContractId>) -> usize;
}

#[cfg_attr(
    any(feature = "cli", feature = "serde"),
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
pub struct Anchor {
    pub txid: Txid,
    pub commitment: MultimsgCommitment,
    pub proof: Proof,
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

impl Ord for Anchor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.anchor_id().cmp(&other.anchor_id())
    }
}

impl PartialOrd for Anchor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl DumbDefault for Anchor {
    fn dumb_default() -> Self {
        Self {
            txid: Txid::default(),
            proof: Proof::dumb_default(),
            commitment: MultimsgCommitment::default(),
        }
    }
}

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
            HashMap::<usize, MessageMap>::new(),
            |mut data, (contract_id, node_id)| {
                let id = Uint256::from_be_bytes(*contract_id.as_slice());
                let vout = id % Uint256::from_u64(num_outs).unwrap();
                let vout = ((vout.low_u64() + fee as u64) % num_outs) as usize;
                data.entry(vout).or_insert(BTreeMap::default()).insert(
                    (*contract_id.as_slice()).into(),
                    sha256d::Hash::from_inner(*node_id.as_slice()),
                );
                data
            },
        );

        let mut anchors: Vec<Anchor> = vec![];
        let mut contract_anchor_map = HashMap::<ContractId, usize>::new();
        for (vout, multimsg) in per_output_sources {
            let mm_commitment = MultimsgCommitment::try_commit(&multimsg)?;

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
            let source = match psbt_out
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
                    source,
                    tag: *LNPBP4_TAG,
                    tweaking_factor: None,
                },
                tweaking_factor: None,
            };

            let mm_buffer: Vec<u8> = mm_commitment
                .clone()
                .commitments
                .into_iter()
                .map(|item| item.commitment.into_inner().to_vec())
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

            multimsg.iter().for_each(|(id, _)| {
                let contract_id =
                    ContractId::from_hash(sha256d::Hash::from_inner(**id));
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
            .commitment
            == sha256d::Hash::from_slice(&node_id[..])
                .expect("TaggedHashes type is broken")
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
            .map(|item| item.commitment.into_inner().to_vec())
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

impl CommitEncodeWithStrategy for Anchor {
    type Strategy = commit_strategy::UsingStrict;
}

impl ConsensusCommit for Anchor {
    type Commitment = AnchorId;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::contract::{Genesis, Node};
    use bitcoin::consensus::deserialize;
    use bitcoin::util::psbt::PartiallySignedTransaction;
    use lnpbp::strict_encoding::StrictDecode;
    use lnpbp::tagged_hash;

    static GENESIS: [u8; 2454] = include!("../../test/genesis.in");

    static PSBT: [u8; 462] = include!("../../test/test_transaction.psbt");

    #[test]
    fn test_anchor_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:anchor");
        assert_eq!(**midstate, MIDSTATE_ANCHOR_ID);
    }

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
                    key.key.serialize().to_vec(),
                );
            }
        }

        // Copy witness psbt for future assertion
        let mut witness_psbt = source_psbt.clone();

        // Create the transition map for commitment
        let mut map: BTreeMap<ContractId, NodeId> = BTreeMap::new();
        map.insert(contract_id, node_id);

        // Make commitment into witness psbt
        Anchor::commit(map, &mut witness_psbt).unwrap();

        // Check number of output remains same
        assert_eq!(
            source_psbt.global.unsigned_tx.output.len(),
            witness_psbt.global.unsigned_tx.output.len()
        );

        // Check output values remains unchanged
        assert_eq!(
            source_psbt.global.unsigned_tx.output[0].value,
            witness_psbt.global.unsigned_tx.output[0].value
        );
        assert_eq!(
            source_psbt.global.unsigned_tx.output[1].value,
            witness_psbt.global.unsigned_tx.output[1].value
        );
    }
}
