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
use std::collections::{BTreeMap, HashMap};

use amplify::{DumbDefault, Wrapper};
use bitcoin::hashes::{sha256, sha256t, Hash};
use bitcoin::secp256k1;
use bitcoin::util::psbt::raw::ProprietaryKey;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::util::uint::Uint256;
use bitcoin::{Transaction, Txid};

use lnpbp::bp::dbc::{
    self, Container, Proof, ScriptEncodeData, ScriptEncodeMethod, SpkContainer,
    TxCommitment, TxContainer, TxSupplement, TxoutContainer,
};
use lnpbp::bp::resolvers::{Fee, FeeError};
use lnpbp::bp::TaggedHash;
use lnpbp::client_side_validation::{
    commit_strategy, CommitEncodeWithStrategy, ConsensusCommit,
};
use lnpbp::commit_verify::{CommitVerify, EmbedCommitVerify, TryCommitVerify};
use lnpbp::lnpbp4::{MultimsgCommitment, TooManyMessagesError};
use lnpbp::strict_encoding::{strategies, Strategy};

use crate::{ContractId, NodeId};

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

#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
pub struct Anchor {
    pub txid: Txid,
    pub commitment: MultimsgCommitment,
    pub proof: Proof,
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
        let fee = psbt.fee()?;

        let tx = &mut psbt.global.unsigned_tx;
        let num_outs = tx.output.len() as u64;

        // Compute which transition commitments must go into which output and
        // assemble them in per-output-packs of ContractId: Transition
        // commitment type
        let per_output_sources = transitions.into_iter().fold(
            HashMap::<usize, BTreeMap<sha256::Hash, sha256::Hash>>::new(),
            |mut data, (contract_id, node_id)| {
                let id = Uint256::from_be_bytes(*contract_id.as_slice());
                let vout = id % Uint256::from_u64(num_outs).unwrap();
                let vout = vout.low_u64() as usize;
                data.entry(vout).or_insert(BTreeMap::default()).insert(
                    sha256::Hash::from_inner(*contract_id.as_slice()),
                    sha256::Hash::from_inner(*node_id.as_slice()),
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
                        prefix: b"RGB".to_vec(),
                        subtype: PSBT_OUT_PUBKEY,
                        key: vec![],
                    })
                    .ok_or(Error::NoRequiredPubkey(vout))?,
            )
            .map_err(|_| Error::WrongPubkeyData)?;
            // TODO: (new) Add support for Taproot parsing
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
            // TODO: (new) Move parsing of the output+input into Descriptor impl
            // TODO: (new) With miniscript stabilization refactor this to use it
            let method = if psbt_out.redeem_script.is_some() {
                ScriptEncodeMethod::ScriptHash
            } else if psbt_out.witness_script.is_some() {
                ScriptEncodeMethod::WScriptHash
            } else {
                // TODO: (new) Check PSBT whether pubkey output is witness and
                //       return error otherwise
                ScriptEncodeMethod::WPubkeyHash
            };

            let mut container = TxContainer {
                tx: tx.clone(),
                fee,
                protocol_factor: vout as u32,
                txout_container: TxoutContainer {
                    value: tx_out.value,
                    script_container: SpkContainer {
                        pubkey,
                        method,
                        source,
                        tag: *LNPBP4_TAG,
                        tweaking_factor: None,
                    },
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
                TxCommitment::embed_commit(&mut container, &mm_digest).unwrap();

            *tx = commitment.into_inner().clone();
            psbt.outputs
                .get_mut(container.vout())
                .map(|output| {
                    output.proprietary.insert(
                        ProprietaryKey {
                            prefix: b"RGB".to_vec(),
                            subtype: PSBT_OUT_TWEAK,
                            key: vec![]
                        },
                        container.tweaking_factor.expect(
                            "Tweaking factor always present after commitment procedure"
                        )[..].to_vec())
                });

            multimsg.iter().for_each(|(id, _)| {
                let contract_id = ContractId::from_hash(*id);
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
            == sha256::Hash::from_slice(&node_id[..])
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

        // TODO: Refactor multimessage commitments
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
        // TODO: Refactor using bp::seals
        let container =
            TxContainer::reconstruct(&self.proof, &supplement, &tx)?;
        let commitment = TxCommitment::from(tx.clone());
        commitment.verify(&container, &value)
    }

    #[inline]
    pub fn anchor_id(&self) -> AnchorId {
        self.clone().consensus_commit()
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
    use amplify::Wrapper;

    use super::*;
    use lnpbp::bp::tagged_hash;

    #[test]
    fn test_anchor_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:anchor");
        assert_eq!(midstate.into_inner(), MIDSTATE_ANCHOR_ID);
    }
}
