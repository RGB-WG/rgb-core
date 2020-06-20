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

use std::collections::{BTreeMap, HashMap};
use std::io;

use amplify::Wrapper;
use bitcoin::secp256k1;
use bitcoin::util::psbt::{raw::Key, PartiallySignedTransaction as Psbt};
use bitcoin::util::uint::Uint256;
use bitcoin_hashes::{sha256, Hash};

use crate::bp::dbc::{
    Container, Proof, ScriptInfo, ScriptPubkeyComposition, ScriptPubkeyContainer, TxCommitment,
    TxContainer, TxoutContainer,
};
use crate::commit_verify::{CommitVerify, EmbedCommitVerify};
use crate::lnpbp4::MultimsgCommitment;
use crate::rgb::{ContractId, TransitionId};
use crate::strict_encoding::{self, StrictDecode, StrictEncode};

pub const PSBT_FEE_KEY: &[u8] = b"\x03rgb\x01";
pub const PSBT_PUBKEY_KEY: &[u8] = b"\x03rgb\x02";
lazy_static! {
    static ref LNPBP4_TAG: bitcoin::hashes::sha256::Hash = sha256::Hash::hash(b"LNPBP4");
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display_from(Debug)]
pub enum Error {
    NoRequiredOutputInformation(usize),
    NoRequiredPubkey(usize),
    NoFeeInformation,
    #[derive_from]
    WrongPubkeyData(secp256k1::Error),
}

#[derive(Clone, Debug)]
pub struct Anchor {
    pub commitment: MultimsgCommitment,
    pub proof: Proof,
}

impl Anchor {
    pub fn commit(
        transitions: HashMap<ContractId, TransitionId>,
        psbt: &mut Psbt,
    ) -> Result<Vec<Self>, Error> {
        let tx = &mut psbt.global.unsigned_tx;
        let num_outs = tx.output.len() as u64;

        let pubkey_key = Key {
            type_value: 0xFC,
            key: PSBT_PUBKEY_KEY.to_vec(),
        };
        let fee_key = Key {
            type_value: 0xFC,
            key: PSBT_FEE_KEY.to_vec(),
        };

        let fee = psbt
            .global
            .unknown
            .get(&fee_key)
            .ok_or(Error::NoFeeInformation)?;
        let mut fee_slice = [0u8; 8];
        fee_slice.copy_from_slice(fee);
        let fee = u64::from_be_bytes(fee_slice);

        // Compute which transition commitments must go into which output and
        // assemble them in per-output-packs of ContractId: Transition commitment
        // type
        let per_output_sources = transitions.into_iter().fold(
            HashMap::<usize, BTreeMap<sha256::Hash, sha256::Hash>>::new(),
            |mut data, (contract_id, t)| {
                let id = Uint256::from_be_bytes(contract_id.into_inner());
                let vout = id % Uint256::from_u64(num_outs).unwrap();
                let vout = vout.low_u64() as usize;
                data.entry(vout).or_insert(BTreeMap::default()).insert(
                    sha256::Hash::from_inner(contract_id.into_inner()),
                    sha256::Hash::from_inner(t.into_inner()),
                );
                data
            },
        );

        let mut anchors: Vec<Anchor> = vec![];
        for (vout, multimsg) in per_output_sources {
            let mm_commitment = MultimsgCommitment::commit(&multimsg);
            let psbt_out = psbt
                .outputs
                .get(vout)
                .ok_or(Error::NoRequiredOutputInformation(vout))?
                .clone();
            let tx_out = &tx.output[vout];

            let pubkey = psbt_out
                .unknown
                .get(&pubkey_key)
                .ok_or(Error::NoRequiredPubkey(vout))?;
            let pubkey = secp256k1::PublicKey::from_slice(pubkey)?;
            let script_info = match psbt_out
                .redeem_script
                .as_ref()
                .or_else(|| psbt_out.witness_script.as_ref())
            {
                None => ScriptInfo::None,
                Some(script) => ScriptInfo::LockScript(script.into()),
            };
            let scriptpubkey_composition = if psbt_out.redeem_script.is_some() {
                ScriptPubkeyComposition::ScriptHash
            } else if psbt_out.witness_script.is_some() {
                ScriptPubkeyComposition::WScriptHash
            } else {
                ScriptPubkeyComposition::WPubkeyHash
            };

            let container = TxContainer {
                tx: tx.clone(),
                fee,
                protocol_factor: vout as u32,
                txout_container: TxoutContainer {
                    value: tx_out.value,
                    script_container: ScriptPubkeyContainer {
                        pubkey,
                        script_info,
                        scriptpubkey_composition,
                        tag: *LNPBP4_TAG,
                    },
                },
            };

            let mm_buffer: Vec<u8> = mm_commitment
                .clone()
                .commitments
                .into_iter()
                .map(|item| item.commitment.into_inner().to_vec())
                .flatten()
                .collect();
            let mm_digest = sha256::Hash::commit(&mm_buffer);
            let commitment = TxCommitment::embed_commit(&container, &mm_digest).unwrap();

            *tx = commitment.into_inner().clone();

            anchors.push(Anchor {
                commitment: mm_commitment,
                proof: container.into_proof(),
            });
        }

        Ok(anchors)
    }
}

impl StrictEncode for Anchor {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Ok(strict_encode_list!(e; self.commitment, self.proof))
    }
}

impl StrictDecode for Anchor {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self {
            commitment: MultimsgCommitment::strict_decode(&mut d)?,
            proof: Proof::strict_decode(&mut d)?,
        })
    }
}
