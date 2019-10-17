// LNP/BP Rust Library
// Written in 2019 by
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


///! Outdated

use bitcoin::{Transaction, TxOut, Script};
use bitcoin::util::key::PublicKey as BitcoinPublicKey;
use bitcoin::util::contracthash::{Template, ScriptPubkeyType, ScriptPubkeyType::*, WitnessScriptVersion};
use secp256k1::PublicKey;
use hashes::Hash as HashTrait;
use crate::commitments::CommitmentWitnessOptions::WitnessV0;

#[derive(Debug, Clone)]
/// Return values identifying result of commitment presence check
pub enum CommitmentPresence {
    /// Commitment with the given parameters was found in the corresponding transaction output
    Present,

    /// Transaction has less outputs than the given commitment output number
    NoOutput,

    /// There is no support for cryptographic commitments to the output type under the given
    /// output number
    WrongOutput(ScriptPubkeyType),

    /// Commitment with the given parameters was not found in the corresponding transaction output
    NoCommitment
}

#[derive(Debug, Clone)]
/// Cryptographic commitment types
pub enum Commitment<HT: HashTrait> {
    /// Pay-to-Contract cryptographic commitment as defined in LNPBPs-0001
    Pay2Contract(String, HT, PublicKey),

    /// OP_RETURN cryptographic commitment as defined in LNPBPs-0002
    OpReturn(String, HT)
}

/// Defines which particular scriptPubkey or witnessScript form should be used for Pay2Contract
/// commitment
pub enum CommitmentWitnessOptions {
    /// Pay-to-Contract with standard P2PKH scriptPubkey transaction output
    NoWitness,

    /// Pay-to-Contract with P2WPKH wrapped into P2SH scriptPubkey transaction output
    WitnessOverP2SH,

    /// Pay-to-Contract with P2WPKH witnessScript V0
    WitnessV0,
}

impl CommitmentWitnessOptions {
    /// Returns ScriptPubkeyType for this CommitmentWitnessOptions case
    fn get_scriptpubkey_type(&self) -> ScriptPubkeyType {
        match self {
            CommitmentWitnessOptions::NoWitness => P2PKH,
            CommitmentWitnessOptions::WitnessOverP2SH => P2WPKH(WitnessScriptVersion::LegacyP2SH),
            CommitmentWitnessOptions::WitnessV0 => WitnessScriptVersion::V0,
        }
    }
}

impl<HT: HashTrait> Commitment<HT> {
    /// Lists all supported scriptPubkey txout types which can contain cryptographic commitment
    pub fn all_supported_output_types() -> Vec<ScriptPubkeyType> {
        return vec![P2PKH, P2WPKH(WitnessScriptVersion::V0),
                    P2WPKH(WitnessScriptVersion::LegacyP2SH), OpReturn];
    }

    /// List supported scriptPubkey txout types wich may be used for a given instance of
    /// a cryptographic commitment
    pub fn supported_output_types(&self) -> Vec<ScriptPubkeyType> {
        return match self {
            Commitment::Pay2Contract(_,_,_) => vec![P2PKH,
                                                    P2WPKH(WitnessScriptVersion::V0),
                                                    P2WPKH(WitnessScriptVersion::LegacyP2SH)],
            Commitment::OpReturn(_,_) => vec![OpReturn],
        }
    }

    /// Checks whether this commitment is present in particular transaction output
    pub fn check_presence(&self, tx: Transaction, vout: u16) -> CommitmentPresence {
        if tx.output.len() <= vout as usize {
            return CommitmentPresence::NoOutput
        }
        let script = tx.output[vout].script_pubkey;

        match self {
            Commitment::Pay2Contract(tag, hash, pubkey) => {
                if script.is_p2pkh() {

                } else if script.is_v0_p2wpkh() {

                } else if script.is_p2sh() {

                } else {
                    CommitmentPresence::WrongOutput()
                }

                if script == self.script_pubkey(Some(CommitmentWitnessOptions::WitnessV0)) ||
                   script == self.script_pubkey(Some(CommitmentWitnessOptions::NoWitness)) ||
                   script == self.script_pubkey(Some(CommitmentWitnessOptions::WitnessOverP2SH)) {
                    CommitmentPresence::Present
                } else {
                    CommitmentPresence::NoCommitment
                }
            },
            Commitment::OpReturn(tag, hash) => {
                CommitmentPresence::Present
            },
        }
    }

    /// Returns script pubkey for a given commitment option
    fn script_pubkey(&self, witness: Option<CommitmentWitnessOptions>) -> Script {
        match self {
            Commitment::Pay2Contract(tag, hash, pubkey) => {
                let witness = witness.unwrap_or(WitnessV0);
                let spkt = witness.get_scriptpubkey_type();
                let template = Template::for_scriptpubkey_type(spkt).unwrap();
                let bitcoin_pk = BitcoinPublicKey{ compressed: true, key: *pubkey };
                template.to_script(&[bitcoin_pk][..])
            },
            Commitment::OpReturn(tag, hash) => {
                let template = Template::for_scriptpubkey_type(OpReturn).unwrap();
                template.to_script(&[])
            },
        }.unwrap()
    }
}
