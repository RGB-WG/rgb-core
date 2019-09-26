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


///! Implementation of LNPBPs covering different cryptographic commitment schemes:
///! LNPBPs-0001: Cryptographic commitments with public key tweaking
///! LNPBPs-0002: OP_RETURN cryptographic commitment
///!
///! In the future, with the addition of new LNPBPs for cryptographic commitments the support
///! must be extended to cover sign-to-contract scheme, Schnorr's signatures, multisig outputs etc

use bitcoin::{Transaction, Script};
use bitcoin::util::key::PublicKey as BitcoinPublicKey;
use bitcoin::util::contracthash::{Template, ScriptPubkeyType, ScriptPubkeyType::*, WitnessScriptVersion};
use secp256k1::PublicKey;
use hashes::Hash as HashTrait;

#[derive(Debug, Clone)]
/// Return values identifying result of commitment precence check
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
    Pay2Contract(String, HT, PublicKey),
    OpReturn(String, HT)
}

impl<HT: HashTrait> Commitment<HT> {
    pub fn all_supported_output_types() -> Vec<ScriptPubkeyType> {
        return vec![P2PKH, P2WPKH(WitnessScriptVersion::V0),
                    P2WPKH(WitnessScriptVersion::LegacyP2SH), OpReturn];
    }

    pub fn supported_output_types(&self) -> Vec<ScriptPubkeyType> {
        return match self {
            Commitment::Pay2Contract(_,_,_) => vec![P2PKH,
                                                    P2WPKH(WitnessScriptVersion::V0),
                                                    P2WPKH(WitnessScriptVersion::LegacyP2SH)],
            Commitment::OpReturn(_,_) => vec![OpReturn],
        }
    }

    pub fn check_presence(&self, tx: Transaction, vout: u16) -> CommitmentPresence {
        if tx.output.len() <= vout as usize {
            return CommitmentPresence::NoOutput
        }
        match self {
            Commitment::Pay2Contract(tag, hash, pubkey) => {
                CommitmentPresence::Present
            },
            Commitment::OpReturn(tag, hash) => {
                CommitmentPresence::Present
            },
        }
    }

    pub fn script_pubkey(&self) -> Script {
        match self {
            Commitment::Pay2Contract(tag, hash, pubkey) => {
                let template = Template::for_scriptpubkey_type(P2PKH).unwrap();
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
