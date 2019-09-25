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
use secp256k1::PublicKey;
use hashes::Hash as HashTrait;

use crate::common::{OutputType, WitnessScriptVersion};

/// Return values identifying result of commitment precence check
#[derive(Debug, Clone)]
pub enum CommitmentPresence {
    /// Commitment with the given parameters was found in the corresponding transaction output
    Present,

    /// Transaction has less outputs than the given commitment output number
    NoOutput,

    /// There is no support for cryptographic commitments to the output type under the given
    /// output number
    WrongOutput(OutputType),

    /// Commitment with the given parameters was not found in the corresponding transaction output
    NoCommitment
}

#[derive(Debug, Clone)]
pub enum Commitment<HT: HashTrait> {
    Pay2Contract(String, HT, PublicKey),
    OpReturn(String, HT)
}

///

impl<HT: HashTrait> Commitment<HT> {
    pub fn all_supported_output_types() -> Vec<OutputType> {
        return vec![OutputType::P2PKH, OutputType::P2WPH(WitnessScriptVersion::V0),
                    OutputType::P2WPH(WitnessScriptVersion::LegacyP2SH), OutputType::OpReturn];
    }

    pub fn supported_output_types(&self) -> Vec<OutputType> {
        return match self {
            Commitment::Pay2Contract(_,_,_) => vec![OutputType::P2PKH,
                                             OutputType::P2WPH(WitnessScriptVersion::V0),
                                             OutputType::P2WPH(WitnessScriptVersion::LegacyP2SH)],
            Commitment::OpReturn(_,_) => vec![OutputType::OpReturn],
        }
    }

    pub fn check_presence(&self, tx: Transaction, vout: u16) -> CommitmentPresence {
        if tx.output.len() <= vout as usize {
            return CommitmentPresence::NoOutput
        }
        match self {
            Commitment::Pay2Contract(tag, hash, pubkey) => CommitmentPresence::Present,
            Commitment::OpReturn(tag, hash) => CommitmentPresence::Present,
        }
    }

    pub fn script_sig(&self) -> Script {
        unimplemented!()
    }
}
