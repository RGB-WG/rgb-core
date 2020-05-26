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

//! General workflow for working with ScriptPubkey* types:
//! ```text
//! Template -> Descriptor -> Structure -> PubkeyScript -> TxOut
//!
//! TxOut -> PubkeyScript -> Descriptor -> Structure -> Format
//! ```

use bitcoin::{blockdata::script::*, hash_types::*, hashes::Hash, secp256k1};
use core::convert::TryFrom;

use super::types::*;

/// Enum defining standard and providing all required data for script pubkey
/// serialization. This enum is not designed for wallets; it covers only
/// BIPs and Bitcoin Core extra-wallet parts.
///
/// If you need enum without attached data (like for functions detecting
/// type of the script pubkey) check [ScriptPubkeyFormat].
pub enum ScriptPubkeyStructure {
    /// Initial standard used by Bitcoin Core (also codenamed "P2PK")
    /// that uses uncompressed public key serialization followed with
    /// `OP_CHECKSIG` code
    KeyChecksig(bitcoin::PublicKey),

    /// Script pubkey serialization according to widely accepted standard
    KeyHash(PubkeyHash),

    /// Script pubkey serialization according to BIP-16
    ScriptHash(ScriptHash),

    /// Segwit script pubkey serialization according to BIP-141
    /// <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#Witness_program>
    Witness(WitnessVersion, WitnessProgram),

    /// Outputs containing OP_RETURN serialized according to
    /// [Bitcoin Core-defined rules](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.12.0.md#relay-any-sequence-of-pushdatas-in-op_return-outputs-now-allowed)
    /// as initial OP_RETURN code with any combination of data pushes and
    /// numeric constant opcodes (OP_1 to OP_16)
    OpReturn(Vec<Vec<u8>>),

    /// Custom (i.e. non-standard) output with arbitrary script
    Custom(Script),
}

pub enum ScriptPubkeyFormat {
    /// Initial standard used by Bitcoin Core (also codenamed "P2PK")
    /// that uses uncompressed public key serialization followed with
    /// `OP_CHECKSIG` code
    KeyChecksig,

    /// Script pubkey serialization according to widely accepted standard
    KeyHash,

    /// Script pubkey serialization according to BIP-16
    ScriptHash,

    /// Segwit script pubkey serialization according to BIP-141
    /// <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#Witness_program>
    Witness,

    /// Outputs containing OP_RETURN serialized according to
    /// [Bitcoin Core-defined rules](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.12.0.md#relay-any-sequence-of-pushdatas-in-op_return-outputs-now-allowed)
    OpReturn,

    /// Custom (i.e. non-standard) output with arbitrary script
    Custom,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ScriptPubkeyDescriptor {
    P2S(PubkeyScript),
    P2PK(bitcoin::PublicKey),
    P2PKH(PubkeyHash),
    P2SH(ScriptHash),
    P2OR(Vec<Vec<u8>>),
    P2WPKH(WPubkeyHash),
    P2WSH(WScriptHash),
    P2TR(secp256k1::PublicKey),
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ScriptPubkeyTemplate {
    P2S(PubkeyScript),
    P2PK(bitcoin::PublicKey),
    P2PKH(bitcoin::PublicKey),
    P2SH(LockScript),
    P2OR(Vec<Vec<u8>>),
    #[allow(non_camel_case_types)]
    P2SH_P2WPKH(bitcoin::PublicKey),
    #[allow(non_camel_case_types)]
    P2SH_P2WSH(LockScript),
    P2WPKH(bitcoin::PublicKey),
    P2WSH(LockScript),
    P2TR(secp256k1::PublicKey, TapScript),
}

#[derive(Clone, PartialEq, Eq, Display, Debug, From, Error)]
#[display_from(Debug)]
pub enum Error {
    InvalidKeyData,
    UnsupportedWitnessVersion,
}

impl TryFrom<PubkeyScript> for ScriptPubkeyDescriptor {
    type Error = Error;
    fn try_from(script_pubkey: PubkeyScript) -> Result<Self, Self::Error> {
        use bitcoin::blockdata::opcodes::all::*;
        use ScriptPubkeyDescriptor::*;

        let script = &*script_pubkey;
        let p = script.as_bytes();
        Ok(match script {
            s if s.is_p2pk() => {
                let key = match p[0].into() {
                    OP_PUSHBYTES_65 => bitcoin::PublicKey::from_slice(&p[1..66]),
                    OP_PUSHBYTES_33 => bitcoin::PublicKey::from_slice(&p[1..34]),
                    _ => panic!("Reading hash from fixed slice failed"),
                }
                .map_err(|_| Error::InvalidKeyData)?;
                P2PK(key)
            }
            s if s.is_p2pkh() => P2PKH(
                PubkeyHash::from_slice(&p[2..23]).expect("Reading hash from fixed slice failed"),
            ),
            s if s.is_p2sh() => P2SH(
                ScriptHash::from_slice(&p[1..22]).expect("Reading hash from fixed slice failed"),
            ),
            s if s.is_v0_p2wpkh() => P2WPKH(
                WPubkeyHash::from_slice(&p[2..23]).expect("Reading hash from fixed slice failed"),
            ),
            s if s.is_v0_p2wsh() => P2WSH(
                WScriptHash::from_slice(&p[2..34]).expect("Reading hash from fixed slice failed"),
            ),
            s if s.is_witness_program() => Err(Error::UnsupportedWitnessVersion)?,
            s if s.is_op_return() => P2OR(
                Script::from(p[1..].to_vec())
                    .iter(false)
                    .map(|instr| {
                        if let Instruction::PushBytes(data) = instr {
                            data.to_vec()
                        } else {
                            panic!("Rust bitcoin library broken in script parsing functionality")
                        }
                    })
                    .collect(),
            ),
            _ => P2S(script_pubkey),
        })
    }
}

impl From<ScriptPubkeyDescriptor> for PubkeyScript {
    fn from(spkt: ScriptPubkeyDescriptor) -> PubkeyScript {
        use ScriptPubkeyDescriptor::*;

        PubkeyScript::from(match spkt {
            P2S(script) => (*script).clone(),
            P2PK(pubkey) => Builder::gen_p2pk(&pubkey).into_script(),
            P2PKH(pubkey_hash) => Builder::gen_p2pkh(&pubkey_hash).into_script(),
            P2SH(script_hash) => Builder::gen_p2sh(&script_hash).into_script(),
            P2OR(data) => {
                if data.len() > 1 {
                    panic!("Underlying rust bitcoin library does not support multiple data in OP_RETURN")
                }
                Builder::gen_op_return(&data[0]).into_script()
            }
            P2WPKH(wpubkey_hash) => Builder::gen_v0_p2wpkh(&wpubkey_hash).into_script(),
            P2WSH(wscript_hash) => Builder::gen_v0_p2wsh(&wscript_hash).into_script(),
            P2TR(_) => unimplemented!(),
        })
    }
}

impl From<ScriptPubkeyDescriptor> for ScriptPubkeyStructure {
    fn from(descr: ScriptPubkeyDescriptor) -> Self {
        use ScriptPubkeyDescriptor::*;
        use ScriptPubkeyStructure as PkStruct;
        match descr {
            P2S(script) => PkStruct::Custom((*script).clone()),
            P2PK(pubkey) => PkStruct::KeyChecksig(pubkey),
            P2PKH(hash) => PkStruct::KeyHash(hash),
            P2SH(hash) => PkStruct::ScriptHash(hash),
            P2OR(data) => PkStruct::OpReturn(data),
            P2WPKH(hash) => PkStruct::Witness(WitnessVersion::V0, hash.to_vec().into()),
            P2WSH(hash) => PkStruct::Witness(WitnessVersion::V0, hash.to_vec().into()),
            P2TR(pubkey) => {
                PkStruct::Witness(WitnessVersion::V1, pubkey.serialize().to_vec().into())
            }
        }
    }
}
