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
#[non_exhaustive]
pub enum ScriptPubkeyContent {
    #[display("script({0})", alt = "script({_0:#})")]
    Bare(PubkeyScript),

    #[display("pk({0})")]
    Pk(bitcoin::PublicKey),

    #[display("pkh({0})")]
    Pkh(PubkeyHash),

    #[display("sh({0})")]
    Sh(ScriptHash),

    #[display("script(OP_RETURN {_0:?})")]
    Return(Vec<Vec<u8>>),

    #[display("wpkh({0})")]
    Wpkh(WPubkeyHash),

    #[display("wsh({0})")]
    Wsh(WScriptHash),

    #[display("tr({0})")]
    Taproot(secp256k1::PublicKey),
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display(Debug)]
#[non_exhaustive]
pub enum ScriptPubkeyTemplate {
    Bare(PubkeyScript),
    Pk(bitcoin::PublicKey),
    Pkh(bitcoin::PublicKey),
    Sh(LockScript),
    Return(Vec<Vec<u8>>),
    #[allow(non_camel_case_types)]
    ShWpkh(bitcoin::PublicKey),
    #[allow(non_camel_case_types)]
    ShWsh(LockScript),
    Wpkh(bitcoin::PublicKey),
    Wsh(LockScript),
    Taproot(secp256k1::PublicKey, TapScript),
}

#[derive(Clone, Copy, PartialEq, Eq, Display, Debug, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// Can't deserealized public key from bitcoin script push op code
    InvalidKeyData,
    /// Wrong witness version, may be you need to upgrade used library version
    UnsupportedWitnessVersion,
}

impl TryFrom<PubkeyScript> for ScriptPubkeyContent {
    type Error = Error;
    fn try_from(script_pubkey: PubkeyScript) -> Result<Self, Self::Error> {
        use bitcoin::blockdata::opcodes::all::*;
        use ScriptPubkeyContent::*;

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
                Pk(key)
            }
            s if s.is_p2pkh() => Pkh(
                PubkeyHash::from_slice(&p[2..23]).expect("Reading hash from fixed slice failed"),
            ),
            s if s.is_p2sh() => Sh(
                ScriptHash::from_slice(&p[1..22]).expect("Reading hash from fixed slice failed"),
            ),
            s if s.is_v0_p2wpkh() => Wpkh(
                WPubkeyHash::from_slice(&p[2..23]).expect("Reading hash from fixed slice failed"),
            ),
            s if s.is_v0_p2wsh() => Wsh(
                WScriptHash::from_slice(&p[2..34]).expect("Reading hash from fixed slice failed"),
            ),
            s if s.is_witness_program() => Err(Error::UnsupportedWitnessVersion)?,
            s if s.is_op_return() => Return(
                Script::from(p[1..].to_vec())
                    .instructions()
                    .map(|instr| {
                        if let Ok(Instruction::PushBytes(data)) = instr {
                            data.to_vec()
                        } else {
                            panic!("Rust bitcoin library broken in script parsing functionality")
                        }
                    })
                    .collect(),
            ),
            _ => Bare(script_pubkey),
        })
    }
}

impl From<ScriptPubkeyContent> for PubkeyScript {
    fn from(spkt: ScriptPubkeyContent) -> PubkeyScript {
        use ScriptPubkeyContent::*;

        PubkeyScript::from(match spkt {
            Bare(script) => (*script).clone(),
            Pk(pubkey) => Script::new_p2pk(&pubkey),
            Pkh(pubkey_hash) => Script::new_p2pkh(&pubkey_hash),
            Sh(script_hash) => Script::new_p2sh(&script_hash),
            Return(data) => {
                if data.len() > 1 {
                    panic!("Underlying rust bitcoin library does not support multiple data in OP_RETURN")
                }
                Script::new_op_return(&data[0])
            }
            Wpkh(wpubkey_hash) => Script::new_v0_wpkh(&wpubkey_hash),
            Wsh(wscript_hash) => Script::new_v0_wsh(&wscript_hash),
            Taproot(_) => unimplemented!(),
        })
    }
}

impl From<ScriptPubkeyContent> for ScriptPubkeyStructure {
    fn from(descr: ScriptPubkeyContent) -> Self {
        use ScriptPubkeyContent::*;
        use ScriptPubkeyStructure as PkStruct;
        match descr {
            Bare(script) => PkStruct::Custom((*script).clone()),
            Pk(pubkey) => PkStruct::KeyChecksig(pubkey),
            Pkh(hash) => PkStruct::KeyHash(hash),
            Sh(hash) => PkStruct::ScriptHash(hash),
            Return(data) => PkStruct::OpReturn(data),
            Wpkh(hash) => {
                PkStruct::Witness(WitnessVersion::V0, hash.to_vec().into())
            }
            Wsh(hash) => {
                PkStruct::Witness(WitnessVersion::V0, hash.to_vec().into())
            }
            Taproot(pubkey) => PkStruct::Witness(
                WitnessVersion::V1,
                pubkey.serialize().to_vec().into(),
            ),
        }
    }
}
