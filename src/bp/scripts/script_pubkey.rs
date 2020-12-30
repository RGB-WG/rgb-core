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

    /// Custom (i.e. non-standard) output with arbitrary script
    Custom,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[non_exhaustive]
pub enum ScriptPubkeyContent {
    #[display("bare({0})", alt = "bare({_0:#})")]
    Bare(PubkeyScript),

    #[display("pk({0})")]
    Pk(bitcoin::PublicKey),

    #[display("pkh({0})")]
    Pkh(PubkeyHash),

    #[display("sh({0})")]
    Sh(ScriptHash),

    #[display("wpkh({0})")]
    Wpkh(WPubkeyHash),

    #[display("wsh({0})")]
    Wsh(WScriptHash),

    #[display("tr({0})")]
    Taproot(secp256k1::PublicKey),
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[non_exhaustive]
pub enum ScriptPubkeyTemplate {
    #[display("bare({0})", alt = "bare({_0:#})")]
    Bare(PubkeyScript),

    #[display("pk({0})")]
    Pk(bitcoin::PublicKey),

    #[display("pkh({0})")]
    Pkh(bitcoin::PublicKey),

    #[display("sh({0})")]
    Sh(LockScript),

    #[display("sh(wpkh({0}))", alt = "sh(wpkh({_0:#}))")]
    ShWpkh(bitcoin::PublicKey),

    #[display("sh(wsh({0}))")]
    ShWsh(LockScript),

    #[display("wpkh({0})")]
    Wpkh(bitcoin::PublicKey),

    #[display("wsh({0})")]
    Wsh(LockScript),

    #[display("tr({0})")]
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
                    OP_PUSHBYTES_65 => {
                        bitcoin::PublicKey::from_slice(&p[1..66])
                    }
                    OP_PUSHBYTES_33 => {
                        bitcoin::PublicKey::from_slice(&p[1..34])
                    }
                    _ => panic!("Reading hash from fixed slice failed"),
                }
                .map_err(|_| Error::InvalidKeyData)?;
                Pk(key)
            }
            s if s.is_p2pkh() => Pkh(PubkeyHash::from_slice(&p[2..23])
                .expect("Reading hash from fixed slice failed")),
            s if s.is_p2sh() => Sh(ScriptHash::from_slice(&p[1..22])
                .expect("Reading hash from fixed slice failed")),
            s if s.is_v0_p2wpkh() => Wpkh(
                WPubkeyHash::from_slice(&p[2..23])
                    .expect("Reading hash from fixed slice failed"),
            ),
            s if s.is_v0_p2wsh() => Wsh(WScriptHash::from_slice(&p[2..34])
                .expect("Reading hash from fixed slice failed")),
            s if s.is_witness_program() => {
                Err(Error::UnsupportedWitnessVersion)?
            }
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
