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

/// Descriptor category specifies way how the `scriptPubkey` is structured
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    Hash,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[non_exhaustive]
pub enum DescriptorCategory {
    /// Bare descriptors: `pk` and bare scripts, including `OP_RETURN`s
    #[display("bare")]
    Bare,

    /// Hash-based descriptors: `pkh` for public key hashes and BIP-16 `sh` for
    /// P2SH scripts
    #[display("hashed")]
    Hashed,

    /// SegWit descriptors for legacy wallets defined in BIP 141 as P2SH nested
    /// types <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#P2WPKH_nested_in_BIP16_P2SH>:
    /// `sh(wpkh)` and `sh(wsh)`
    #[display("nested")]
    Nested,

    /// Native SegWit descriptors: `wpkh` for public keys and `wsh` for scripts
    #[display("segwit")]
    SegWit,

    /// Netive Taproot descriptors: `taproot`
    #[display("taproot")]
    Taproot,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[non_exhaustive]
pub enum CompactDescriptor {
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
pub enum ExpandedDescriptor {
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

impl TryFrom<PubkeyScript> for CompactDescriptor {
    type Error = Error;
    fn try_from(script_pubkey: PubkeyScript) -> Result<Self, Self::Error> {
        use bitcoin::blockdata::opcodes::all::*;
        use CompactDescriptor::*;

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

impl From<CompactDescriptor> for PubkeyScript {
    fn from(spkt: CompactDescriptor) -> PubkeyScript {
        use CompactDescriptor::*;

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
