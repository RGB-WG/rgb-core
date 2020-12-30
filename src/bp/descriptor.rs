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

use core::convert::TryFrom;
use regex::Regex;
use std::str::FromStr;

use bitcoin;
use bitcoin::blockdata::script::Script;
use bitcoin::hash_types::{PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, Fingerprint};
use miniscript::descriptor::DescriptorSinglePub;
use miniscript::{MiniscriptKey, NullCtx, ToPublicKey};

use super::{LockScript, PubkeyScript, TapScript};
use crate::bp::bip32::{ComponentsParseError, DerivationComponentsCtx};
use crate::bp::DerivationComponents;

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

#[derive(Clone, PartialEq, Eq, Debug, Display, StrictEncode, StrictDecode)]
#[lnpbp_crate(crate)]
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

#[derive(Clone, PartialEq, Eq, Debug, Display, StrictEncode, StrictDecode)]
#[lnpbp_crate(crate)]
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

#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(inner)]
#[non_exhaustive]
pub enum PubkeyPlaceholder {
    /// Single known public key
    Pubkey(DescriptorSinglePub),

    /// Public key range with deterministic derivation that can be derived
    /// from a known extended public key without private key
    XPubDerivable(DerivationComponents),
}

impl PubkeyPlaceholder {
    pub fn count(&self) -> u32 {
        match self {
            PubkeyPlaceholder::Pubkey(_) => 1,
            PubkeyPlaceholder::XPubDerivable(ref components) => {
                components.count()
            }
        }
    }
}

impl MiniscriptKey for PubkeyPlaceholder {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash {
        self.clone()
    }
}

impl<'secp, C> ToPublicKey<DerivationComponentsCtx<'secp, C>>
    for PubkeyPlaceholder
where
    C: 'secp + secp256k1::Verification,
{
    fn to_public_key(
        &self,
        to_pk_ctx: DerivationComponentsCtx<'secp, C>,
    ) -> bitcoin::PublicKey {
        match self {
            PubkeyPlaceholder::Pubkey(ref pkd) => {
                pkd.key.to_public_key(NullCtx)
            }
            PubkeyPlaceholder::XPubDerivable(ref dc) => {
                dc.to_public_key(to_pk_ctx)
            }
        }
    }

    fn hash_to_hash160(
        hash: &Self::Hash,
        to_pk_ctx: DerivationComponentsCtx<'secp, C>,
    ) -> hash160::Hash {
        hash.to_public_key(to_pk_ctx).to_pubkeyhash()
    }
}

impl ToPublicKey<NullCtx> for PubkeyPlaceholder {
    fn to_public_key(&self, to_pk_ctx: NullCtx) -> bitcoin::PublicKey {
        match self {
            PubkeyPlaceholder::Pubkey(ref pkd) => {
                pkd.key.to_public_key(to_pk_ctx)
            }
            PubkeyPlaceholder::XPubDerivable(ref dc) => {
                dc.to_public_key(DerivationComponentsCtx::new(
                    &*crate::SECP256K1,
                    ChildNumber::Normal { index: 0 },
                ))
            }
        }
    }

    fn hash_to_hash160(hash: &Self::Hash, to_pk_ctx: NullCtx) -> hash160::Hash {
        hash.to_public_key(to_pk_ctx).to_pubkeyhash()
    }
}

impl FromStr for PubkeyPlaceholder {
    type Err = ComponentsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        static ERR: &'static str =
            "wrong build-in pubkey placeholder regex parsing syntax";

        lazy_static! {
            static ref RE_PUBKEY: Regex = Regex::new(
                r"(?x)^
                (\[
                    (?P<fingerprint>[0-9A-Fa-f]{8})      # Fingerprint
                    (?P<deviation>(/[0-9]{1,10}[h']?)+)  # Derivation path
                \])?
                (?P<pubkey>0[2-3][0-9A-Fa-f]{64}) |      # Compressed pubkey
                (?P<pubkey_long>04[0-9A-Fa-f]{128})      # Non-compressed pubkey
                $",
            )
            .expect(ERR);
        }
        if let Some(caps) = RE_PUBKEY.captures(s) {
            let origin = if let Some((fp, deriv)) =
                caps.name("fingerprint").map(|fp| {
                    (fp.as_str(), caps.name("derivation").expect(ERR).as_str())
                }) {
                let fp = fp
                    .parse::<Fingerprint>()
                    .map_err(|err| ComponentsParseError(err.to_string()))?;
                let deriv = format!("m/{}", deriv)
                    .parse::<DerivationPath>()
                    .map_err(|err| ComponentsParseError(err.to_string()))?;
                Some((fp, deriv))
            } else {
                None
            };
            let key = bitcoin::PublicKey::from_str(
                caps.name("pubkey")
                    .or(caps.name("pubkey_long"))
                    .expect(ERR)
                    .as_str(),
            )
            .map_err(|err| ComponentsParseError(err.to_string()))?;
            Ok(PubkeyPlaceholder::Pubkey(DescriptorSinglePub {
                origin,
                key,
            }))
        } else {
            Ok(PubkeyPlaceholder::XPubDerivable(
                DerivationComponents::from_str(s)?,
            ))
        }
    }
}
