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

use amplify::Wrapper;
use core::convert::TryFrom;
use regex::Regex;
#[cfg(feature = "serde")]
use serde_with::{hex::Hex, As, DisplayFromStr};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::hash_types::{PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, Fingerprint};
use miniscript::descriptor::DescriptorSinglePub;
use miniscript::policy::compiler::CompilerError;
use miniscript::{
    policy, Miniscript, MiniscriptKey, NullCtx, Segwitv0, ToPublicKey,
};

use super::{
    DerivationComponents, LockScript, PubkeyScript, TapScript, ToLockScript,
    ToPubkeyScript, WitnessVersion,
};
use crate::bp::bip32::{
    ComponentsParseError, DerivationComponentsCtx, UnhardenedIndex,
};
use crate::strict_encoding::{StrictDecode, StrictEncode};

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
pub enum Category {
    /// Bare descriptors: `pk` and bare scripts, including `OP_RETURN`s.
    ///
    /// The script or public key gets right into `scriptPubkey`, i.e. as
    /// **P2PK** (for a public key) or as custom script (mostly used for
    /// `OP_RETURN`)
    #[display("bare")]
    Bare,

    /// Hash-based descriptors: `pkh` for public key hashes and BIP-16 `sh` for
    /// **P2SH** scripts.
    ///
    /// We hash public key or script and use non-SegWit `scriptPubkey`
    /// encoding, i.e. **P2PKH** or **P2SH** with corresponding non-segwit
    /// transaction input `sigScript` containing copy of [`LockScript`] in
    /// `redeemScript` field
    #[display("hashed")]
    Hashed,

    /// SegWit descriptors for legacy wallets defined in BIP 141 as P2SH nested
    /// types <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#P2WPKH_nested_in_BIP16_P2SH>:
    /// `sh(wpkh)` and `sh(wsh)`
    ///
    /// Compatibility variant for SegWit outputs when the SegWit version and
    /// program are encoded as [`RedeemScript`] in `sigScript` transaction
    /// input field, while the original public key or [`WitnessScript`] are
    /// stored in `witness`. `scriptPubkey` contains a normal **P2SH**
    /// composed agains the `redeemScript` from `sigScript`
    /// (**P2SH-P2WPKH** and **P2SH-P2WSH** variants).
    ///
    /// This type works with only with witness version v0, i.e. not applicable
    /// for Taproot.
    #[display("nested")]
    Nested,

    /// Native SegWit descriptors: `wpkh` for public keys and `wsh` for scripts
    ///
    /// We produce either **P2WPKH** or **P2WSH** output and use witness field
    /// in transaction input to store the original [`LockScript`] or the public
    /// key
    #[display("segwit")]
    SegWit,

    /// Native Taproot descriptors: `taproot`
    #[display("taproot")]
    Taproot,
}

/// Errors that happens during [`Category::deduce`] process
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
pub enum DeductionError {
    /// For P2SH scripts we need to know whether it is created for the
    /// witness-containing spending transaction input, i.e. whether its redeem
    /// script will have a witness structure, or not. If this information was
    /// not provided, this error is returned.
    IncompleteInformation,

    /// Here we support only version 0 and 1 of the witness, otherwise this
    /// error is returned
    UnsupportedWitnessVersion(WitnessVersion),
}

impl Category {
    /// Deduction of [`Category`] from a `scriptPubkey` data and,
    /// optionally, information about the presence of the witness for P2SH
    /// `scriptPubkey`'s.
    ///
    /// # Arguments
    ///
    /// * `pubkey_script` - script from transaction output `scriptPubkey`
    /// * `has_witness` - an optional `bool` with the following meaning:
    ///     - `None`: witness presence must be determined from the
    ///       `pubkey_script` value; don't use it for P2SH `scriptPubkey`s,
    ///       otherwise the method will return
    ///       [`DeductionError::IncompleteInformation`] error.
    ///     - `Some(true)`: presence of a witness structure will be required in
    ///       transaction input to spend the given `pubkey_script`, i.e. it was
    ///       composed with P2SH-P2W*H scheme
    ///     - `Some(false)`: if `scriptPubkey` is P2SH, it is a "normal" P2SH
    ///       and was not created with P2SH-P2W*H scheme. The spending
    ///       transaction input would not have `witness` structure.
    ///
    /// # Errors
    ///
    /// The function may [DeductionError] in the following cases
    ///
    /// * `IncompleteInformation`: the provided pubkey script (`pubkey_script`
    ///   argument) is P2SH script, and `has_witness` argument was set to `None`
    ///   (see explanation about the argument usage above).
    /// * `UnsupportedWitnessVersion(WitnessVersion)`: the provided pubkey
    ///   script has a witness version above 1.
    pub fn deduce(
        pubkey_script: &PubkeyScript,
        has_witness: Option<bool>,
    ) -> Result<Category, DeductionError> {
        match pubkey_script.as_inner() {
            p if p.is_v0_p2wpkh() || p.is_v0_p2wsh() => Ok(Category::SegWit),
            p if p.is_witness_program() => {
                const ERR: &'static str =
                    "bitcoin::Script::is_witness_program is broken";
                match WitnessVersion::try_from(
                    p.instructions_minimal().next().expect(ERR).expect(ERR),
                )
                .expect(ERR)
                {
                    WitnessVersion::V0 => unreachable!(),
                    WitnessVersion::V1 => Ok(Category::Taproot),
                    ver => Err(DeductionError::UnsupportedWitnessVersion(ver)),
                }
            }
            p if p.is_p2pkh() => Ok(Category::Hashed),
            p if p.is_p2sh() => match has_witness {
                None => Err(DeductionError::IncompleteInformation),
                Some(true) => Ok(Category::Nested),
                Some(false) => Ok(Category::Hashed),
            },
            _ => Ok(Category::Bare),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, StrictEncode, StrictDecode)]
#[lnpbp_crate(crate)]
#[non_exhaustive]
pub enum Compact {
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
pub enum Expanded {
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

impl From<Expanded> for PubkeyScript {
    fn from(expanded: Expanded) -> PubkeyScript {
        match expanded {
            Expanded::Bare(pubkey_script) => pubkey_script,
            Expanded::Pk(pk) => pk.to_pubkey_script(Category::Bare),
            Expanded::Pkh(pk) => pk.to_pubkey_script(Category::Hashed),
            Expanded::Sh(script) => script.to_pubkey_script(Category::Hashed),
            Expanded::ShWpkh(pk) => pk.to_pubkey_script(Category::Nested),
            Expanded::ShWsh(script) => {
                script.to_pubkey_script(Category::Nested)
            }
            Expanded::Wpkh(pk) => pk.to_pubkey_script(Category::SegWit),
            Expanded::Wsh(script) => script.to_pubkey_script(Category::SegWit),
            Expanded::Taproot(..) => unimplemented!(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Display, Debug, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// Can't deserealized public key from bitcoin script push op code
    InvalidKeyData,

    /// Wrong witness version, may be you need to upgrade used library version
    UnsupportedWitnessVersion,

    /// Policy compilation error
    #[from]
    #[display(inner)]
    PolicyCompilation(CompilerError),
}

impl TryFrom<PubkeyScript> for Compact {
    type Error = Error;
    fn try_from(script_pubkey: PubkeyScript) -> Result<Self, Self::Error> {
        use bitcoin::blockdata::opcodes::all::*;
        use Compact::*;

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

impl From<Compact> for PubkeyScript {
    fn from(spkt: Compact) -> PubkeyScript {
        use Compact::*;

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

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase", untagged)
)]
#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[non_exhaustive]
pub enum SingleSig {
    /// Single known public key
    #[cfg_attr(feature = "serde", serde(skip))]
    Pubkey(
        // TODO: Update serde serializer once miniscript will have
        // Display/FromStr #[cfg_attr(feature = "serde", serde(with =
        // "As::<DisplayFromStr>"))]
        DescriptorSinglePub,
    ),

    /// Public key range with deterministic derivation that can be derived
    /// from a known extended public key without private key
    #[cfg_attr(feature = "serde", serde(rename = "xpub"))]
    XPubDerivable(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        DerivationComponents,
    ),
}

impl Display for SingleSig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SingleSig::Pubkey(pk) => {
                if let Some((fp, path)) = &pk.origin {
                    let path = path.to_string().replace("m/", "");
                    write!(f, "[{}]/{}/", fp, path)?;
                }
                Display::fmt(&pk.key, f)
            }
            SingleSig::XPubDerivable(xpub) => Display::fmt(xpub, f),
        }
    }
}

impl SingleSig {
    pub fn count(&self) -> u32 {
        match self {
            SingleSig::Pubkey(_) => 1,
            SingleSig::XPubDerivable(ref components) => components.count(),
        }
    }
}

impl MiniscriptKey for SingleSig {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash {
        self.clone()
    }
}

impl<'secp, C> ToPublicKey<DerivationComponentsCtx<'secp, C>> for SingleSig
where
    C: 'secp + secp256k1::Verification,
{
    fn to_public_key(
        &self,
        to_pk_ctx: DerivationComponentsCtx<'secp, C>,
    ) -> bitcoin::PublicKey {
        match self {
            SingleSig::Pubkey(ref pkd) => pkd.key.to_public_key(NullCtx),
            SingleSig::XPubDerivable(ref dc) => dc.to_public_key(to_pk_ctx),
        }
    }

    fn hash_to_hash160(
        hash: &Self::Hash,
        to_pk_ctx: DerivationComponentsCtx<'secp, C>,
    ) -> hash160::Hash {
        hash.to_public_key(to_pk_ctx).to_pubkeyhash()
    }
}

impl ToPublicKey<NullCtx> for SingleSig {
    fn to_public_key(&self, to_pk_ctx: NullCtx) -> bitcoin::PublicKey {
        match self {
            SingleSig::Pubkey(ref pkd) => pkd.key.to_public_key(to_pk_ctx),
            SingleSig::XPubDerivable(ref dc) => {
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

impl FromStr for SingleSig {
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
            Ok(SingleSig::Pubkey(DescriptorSinglePub { origin, key }))
        } else {
            Ok(SingleSig::XPubDerivable(DerivationComponents::from_str(s)?))
        }
    }
}

/// Allows creating templates for native bitcoin scripts with embedded
/// key generator templates. May be useful for creating descriptors in
/// situations where target script can't be deterministically represented by
/// miniscript, for instance for Lightning network-specific transaction outputs
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Hash,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
pub enum OpcodeTemplate<Pk>
where
    Pk: MiniscriptKey + StrictEncode + StrictDecode,
    <Pk as FromStr>::Err: Display,
{
    /// Normal script command (OP_CODE)
    #[display("opcode({0})")]
    OpCode(u8),

    /// Binary data (follows push commands)
    #[display("data({0:#x?})")]
    Data(#[cfg_attr(feature = "serde", serde(with = "As::<Hex>"))] Box<[u8]>),

    /// Key template
    #[display("key({0})")]
    Key(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))] Pk,
    ),
}

impl<Pk> OpcodeTemplate<Pk>
where
    Pk: MiniscriptKey
        + ToPublicKey<DerivationComponentsCtx<'static, secp256k1::All>>
        + StrictEncode
        + StrictDecode,
    <Pk as FromStr>::Err: Display,
{
    fn translate_pk(
        &self,
        child_index: UnhardenedIndex,
    ) -> OpcodeTemplate<bitcoin::PublicKey> {
        match self {
            OpcodeTemplate::OpCode(code) => OpcodeTemplate::OpCode(*code),
            OpcodeTemplate::Data(data) => OpcodeTemplate::Data(data.clone()),
            OpcodeTemplate::Key(key) => OpcodeTemplate::Key(key.to_public_key(
                DerivationComponentsCtx {
                    secp_ctx: &*crate::SECP256K1,
                    child_number: child_index.into(),
                },
            )),
        }
    }
}

/// Allows creating templates for native bitcoin scripts with embedded
/// key generator templates. May be useful for creating descriptors in
/// situations where target script can't be deterministically represented by
/// miniscript, for instance for Lightning network-specific transaction outputs
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    From,
    StrictEncode,
    StrictDecode,
)]
#[wrap(Index, IndexMut, IndexFull, IndexFrom, IndexTo, IndexInclusive)]
#[lnpbp_crate(crate)]
pub struct ScriptTemplate<Pk>(Vec<OpcodeTemplate<Pk>>)
where
    Pk: MiniscriptKey + StrictEncode + StrictDecode,
    <Pk as FromStr>::Err: Display;

impl<Pk> Display for ScriptTemplate<Pk>
where
    Pk: MiniscriptKey + StrictEncode + StrictDecode,
    <Pk as FromStr>::Err: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for instruction in &self.0 {
            Display::fmt(instruction, f)?;
        }
        Ok(())
    }
}

impl<Pk> ScriptTemplate<Pk>
where
    Pk: MiniscriptKey
        + StrictEncode
        + StrictDecode
        + ToPublicKey<DerivationComponentsCtx<'static, secp256k1::All>>,
    <Pk as FromStr>::Err: Display,
{
    fn translate_pk(
        &self,
        child_index: UnhardenedIndex,
    ) -> ScriptTemplate<bitcoin::PublicKey> {
        self.0
            .iter()
            .map(|op| op.translate_pk(child_index))
            .collect::<Vec<_>>()
            .into()
    }
}

impl From<ScriptTemplate<bitcoin::PublicKey>> for Script {
    fn from(template: ScriptTemplate<bitcoin::PublicKey>) -> Self {
        let mut builder = Builder::new();
        for op in template.into_inner() {
            builder = match op {
                OpcodeTemplate::OpCode(code) => {
                    builder.push_opcode(opcodes::All::from(code))
                }
                OpcodeTemplate::Data(data) => builder.push_slice(&data),
                OpcodeTemplate::Key(key) => builder.push_key(&key),
            };
        }
        builder.into_script()
    }
}

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[non_exhaustive]
#[lnpbp_crate(crate)]
pub enum ScriptConstruction {
    #[cfg_attr(feature = "serde", serde(rename = "script"))]
    #[display(inner)]
    ScriptTemplate(ScriptTemplate<SingleSig>),

    #[display(inner)]
    Miniscript(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        Miniscript<SingleSig, Segwitv0>,
    ),

    #[cfg_attr(feature = "serde", serde(rename = "policy"))]
    #[display(inner)]
    MiniscriptPolicy(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        policy::Concrete<SingleSig>,
    ),
}

// TODO: Remove after <https://github.com/rust-bitcoin/rust-miniscript/pull/224>
impl std::hash::Hash for ScriptConstruction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_string().hash(state)
    }
}

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
pub struct ScriptSource {
    pub script: ScriptConstruction,

    pub source: Option<String>,

    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    pub tweak_target: Option<SingleSig>,
}

impl Display for ScriptSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(ref source) = self.source {
            f.write_str(source)
        } else {
            Display::fmt(&self.script, f)
        }
    }
}

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
pub struct MultiSig {
    pub threshold: Option<u8>,

    #[cfg_attr(feature = "serde", serde(with = "As::<Vec<DisplayFromStr>>"))]
    pub pubkeys: Vec<SingleSig>,

    pub reorder: bool,
}

impl Display for MultiSig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "multi({},", self.threshold())?;
        f.write_str(
            &self
                .pubkeys
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )?;
        f.write_str(")")
    }
}

impl MultiSig {
    pub fn threshold(&self) -> usize {
        self.threshold
            .map(|t| t as usize)
            .unwrap_or(self.pubkeys.len())
    }

    pub fn to_public_keys(
        &self,
        child_index: UnhardenedIndex,
    ) -> Vec<bitcoin::PublicKey> {
        let mut set = self
            .pubkeys
            .iter()
            .map(|key| {
                key.to_public_key(DerivationComponentsCtx {
                    secp_ctx: &*crate::SECP256K1,
                    child_number: child_index.into(),
                })
            })
            .collect::<Vec<_>>();
        if self.reorder {
            set.sort();
        }
        set
    }
}

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Hash,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
pub struct MuSigBranched {
    #[cfg_attr(feature = "serde", serde(with = "As::<Vec<DisplayFromStr>>"))]
    pub extra_keys: Vec<SingleSig>,

    pub tapscript: ScriptConstruction,

    pub source: Option<String>,
}

impl Display for MuSigBranched {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{};", self.tapscript)?;
        f.write_str(
            &self
                .extra_keys
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename = "lowercase")
)]
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
#[non_exhaustive]
#[lnpbp_crate(crate)]
pub enum Template {
    #[display(inner)]
    SingleSig(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        SingleSig,
    ),

    #[display(inner)]
    MultiSig(MultiSig),

    #[display(inner)]
    Scripted(ScriptSource),

    #[cfg_attr(feature = "serde", serde(rename = "musig"))]
    #[display(inner)]
    MuSigBranched(MuSigBranched),
}

impl Template {
    pub fn is_singlesig(&self) -> bool {
        match self {
            Template::SingleSig(_) => true,
            _ => false,
        }
    }

    pub fn to_public_key(
        &self,
        child_index: UnhardenedIndex,
    ) -> Option<bitcoin::PublicKey> {
        match self {
            Template::SingleSig(key) => {
                Some(key.to_public_key(DerivationComponentsCtx {
                    secp_ctx: &*crate::SECP256K1,
                    child_number: child_index.into(),
                }))
            }
            _ => None,
        }
    }
}

pub trait DeriveLockScript {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        descr_category: Category,
    ) -> Result<LockScript, Error>;
}

impl DeriveLockScript for SingleSig {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        descr_category: Category,
    ) -> Result<LockScript, Error> {
        let pk = self.to_public_key(DerivationComponentsCtx {
            secp_ctx: &*crate::SECP256K1,
            child_number: child_index.into(),
        });
        Ok(pk.to_lock_script(descr_category))
    }
}

impl DeriveLockScript for MultiSig {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        descr_category: Category,
    ) -> Result<LockScript, Error> {
        let ctx = DerivationComponentsCtx {
            secp_ctx: &*crate::SECP256K1,
            child_number: child_index.into(),
        };
        match descr_category {
            Category::SegWit | Category::Nested => {
                let ms = Miniscript::<_, miniscript::Segwitv0>::from_ast(
                    miniscript::Terminal::Multi(
                        self.threshold(),
                        self.pubkeys.clone(),
                    ),
                )
                .expect("miniscript is unable to produce mutisig");
                Ok(ms.encode(ctx).into())
            }
            Category::Taproot => unimplemented!(),
            _ => {
                let ms = Miniscript::<_, miniscript::Legacy>::from_ast(
                    miniscript::Terminal::Multi(
                        self.threshold(),
                        self.pubkeys.clone(),
                    ),
                )
                .expect("miniscript is unable to produce mutisig");
                Ok(ms.encode(ctx).into())
            }
        }
    }
}

impl DeriveLockScript for ScriptSource {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        _: Category,
    ) -> Result<LockScript, Error> {
        let ms = match &self.script {
            ScriptConstruction::Miniscript(ms) => ms.clone(),
            ScriptConstruction::MiniscriptPolicy(policy) => policy.compile()?,
            ScriptConstruction::ScriptTemplate(template) => {
                return Ok(
                    Script::from(template.translate_pk(child_index)).into()
                )
            }
        };

        Ok(ms
            .encode(DerivationComponentsCtx {
                secp_ctx: &*crate::SECP256K1,
                child_number: child_index.into(),
            })
            .into())
    }
}

impl DeriveLockScript for MuSigBranched {
    fn derive_lock_script(
        &self,
        _child_index: UnhardenedIndex,
        _descr_category: Category,
    ) -> Result<LockScript, Error> {
        // TODO: Implement after Taproot release
        unimplemented!()
    }
}

impl DeriveLockScript for Template {
    fn derive_lock_script(
        &self,
        child_index: UnhardenedIndex,
        descr_category: Category,
    ) -> Result<LockScript, Error> {
        match self {
            Template::SingleSig(key) => {
                key.derive_lock_script(child_index, descr_category)
            }
            Template::MultiSig(multisig) => {
                multisig.derive_lock_script(child_index, descr_category)
            }
            Template::Scripted(scripted) => {
                scripted.derive_lock_script(child_index, descr_category)
            }
            Template::MuSigBranched(musig) => {
                musig.derive_lock_script(child_index, descr_category)
            }
        }
    }
}

#[derive(
    Clone,
    Copy,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Default,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
pub struct Variants {
    pub bare: bool,
    pub hashed: bool,
    pub nested: bool,
    pub segwit: bool,
    pub taproot: bool,
}

#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
/// Error parsing descriptor variants: unrecognized string
pub struct VariantsParseError;

impl Display for Variants {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut comps = Vec::with_capacity(5);
        if self.bare {
            comps.push(if f.alternate() { "bare" } else { "b" });
        }
        if self.hashed {
            comps.push(if f.alternate() { "hashed" } else { "h" });
        }
        if self.nested {
            comps.push(if f.alternate() { "nested" } else { "n" });
        }
        if self.segwit {
            comps.push(if f.alternate() { "segwit" } else { "s" });
        }
        if self.taproot {
            comps.push(if f.alternate() { "taproot" } else { "t" });
        }
        f.write_str(&comps.join("|"))
    }
}

impl FromStr for Variants {
    type Err = VariantsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut dv = Variants::default();
        for item in s.split('|') {
            match item.to_lowercase().as_str() {
                "b" | "bare" => dv.bare = true,
                "h" | "hashed" => dv.hashed = true,
                "n" | "nested" => dv.nested = true,
                "s" | "segwit" => dv.segwit = true,
                "t" | "taproot" => dv.taproot = true,
                _ => Err(VariantsParseError)?,
            }
        }
        Ok(dv)
    }
}

impl Variants {
    pub fn count(&self) -> u32 {
        self.bare as u32
            + self.hashed as u32
            + self.nested as u32
            + self.segwit as u32
            + self.taproot as u32
    }

    pub fn has_match(&self, category: Category) -> bool {
        match category {
            Category::Bare => self.bare,
            Category::Hashed => self.hashed,
            Category::Nested => self.nested,
            Category::SegWit => self.segwit,
            Category::Taproot => self.taproot,
        }
    }
}

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[display("{variants}({template})")]
#[lnpbp_crate(crate)]
pub struct Generator {
    pub template: Template,

    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    pub variants: Variants,
}

impl Generator {
    pub fn descriptors(
        &self,
        index: UnhardenedIndex,
    ) -> Result<HashMap<Category, Expanded>, Error> {
        let mut descriptors = HashMap::with_capacity(5);
        let single = if let Template::SingleSig(_) = self.template {
            Some(self.template.to_public_key(index).expect("Can't fail"))
        } else {
            None
        };
        if self.variants.bare {
            let d = if let Some(pk) = single {
                Expanded::Pk(pk)
            } else {
                Expanded::Bare(
                    self.template
                        .derive_lock_script(index, Category::Bare)?
                        .into_inner()
                        .into(),
                )
            };
            descriptors.insert(Category::Bare, d);
        }
        if self.variants.hashed {
            let d = if let Some(pk) = single {
                Expanded::Pkh(pk)
            } else {
                Expanded::Sh(
                    self.template
                        .derive_lock_script(index, Category::Hashed)?,
                )
            };
            descriptors.insert(Category::Hashed, d);
        }
        if self.variants.nested {
            let d = if let Some(pk) = single {
                Expanded::ShWpkh(pk)
            } else {
                Expanded::ShWsh(
                    self.template
                        .derive_lock_script(index, Category::Nested)?,
                )
            };
            descriptors.insert(Category::Nested, d);
        }
        if self.variants.segwit {
            let d = if let Some(pk) = single {
                Expanded::Wpkh(pk)
            } else {
                Expanded::Wsh(
                    self.template
                        .derive_lock_script(index, Category::SegWit)?,
                )
            };
            descriptors.insert(Category::SegWit, d);
        }
        /* TODO: Enable once Taproot will go live
        if self.variants.taproot {
            scripts.push(content.taproot());
        }
         */
        Ok(descriptors)
    }

    #[inline]
    pub fn pubkey_scripts(
        &self,
        index: UnhardenedIndex,
    ) -> Result<HashMap<Category, Script>, Error> {
        Ok(self
            .descriptors(index)?
            .into_iter()
            .map(|(cat, descr)| (cat, PubkeyScript::from(descr).into()))
            .collect())
    }
}
