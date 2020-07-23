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

//! # Bitcoin script types
//!
//! Bitcoin doesn't make a distinction between Bitcoin script coming from different sources, like
//! *scriptPubKey* in transaction output or witness and *sigScript* in transaction input. There are
//! many other possible script containers for Bitcoin script: redeem script, witness script,
//! tapscript. In fact, any "script" of `Script` type can be used for inputs and outputs.
//! What is a valid script for one will be a valid script for the other; the only req. is formatting
//! of opcodes & pushes. That would mean that in principle every input script can be used as an
//! output script, btu not vice versa. But really what makes a "script" is just the fact that it's
//! formatted correctly.
//!
//! While all `Script`s represent the same type **semantically**, there is a clear distinction
//! at the **logical** level: Bitcoin script has the property to be committed into some other
//! Bitcoin script – in a nested structures like in several layers, like *redeemScript* inside of
//! *sigScript* used for P2SH, or *tapScript* within *witnessScript* coming from *witness* field
//! for Taproot. These nested layers do distinguish on the information they contain, since some of
//! them only commit to the hashes of the nested scripts (`ScriptHash`, `WitnessProgramm`) or
//! public keys (`PubkeyHash`, `WPubkeyHash`), while other contain the full source of the script.
//!
//! The present type system represents a solution to the problem: it distinguish different logical
//! types by introducing `Script` wrapper types. It defines `LockScript` as bottom layer of a script
//! hierarchy, containing no other script commitments (in form of their hashes). It also defines
//! types above on it: `PubkeyScript` (for whatever is there in `pubkeyScript` field of a `TxOut`),
//! `SigScript` (for whatever comes from `sigScript` field of `TxIn`), `RedeemScript` and `TapScript`.
//! Then, there are conversion functions, which for instance can analyse `PubkeyScript`
//! and if it is a custom script or P2PK return a `LockScript` type - or otherwise fail with the
//! error. So with this type system one is always sure which logical information it does contain.
//!
//! ## Type derivation
//!
//! The following charts represent possible relations between script types:
//!
//! ```text
//!                                                                            LockScript
//!                                                                _________________________________
//!                                                                ^      ^  ^    ^                ^
//!                                                                |      |  |    |                |
//! [txout.scriptPubKey] <===> PubkeyScript --?--/P2PK & custom/---+      |  |    |                |
//!                                                                       |  |    |                |
//! [txin.sigScript] <===> SigScript --+--?!--/P2(W)PKH/--(#=PubkeyHash)--+  |    |                |
//!                                    |                                     |    |                |
//!                                    |                           (#=ScriptHash) |                |
//!                                    |                                     |    |                |
//!                                    +--?!--> RedeemScript --+--?!------/P2SH/  |                |
//!                                                            |                  |                |
//!                                                  /P2WSH-in-P2SH/  /#=V0_WitnessProgram_P2WSH/  |
//!                                                            |                  |                |
//!                                                            +--?!--> WitnessScript              |
//!                                                                       ^^      |                |
//!                                                                       || /#=V1_WitnessProgram/ |
//!                                                                       ||      |                |
//! [?txin.witness] <=====================================================++      +--?---> TapScript
//!
//! ```
//! Legend:
//! * `[source] <===> `: data source
//! * `[?source] <===> `: data source which may be absent
//! * `--+--`: algorithmic branching (alternative computation options)
//! * `--?-->`: a conversion exists, but it may fail (returns `Option` or `Result`)
//! * `--?!-->`: a conversion exists, but it may fail; however one of alternative branches must
//!              always succeed
//! * `----->`: a conversion exists which can't fail
//! * `--/format/--`: a format implied by scriptPubKey program
//! * `--(#=type)--`: the hash of the value following `->` must match to the value of the `<type>`
//!
//! ## Type conversion
//!
//! ```text
//! LockScript -+-> (PubkeyScript, RedeemScript) -+-> SigScript
//!             |                                 +-> WitnessScript
//!             +-> PubkeyScript
//!             |
//!             +-> TapScript
//!
//! PubkeyScript -+-?-> LockScript
//! ```
//!

use amplify::Wrapper;
use bitcoin::{
    blockdata::{opcodes, opcodes::All, script::*},
    secp256k1, ScriptHash, WPubkeyHash, WScriptHash,
};
use core::convert::TryFrom;

use crate::strict_encoding;

wrapper!(
    LockScript,
    Script,
    doc = "\
    Script which knowledge is required for spending some specific transaction output.
    This is the deepest nested version of Bitcoin script containing no hashes of other \
    scripts, including P2SH redeemScript hashes or witnessProgram (hash or witness \
    script), or public keys",
    derive = [Default, PartialEq, Eq, PartialOrd, Ord, Hash]
);

impl strict_encoding::Strategy for LockScript {
    type Strategy = strict_encoding::strategies::Wrapped;
}

wrapper!(
    PubkeyScript,
    Script,
    doc = "\
    A content of `scriptPubkey` from a transaction output",
    derive = [Default, PartialEq, Eq, PartialOrd, Ord, Hash]
);

wrapper!(
    SigScript,
    Script,
    doc = "\
    A content of `sigScript` from a transaction input",
    derive = [Default, PartialEq, Eq, PartialOrd, Ord, Hash]
);

wrapper!(
    Witness,
    Vec<Vec<u8>>,
    doc = "\
    A content of the `witness` field from a transaction input according to BIP-141",
    derive = [Default, PartialEq, Eq, PartialOrd, Ord, Hash]
);

wrapper!(
    RedeemScript,
    Script,
    doc = "\
    `redeemScript` as part of the `witness` or `sigScript` structure; it is \
    hashed for P2(W)SH output",
    derive = [Default, PartialEq, Eq, PartialOrd, Ord, Hash]
);

impl RedeemScript {
    pub fn script_hash(&self) -> ScriptHash {
        self.as_inner().script_hash()
    }
}

impl From<LockScript> for RedeemScript {
    fn from(lock_script: LockScript) -> Self {
        RedeemScript(lock_script.to_inner())
    }
}

wrapper!(
    WitnessScript,
    Script,
    doc = "\
    A content of the script from `witness` structure; en equivalent of \
    `redeemScript` for witness-based transaction inputs. However, unlike \
    [RedeemScript], [WitnessScript] produce SHA256-based hashes of \
    [WScriptHash] type",
    derive = [Default, PartialEq, Eq, PartialOrd, Ord, Hash]
);

impl WitnessScript {
    pub fn script_hash(&self) -> WScriptHash {
        self.as_inner().wscript_hash()
    }
}

impl From<LockScript> for WitnessScript {
    fn from(lock_script: LockScript) -> Self {
        WitnessScript(lock_script.to_inner())
    }
}

wrapper!(
    TapScript,
    Script,
    doc = "\
    Any valid branch of Tapscript (BIP-342)",
    derive = [Default, PartialEq, Eq, PartialOrd, Ord, Hash]
);

/// Version of the WitnessProgram: first byte of `scriptPubkey` in
/// transaciton output for transactions starting with opcodes ranging from 0
/// to 16 (inclusive).
///
/// Structure helps to limit possible version of the witness according to the
/// specification; if a plain `u8` type will be used instead it will mean that
/// version > 16, which is incorrect.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display_from(Debug)]
#[repr(u8)]
pub enum WitnessVersion {
    /// Current, initial version of Witness Program. Used for P2WPKH and P2WPK
    /// outputs
    V0 = 0,

    /// Forthcoming second version of Witness Program, which (most probably)
    /// will be used for Taproot
    V1 = 1,

    /// Future (unsupported) version of Witness Program
    V2 = 2,
    /// Future (unsupported) version of Witness Program
    V3 = 3,
    /// Future (unsupported) version of Witness Program
    V4 = 4,
    /// Future (unsupported) version of Witness Program
    V5 = 5,
    /// Future (unsupported) version of Witness Program
    V6 = 6,
    /// Future (unsupported) version of Witness Program
    V7 = 7,
    /// Future (unsupported) version of Witness Program
    V8 = 8,
    /// Future (unsupported) version of Witness Program
    V9 = 9,
    /// Future (unsupported) version of Witness Program
    V10 = 10,
    /// Future (unsupported) version of Witness Program
    V11 = 11,
    /// Future (unsupported) version of Witness Program
    V12 = 12,
    /// Future (unsupported) version of Witness Program
    V13 = 13,
    /// Future (unsupported) version of Witness Program
    V14 = 14,
    /// Future (unsupported) version of Witness Program
    V15 = 15,
    /// Future (unsupported) version of Witness Program
    V16 = 16,
}

/// A error covering only one possible failure in WitnessVersion creation:
/// when the provided version > 16
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display_from(Debug)]
pub enum WitnessVersionError {
    /// The opocde provided for the version construction is incorrect
    IncorrectOpcode,
}

impl TryFrom<u8> for WitnessVersion {
    type Error = WitnessVersionError;

    /// Takes bitcoin Script value and returns either corresponding version of
    /// the Witness program (for opcodes in range of `OP_0`..`OP_16`) or
    /// [WitnessVersionError::IncorrectOpcode] error for the rest of opcodes
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use WitnessVersion::*;
        Ok(match value {
            0 => V0,
            1 => V1,
            2 => V2,
            3 => V3,
            4 => V4,
            5 => V5,
            6 => V6,
            7 => V7,
            8 => V8,
            9 => V9,
            10 => V10,
            11 => V11,
            12 => V12,
            13 => V13,
            14 => V14,
            15 => V15,
            16 => V16,
            _ => Err(WitnessVersionError::IncorrectOpcode)?,
        })
    }
}

impl TryFrom<opcodes::All> for WitnessVersion {
    type Error = WitnessVersionError;

    /// Takes bitcoin Script opcode and returns either corresponding version of
    /// the Witness program (for opcodes in range of `OP_0`..`OP_16`) or
    /// [WitnessVersionError::IncorrectOpcode] error for the rest of opcodes
    fn try_from(value: All) -> Result<Self, Self::Error> {
        WitnessVersion::try_from(value.into_u8())
    }
}

impl<'a> TryFrom<Instruction<'a>> for WitnessVersion {
    type Error = WitnessVersionError;

    /// Takes bitcoin Script instruction (parsed opcode) and returns either
    /// corresponding version of the Witness program (for push-num instructions)
    /// or [WitnessVersionError::IncorrectOpcode] error for the rest of opcodes
    fn try_from(instruction: Instruction<'a>) -> Result<Self, Self::Error> {
        match instruction {
            Instruction::<'a>::Op(op) => Self::try_from(op),
            _ => Err(WitnessVersionError::IncorrectOpcode),
        }
    }
}

impl From<WitnessVersion> for opcodes::All {
    /// Converts `WitnessVersion` instance into corresponding Bitcoin script
    /// opcode (`OP_0`..`OP_16`)
    fn from(ver: WitnessVersion) -> Self {
        opcodes::All::from(ver as u8)
    }
}

wrapper!(
    WitnessProgram,
    Vec<u8>,
    doc = r#"Witness program as defined by BIP-141
        <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#Witness_program>
        
        A scriptPubKey (or redeemScript as defined in BIP16/P2SH) that consists 
        of a 1-byte push opcode (for 0 to 16) followed by a data push between 2 
        and 40 bytes gets a new special meaning. The value of the first push is 
        called the "version byte". The following byte vector pushed is called 
        the "witness program".
        "#,
    derive = [PartialEq, Eq, Default, Hash]
);

impl From<WPubkeyHash> for WitnessProgram {
    fn from(wpkh: WPubkeyHash) -> Self {
        WitnessProgram(wpkh.to_vec())
    }
}

impl From<WScriptHash> for WitnessProgram {
    fn from(wsh: WScriptHash) -> Self {
        WitnessProgram(wsh.to_vec())
    }
}

/// Defines strategy for converting some source Bitcoin script (i.e. [LockScript])
/// into both `scriptPubkey` and `sigScript`/`witness` fields
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Hash)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Strategy {
    /// The script or public key gets right into `scriptPubkey`, i.e. as
    /// **P2PK** (for a public key) or as custom script (mostly used for `OP_RETURN`)
    Exposed,

    /// We hash public key or script and use non-SegWit `scriptPubkey` encoding,
    /// i.e. **P2PKH** or **P2SH** with corresponding non-segwit transaction
    /// input `sigScript` containing copy of [LockScript] in `redeemScript` field
    LegacyHashed,

    /// Compatibility variant for SegWit outputs when the SegWit version and
    /// program are encoded as [RedeemScript] in `sigScript` transaction input
    /// field, while the original public key or [WitnessScript] are stored in
    /// `witness`. `scriptPubkey` contains a normal **P2SH** composed agains
    /// the `redeemScript` from `sigScript` (**P2SH-P2WPKH** and **P2SH-P2WSH**
    /// variants).
    /// This type works with any witness version, including taproot.
    WitnessScriptHash,

    /// We produce either **P2WPKH** or **P2WSH** output and use witness field
    /// in transaction input to store the original [LockScript] or the public key
    WitnessV0,

    /// Will be used for Taproot
    WitnessV1Taproot,
}

/// Errors that happens during [ConversionStrategy::deduce] process
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display_from(Debug)]
pub enum StrategyError {
    /// For P2SH scripts we need to know whether it is created for the
    /// witness-containing spending transaction input, i.e. whether its redeem
    /// script will have a witness structure, or not. If this information was
    /// not provided, this error is returned.
    IncompleteInformation,

    /// Here we support only version 0 and 1 of the witness, otherwise this
    /// error is returned
    UnsupportedWitnessVersion(WitnessVersion),
}

impl Strategy {
    /// Deduction of [ConversionStrategy] from a `scriptPubkey` data and,
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
    ///       [ConversionStrategyError::IncompleteInformation] error.
    ///     - `Some(true)`: presence of a witness structure will be required
    ///       in transaction input to spend the given `pubkey_script`, i.e.
    ///       it was composed with P2SH-P2W*H scheme
    ///     - `Some(false)`: if `scriptPubkey` is P2SH, it is a "normal" P2SH
    ///       and was not created with P2SH-P2W*H scheme. The spending
    ///       transaction input would not have `witness` structure.
    ///
    /// # Errors
    ///
    /// The function may [ConversionStrategyError] in the following cases
    ///
    /// * `IncompleteInformation`: the provided pubkey script (`pubkey_script`
    ///   argument) is P2SH script, and `has_witness` argument was set to `None`
    ///   (see explanation about the argument usage above).
    /// * `UnsupportedWitnessVersion(WitnessVersion)`: the provided pubkey
    ///   script has a witness version above 1.
    ///
    pub fn deduce(
        pubkey_script: &PubkeyScript,
        has_witness: Option<bool>,
    ) -> Result<Strategy, StrategyError> {
        use Strategy::*;
        match pubkey_script.as_inner() {
            p if p.is_v0_p2wpkh() || p.is_v0_p2wsh() => Ok(WitnessV0),
            p if p.is_witness_program() => {
                const ERR: &'static str = "bitcoin::Script::is_witness_program is broken";
                match WitnessVersion::try_from(p.iter(true).next().expect(ERR)).expect(ERR) {
                    WitnessVersion::V0 => unreachable!(),
                    WitnessVersion::V1 => Ok(WitnessV1Taproot),
                    ver => Err(StrategyError::UnsupportedWitnessVersion(ver)),
                }
            }
            p if p.is_p2pkh() => Ok(LegacyHashed),
            p if p.is_p2sh() => match has_witness {
                None => Err(StrategyError::IncompleteInformation),
                Some(true) => Ok(WitnessScriptHash),
                Some(false) => Ok(LegacyHashed),
            },
            _ => Ok(Exposed),
        }
    }
}

/// Scripting data for both transaction output and spending transaction input
/// parts that can be generated from some complete bitcoin Script ([LockScript])
/// or public key using particular [ConversionStrategy]
#[derive(Clone, PartialEq, Eq, Debug, Display, Hash, Default)]
#[display_from(Debug)]
pub struct ScriptSet {
    pub pubkey_script: PubkeyScript,
    pub sig_script: SigScript,
    pub witness_script: Option<Witness>,
}

impl ScriptSet {
    /// Detects whether the structure contains witness data
    #[inline]
    pub fn has_witness(&self) -> bool {
        self.witness_script != None
    }

    /// Detects whether the structure is either P2SH-P2WPKH or P2SH-P2WSH
    pub fn is_witness_sh(&self) -> bool {
        return self.sig_script.as_inner().len() > 0 && self.has_witness();
    }

    /// Tries to convert witness-based script structure into pre-SegWit – and
    /// vice verse. Returns `true` if the conversion is possible and was
    /// successful, `false` if the conversion is impossible; in the later case
    /// the `self` is not changed. The conversion is impossible in the following
    /// cases:
    /// * for P2SH-P2WPKH or P2SH-P2WPSH variants (can be detected with
    ///   [ScriptSet::is_witness_sh] function)
    /// * for scripts that are internally inconsistent
    pub fn transmutate(&mut self, use_witness: bool) -> bool {
        // We can't transmutate P2SH-contained P2WSH/P2WPKH
        if self.is_witness_sh() {
            return false;
        }
        if self.has_witness() != use_witness {
            if use_witness {
                self.witness_script = Some(
                    self.sig_script
                        .as_inner()
                        .iter(false)
                        .filter_map(|instr| {
                            if let Instruction::PushBytes(bytes) = instr {
                                Some(bytes.to_vec())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<Vec<u8>>>()
                        .into(),
                );
                self.sig_script = SigScript::default();
            } else {
                if let Some(ref witness_script) = self.witness_script {
                    self.sig_script = witness_script
                        .as_inner()
                        .iter()
                        .fold(Builder::new(), |builder, bytes| builder.push_slice(bytes))
                        .into_script()
                        .into();
                    self.witness_script = None;
                } else {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }
}

/// Script set generation from public key or a given [LockScript] (with
/// [TapScript] support planned for the future).
pub trait GenerateScripts {
    fn gen_scripts(&self, strategy: Strategy) -> ScriptSet {
        ScriptSet {
            pubkey_script: self.gen_script_pubkey(strategy),
            sig_script: self.gen_sig_script(strategy),
            witness_script: self.gen_witness(strategy),
        }
    }
    fn gen_script_pubkey(&self, strategy: Strategy) -> PubkeyScript;
    fn gen_sig_script(&self, strategy: Strategy) -> SigScript;
    fn gen_witness(&self, strategy: Strategy) -> Option<Witness>;
}

impl GenerateScripts for LockScript {
    fn gen_script_pubkey(&self, strategy: Strategy) -> PubkeyScript {
        match strategy {
            Strategy::Exposed => self.as_inner().into(),
            Strategy::LegacyHashed => Builder::gen_p2sh(&self.script_hash()).into_script().into(),
            Strategy::WitnessV0 => Builder::gen_v0_p2wsh(&self.wscript_hash())
                .into_script()
                .into(),
            Strategy::WitnessScriptHash => {
                // Here we support only V0 version, since V1 version can't
                // be generated from `LockScript` and will require
                // `TapScript` source
                let redeem_script =
                    LockScript::from(self.gen_script_pubkey(Strategy::WitnessV0).to_inner());
                Builder::gen_p2sh(&redeem_script.script_hash())
                    .into_script()
                    .into()
            }
            Strategy::WitnessV1Taproot => unimplemented!(),
        }
    }

    fn gen_sig_script(&self, strategy: Strategy) -> SigScript {
        match strategy {
            // sigScript must contain just a plain signatures, which will be
            // added later
            Strategy::Exposed => SigScript::default(),
            Strategy::LegacyHashed => Builder::new()
                .push_slice(WitnessScript::from(self.clone()).as_bytes())
                .into_script()
                .into(),
            Strategy::WitnessScriptHash => {
                // Here we support only V0 version, since V1 version can't
                // be generated from `LockScript` and will require
                // `TapScript` source
                let redeem_script =
                    LockScript::from(self.gen_script_pubkey(Strategy::WitnessV0).to_inner());
                Builder::new()
                    .push_slice(redeem_script.as_bytes())
                    .into_script()
                    .into()
            }
            // For any segwit version the sigScript must be empty (with the
            // exception to the case of P2SH-embedded outputs, which is already
            // covered above
            _ => SigScript::default(),
        }
    }

    fn gen_witness(&self, strategy: Strategy) -> Option<Witness> {
        match strategy {
            Strategy::Exposed | Strategy::LegacyHashed => None,
            Strategy::WitnessV0 | Strategy::WitnessScriptHash => {
                let witness_script = WitnessScript::from(self.clone());
                Some(Witness::from_inner(vec![witness_script.to_bytes()]))
            }
            Strategy::WitnessV1Taproot => unimplemented!(),
        }
    }
}

impl GenerateScripts for bitcoin::PublicKey {
    fn gen_script_pubkey(&self, strategy: Strategy) -> PubkeyScript {
        match strategy {
            Strategy::Exposed => Builder::gen_p2pk(self).into_script().into(),
            Strategy::LegacyHashed => Builder::gen_p2pkh(&self.pubkey_hash()).into_script().into(),
            Strategy::WitnessV0 => Builder::gen_v0_p2wpkh(&self.wpubkey_hash())
                .into_script()
                .into(),
            Strategy::WitnessScriptHash => {
                // TODO: Support tapscript P2SH-P2TR scheme here
                let redeem_script = self.gen_script_pubkey(Strategy::WitnessV0);
                Builder::gen_p2sh(&redeem_script.script_hash())
                    .into_script()
                    .into()
            }
            Strategy::WitnessV1Taproot => unimplemented!(),
        }
    }
    fn gen_sig_script(&self, strategy: Strategy) -> SigScript {
        match strategy {
            // sigScript must contain just a plain signatures, which will be
            // added later
            Strategy::Exposed => SigScript::default(),
            Strategy::LegacyHashed => Builder::new()
                .push_slice(&self.to_bytes())
                .into_script()
                .into(),
            Strategy::WitnessScriptHash => {
                // TODO: Support tapscript P2SH-P2TR scheme here
                let redeem_script =
                    LockScript::from(self.gen_script_pubkey(Strategy::WitnessV0).into_inner());
                Builder::new()
                    .push_slice(redeem_script.as_bytes())
                    .into_script()
                    .into()
            }
            // For any segwit version the sigScript must be empty (with the
            // exception to the case of P2SH-embedded outputs, which is already
            // covered above
            _ => SigScript::default(),
        }
    }

    fn gen_witness(&self, strategy: Strategy) -> Option<Witness> {
        match strategy {
            Strategy::Exposed | Strategy::LegacyHashed => None,
            Strategy::WitnessV0 | Strategy::WitnessScriptHash => {
                Some(Witness::from_inner(vec![self.to_bytes()]))
            }
            Strategy::WitnessV1Taproot => unimplemented!(),
        }
    }
}

impl GenerateScripts for secp256k1::PublicKey {
    #[inline]
    fn gen_script_pubkey(&self, strategy: Strategy) -> PubkeyScript {
        bitcoin::PublicKey {
            compressed: true,
            key: self.clone(),
        }
        .gen_script_pubkey(strategy)
    }
    #[inline]
    fn gen_sig_script(&self, strategy: Strategy) -> SigScript {
        bitcoin::PublicKey {
            compressed: true,
            key: self.clone(),
        }
        .gen_sig_script(strategy)
    }
    #[inline]
    fn gen_witness(&self, strategy: Strategy) -> Option<Witness> {
        bitcoin::PublicKey {
            compressed: true,
            key: self.clone(),
        }
        .gen_witness(strategy)
    }
}
