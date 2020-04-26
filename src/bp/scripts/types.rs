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
//! While all `Script`s represent the same same type **semantically**, there is a clear distinction
//! at the **logical** level: Bitcoin script has the property to be committed into some other
//! Bitcoin script – in a nested structures like in several layers, like *redeemScript* inside of
//! *sigScript* used for P2SH, or *tapScript* within *witnessScript* coming from *witness* field
//! for Taproot. These nested layers do distinguish on the information they contain, since some of
//! them only commit to the hashes of the nested scripts (`ScriptHash`, `WitnessProgramm`) or
//! public keys (`PubkeyHash`, `WPubkeyHash`), while other contain the full source of the script.
//!
//! The present type system represents a solution to the problem: it distinguish different logical
//! types by introducing `Script` wrapper types. It defines `LockScript` as bottom layer or a script
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

use bitcoin::blockdata::opcodes::All;
use bitcoin::{
    blockdata::{opcodes, script::*},
    hash_types::*,
    secp256k1,
};
use core::convert::TryFrom;
use miniscript::{miniscript::iter::PubkeyOrHash, Miniscript, MiniscriptKey};

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
    WitnessScript,
    Script,
    doc = "\
    A content of the `witness` field from a transaction input according to BIP-141",
    derive = [Default, PartialEq, Eq, PartialOrd, Ord, Hash]
);

/// `redeemScript` as part of the `witness` or `sigScript` structure; it is
/// hashed for P2(W)SH output",
pub type RedeemScript = LockScript;

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

/// Defines strategy for converting some source Bitcoin script (i.e. [LockScript])
/// into both `scriptPubkey` and `sigScript`/`witness` fields
#[derive(Clone, PartialEq, Eq, Debug, Display, Hash)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ConversionStrategy {
    /// The script or public key gets right into `scriptPubkey`, i.e. as
    /// **P2PK** (for a public key) or as custom script (mostly used for `OP_RETURN`)
    Exposed,

    /// We hash public key or script and use non-SegWit `scriptPubkey` encoding,
    /// i.e. **P2PKH** or **P2SH** with corresponding non-segwit transaction
    /// input `sigScript` containing copy of [LockScript] in `redeemScript` field
    LegacyHashed,

    /// We produce either **P2WPKH** or **P2WSH** output and use witness field
    /// in transaction input to store the original [LockScript] or the public key
    SegWitV0,

    /// Compatibility variant for SegWit outputs when the SegWit version and
    /// program are encoded as [RedeemScript] in `witness` transaction input
    /// field and put into `scriptPubkey` as normal **P2SH** (**P2SH-P2WPKH**
    /// and **P2SH-P2WSH** variants)
    SegWitScriptHash,

    /// Will be used for Taproot
    SegWitTaproot,
}

/// Errors that happens during [ConversionStrategy::deduce] process
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display_from(Debug)]
pub enum ConversionStrategyError {
    /// For P2SH scripts we need to know whether it is created for the
    /// witness-containing spending transaction input, i.e. whether its redeem
    /// script will have a witness structure, or not. If this information was
    /// not provided, this error is returned.
    IncompleteInformation,

    /// Here we support only version 0 and 1 of the witness, otherwise this
    /// error is returned
    UnsupportedWitnessVersion(WitnessVersion),
}

impl ConversionStrategy {
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
    ) -> Result<ConversionStrategy, ConversionStrategyError> {
        use ConversionStrategy::*;
        match pubkey_script.as_inner() {
            p if p.is_v0_p2wpkh() || p.is_v0_p2wsh() => Ok(SegWitV0),
            p if p.is_witness_program() => {
                const ERR: &'static str = "bitcoin::Script::is_witness_program is broken";
                match WitnessVersion::try_from(p.iter(true).next().expect(ERR)).expect(ERR) {
                    WitnessVersion::V0 => unreachable!(),
                    WitnessVersion::V1 => Ok(SegWitTaproot),
                    ver => Err(ConversionStrategyError::UnsupportedWitnessVersion(ver)),
                }
            }
            p if p.is_p2pkh() => Ok(LegacyHashed),
            p if p.is_p2sh() => match has_witness {
                None => Err(ConversionStrategyError::IncompleteInformation),
                Some(true) => Ok(SegWitScriptHash),
                Some(false) => Ok(LegacyHashed),
            },
            _ => Ok(Exposed),
        }
    }
}

pub type ScriptTuple = (PubkeyScript, SigScript, Option<WitnessScript>);

#[derive(Debug, Display, Error)]
#[display_from(Debug)]
pub enum LockScriptParseError<Pk: MiniscriptKey> {
    PubkeyHash(Pk::Hash),
    Miniscript(miniscript::Error),
}

impl<Pk: MiniscriptKey> From<miniscript::Error> for LockScriptParseError<Pk> {
    fn from(miniscript_error: miniscript::Error) -> Self {
        Self::Miniscript(miniscript_error)
    }
}

impl LockScript {
    pub fn extract_pubkeys(
        &self,
    ) -> Result<Vec<secp256k1::PublicKey>, LockScriptParseError<bitcoin::PublicKey>> {
        Miniscript::parse(&*self.clone())?
            .iter_pubkeys_and_hashes()
            .try_fold(
                Vec::<secp256k1::PublicKey>::new(),
                |mut keys, item| match item {
                    PubkeyOrHash::HashedPubkey(hash) => Err(LockScriptParseError::PubkeyHash(hash)),
                    PubkeyOrHash::PlainPubkey(key) => {
                        keys.push(key.key);
                        Ok(keys)
                    }
                },
            )
    }

    pub fn replace_pubkeys(
        &self,
        processor: impl Fn(secp256k1::PublicKey) -> Option<secp256k1::PublicKey>,
    ) -> Result<Self, LockScriptParseError<bitcoin::PublicKey>> {
        let result = Miniscript::parse(&*self.clone())?.replace_pubkeys_and_hashes(
            &|item: PubkeyOrHash<bitcoin::PublicKey>| match item {
                PubkeyOrHash::PlainPubkey(pubkey) => processor(pubkey.key).map(|key| {
                    PubkeyOrHash::PlainPubkey(bitcoin::PublicKey {
                        compressed: true,
                        key,
                    })
                }),
                PubkeyOrHash::HashedPubkey(_) => None,
            },
        )?;
        Ok(LockScript::from(result.encode()))
    }

    pub fn replace_pubkeys_and_hashes(
        &self,
        key_processor: impl Fn(secp256k1::PublicKey) -> Option<secp256k1::PublicKey>,
        hash_processor: impl Fn(PubkeyHash) -> Option<PubkeyHash>,
    ) -> Result<Self, LockScriptParseError<bitcoin::PublicKey>> {
        let result = Miniscript::parse(&*self.clone())?.replace_pubkeys_and_hashes(
            &|item: PubkeyOrHash<bitcoin::PublicKey>| match item {
                PubkeyOrHash::PlainPubkey(pubkey) => key_processor(pubkey.key).map(|key| {
                    PubkeyOrHash::PlainPubkey(bitcoin::PublicKey {
                        compressed: true,
                        key,
                    })
                }),
                PubkeyOrHash::HashedPubkey(hash) => {
                    hash_processor(hash.into()).map(|hash| PubkeyOrHash::HashedPubkey(hash.into()))
                }
            },
        )?;
        Ok(LockScript::from(result.encode()))
    }
}
