// LNP/BP Rust Library
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

//! Components related to the scripting system used by schema or applied at the
//! specific contract node level

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::io;

use bitcoin::hashes::hex::ToHex;
use lnpbp::bech32::Bech32DataString;
use lnpbp::client_side_validation::{
    commit_strategy, CommitEncodeWithStrategy,
};

/// Types of supported virtual machines
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[non_exhaustive]
#[repr(u8)]
pub enum VmType {
    /// Embedded code (not a virtual machine) which is the part of this RGB
    /// Core Library. Using this option results in the fact that the schema
    /// does not commit to the actual validating code and it may change (or
    /// be patched) with new RGB Core Lib releases
    #[display("embedded")]
    Embedded = 0x00u8,

    /// Simplicity-based virtual machine (not implemented yet, will always
    /// return false validation result for RGBv0)
    #[display("wasm")]
    Wasm = 0x01u8,

    /// Simplicity-based virtual machine (not implemented yet, will always
    /// return false validation result for RGBv0)
    #[display("simplicity")]
    Simplicity = 0x02u8,
}

impl Default for VmType {
    fn default() -> Self {
        VmType::Embedded
    }
}

/// Executable code overwrite rules
///
/// Defines whether child contract nodes are allowed to replace (overwrite) the
/// code
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[repr(u8)]
pub enum OverwriteRules {
    #[display("deny")]
    /// Denies overwrites
    Deny = 0u8,

    #[display("allow-same-vm")]
    /// Allows overwrite only if the same VM is used
    AllowSameVm = 1u8,

    #[display("allow-any-vm")]
    /// Allows overwrite of both executable code and type of VM
    AllowAnyVm = 2u8,
}

impl Default for OverwriteRules {
    fn default() -> Self {
        OverwriteRules::Deny
    }
}

/// Executable code
///
/// The actual executable code, which must be holistic and not dependent on any
/// external libraries (i.e. must contain all libraries embedded into itself).
/// Its routines can be accessed only through well-typed ABI entrance points,
/// defined as a part of the specific state transition and owned rights, either
/// in the schema (for schema-supplied code base) or within the contract nodes,
/// if the contract is allowed to replace the code provided by the schema.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
pub struct ExecutableCode {
    /// Type of the virtual machine that MUST be used to run the given byte
    /// code
    pub vm_type: VmType,

    /// Script data are presented as a byte array (VM-specific)
    // TODO: #68 Currently script will be limited to 2^16 bytes; we need to
    //       extend that to at least 2^24
    pub byte_code: Box<[u8]>,

    /// Defines whether child contract nodes (genesis for schema, state
    /// transitions for genesis, child state transitions for a state
    /// transition) are allowed to replace (overwrite) the code
    pub overwrite_rules: OverwriteRules,
}

impl CommitEncodeWithStrategy for ExecutableCode {
    type Strategy = commit_strategy::UsingStrict;
}

impl Display for ExecutableCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.vm_type, f)?;
        if f.alternate() {
            f.write_str(&self.byte_code.to_hex())
        } else {
            f.write_str(&self.byte_code.bech32_data_string())
        }
    }
}

/// Marker trait for all node-specific ABI table keys
pub trait NodeAction: Sized + Ord + Copy + Into<u8> {}

/// Genesis-specific ABI table keys
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[non_exhaustive]
#[repr(u8)]
pub enum GenesisAction {
    #[display("validate")]
    /// Validation of the state & metadata defined by a genesis
    Validate = 0,
}

impl From<GenesisAction> for u8 {
    fn from(action: GenesisAction) -> Self {
        action as u8
    }
}

impl NodeAction for GenesisAction {}

/// State extension-specific ABI table keys
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[non_exhaustive]
#[repr(u8)]
pub enum ExtensionAction {
    #[display("validate")]
    /// Validation of the state & metadata defined by a state extension
    Validate = 0,
}

impl From<ExtensionAction> for u8 {
    fn from(action: ExtensionAction) -> Self {
        action as u8
    }
}

impl NodeAction for ExtensionAction {}

/// State transition-specific ABI table keys
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[non_exhaustive]
#[repr(u8)]
pub enum TransitionAction {
    #[display("validate")]
    /// Validation of the state & metadata defined by a state transition
    Validate = 0,

    #[display("blank")]
    /// Creation of an empty (blank) state transition transferring data 1-to-1
    /// from a spending UTXO to a new UTXO. Used when other schema spends UTXO
    /// with the rights assigned under this schema.
    GenerateBlank = 1,
}

impl From<TransitionAction> for u8 {
    fn from(action: TransitionAction) -> Self {
        action as u8
    }
}

impl NodeAction for TransitionAction {}

/// ABI table keys for owned right assignment entries (parts of contract nodes)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[non_exhaustive]
#[repr(u8)]
pub enum AssignmentAction {
    #[display("validate")]
    /// Validation of the state & metadata defined by a state assignment
    Validate = 0,
}

impl From<AssignmentAction> for u8 {
    fn from(action: AssignmentAction) -> Self {
        action as u8
    }
}

/// Offset within script data for the procedure entry point.
///
/// Part of the ABI data.
///
/// NB: For embedded procedures this is a code name of the embedded procedure
///     as defined by [`EmbeddedProcedure`]
// TODO: #68 Replace this type with `Uint24` once it will be implemented by
//       upstream LNPBP#205
pub type EntryPoint = u32;

/// ABI table for contract genesis
pub type GenesisAbi = BTreeMap<GenesisAction, EntryPoint>;
/// ABI table for contract state extension
pub type ExtensionAbi = BTreeMap<ExtensionAction, EntryPoint>;
/// ABI table for contract state transition
pub type TransitionAbi = BTreeMap<TransitionAction, EntryPoint>;
/// ABI table for owned rights assignment inside a contract node
pub type AssignmentAbi = BTreeMap<AssignmentAction, EntryPoint>;

/// Market trait for generalizing over all available ABI types
pub trait Abi {}

impl Abi for GenesisAbi {}
impl Abi for ExtensionAbi {}
impl Abi for TransitionAbi {}
impl Abi for AssignmentAbi {}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[non_exhaustive]
#[repr(u32)] // We must use the type that fits in the size of `EntryPoint`
pub enum EmbeddedProcedure {
    /// Non-inflationary fungible asset transfer control
    ///
    /// Checks that the sum of pedersen commitments in the inputs of type
    /// [`crate::schema::constants::STATE_TYPE_OWNED_AMOUNT`] equal to the sum
    /// of the outputs of the same type, plus validates bulletproof data
    #[display("fungible-no-inflation")]
    FungibleNoInflation = 0x01,

    /// Fungible asset inflation/issue control
    ///
    /// Checks that inflation of a fungible asset produces no more than was
    /// allowed by [`crate::schema::constants::STATE_TYPE_INFLATION_RIGHT`],
    /// i.e. that the sum of all outputs with
    /// [`crate::schema::constants::STATE_TYPE_OWNED_AMOUNT`] type is no more
    /// than that value - plus validates bulletproof data.
    ///
    /// Also validates that the sum of the issued asset is equal to the amount
    /// specified in the [`crate::schema::constants::FIELD_TYPE_ISSUED_SUPPLY`]
    /// metadata field
    #[display("fungible-issue")]
    FungibleIssue = 0x02,

    /// NFT/identity transfer control
    ///
    /// Checks that all identities are transferred once and only once, i.e.
    /// that the _number_ of
    /// [`crate::schema::constants::STATE_TYPE_OWNED_DATA`] inputs is equal
    /// to the _number_ of outputs of this type.
    #[display("nft-transfer")]
    IdentityTransfer = 0x11,

    /// NFT asset secondary issue control
    ///
    /// Checks that inflation of a fungible asset produces no more than was
    /// allowed by [`crate::schema::constants::STATE_TYPE_INFLATION_RIGHT`],
    /// i.e. that the sum of all outputs with
    /// [`crate::schema::constants::STATE_TYPE_OWNED_AMOUNT`] type is no more
    /// than that value
    #[display("nft-issue")]
    NftIssue = 0x12,

    /// Proof-of-burn verification
    ///
    /// Currently not implemented in RGBv0 and always validates to TRUE
    #[display("proof-of-burn")]
    ProofOfBurn = 0x20,

    /// Proof-of-reserve verification
    ///
    /// Currently not implemented in RGBv0 and always validates to TRUE
    #[display("proof-of-reserve")]
    ProofOfReserve = 0x21,

    /// Verification of rights splits procedure
    ///
    /// Checks that each of the owned rights types were assigned one-to-one
    /// between inputs and outputs
    #[display("rights-split")]
    RightsSplit = 0x30,
}

impl EmbeddedProcedure {
    /// Constructs [`EmbeddedProcedure`] from [`EntryPoint`], or returns
    /// `None` if the provided entry point value does not correspond to any of
    /// the embedded procedures
    pub fn from_entry_point(entry_point: EntryPoint) -> Option<Self> {
        Some(match entry_point {
            x if x == EmbeddedProcedure::FungibleNoInflation as u32 => {
                EmbeddedProcedure::FungibleNoInflation
            }
            x if x == EmbeddedProcedure::FungibleIssue as u32 => {
                EmbeddedProcedure::FungibleIssue
            }
            x if x == EmbeddedProcedure::IdentityTransfer as u32 => {
                EmbeddedProcedure::IdentityTransfer
            }
            x if x == EmbeddedProcedure::NftIssue as u32 => {
                EmbeddedProcedure::NftIssue
            }
            x if x == EmbeddedProcedure::ProofOfBurn as u32 => {
                EmbeddedProcedure::ProofOfBurn
            }
            x if x == EmbeddedProcedure::ProofOfReserve as u32 => {
                EmbeddedProcedure::ProofOfReserve
            }
            x if x == EmbeddedProcedure::RightsSplit as u32 => {
                EmbeddedProcedure::RightsSplit
            }
            _ => return None,
        })
    }
}

mod strict_encoding {
    use super::*;
    use lnpbp::strict_encoding::{Error, StrictDecode, StrictEncode};

    impl StrictEncode for EmbeddedProcedure {
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            let val = *self as EntryPoint;
            val.strict_encode(e)
        }
    }

    impl StrictDecode for EmbeddedProcedure {
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            let entry_point = EntryPoint::strict_decode(d)?;
            EmbeddedProcedure::from_entry_point(entry_point).ok_or(
                Error::DataIntegrityError(format!(
                    "Entry point value {} does not correspond to any of known embedded procedures",
                    entry_point
                )))
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use lnpbp::strict_encoding::strict_serialize;

        #[test]
        fn test_basics() {
            // Test Actions and Standard procedures
            // TODO: Uncomment once `test_enum_u8_exhaustive` update to
            //       no-num-trait version will be complete
            /*
            test_enum_u8_exhaustive!(AssignmentAction; AssignmentAction::Validate => 0);
            test_enum_u8_exhaustive!(TransitionAction;
                TransitionAction::Validate => 0,
                TransitionAction::GenerateBlank => 1
            );
            test_enum_u8_exhaustive!(EmbeddedProcedure;
                EmbeddedProcedure::FungibleNoInflation => 0x01,
                EmbeddedProcedure::FungibleIssue => 0x02,
                EmbeddedProcedure::IdentityTransfer => 0x11,
                EmbeddedProcedure::NftIssue => 0x12,
                EmbeddedProcedure::ProofOfBurn => 0x20,
                EmbeddedProcedure::ProofOfReserve => 0x21,
                EmbeddedProcedure::RightsSplit => 0x30
            );*/

            // Test Transition and Assignment ABI
            let mut trans_abi = TransitionAbi::new();
            trans_abi.insert(
                TransitionAction::Validate,
                EmbeddedProcedure::FungibleNoInflation as EntryPoint,
            );
            assert_eq!(
                vec![0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
                strict_serialize(&trans_abi).unwrap()
            );

            let mut assignment_abi = AssignmentAbi::new();
            assignment_abi.insert(AssignmentAction::Validate, 45);
            assert_eq!(
                vec![0x01, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00],
                strict_serialize(&assignment_abi).unwrap()
            );
        }
    }
}
