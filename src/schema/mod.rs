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

mod nodes;
mod schema;
pub mod script;
mod state;
mod types;

pub(self) use super::vm;
pub use nodes::{
    ExtensionSchema, GenesisSchema, MetadataStructure, NodeSchema, NodeType,
    OwnedRightType, OwnedRightsStructure, PublicRightType,
    PublicRightsStructure, TransitionSchema,
};
pub use schema::{ExtensionType, FieldType, Schema, SchemaId, TransitionType};
pub use script::{
    AssignmentAbi, AssignmentAction, ExtensionAbi, ExtensionAction, GenesisAbi,
    GenesisAction, NodeAction, Procedure, SimplicityScript, TransitionAbi,
    TransitionAction,
};
pub use state::{
    DataFormat, DiscreteFiniteFieldFormat, StateFormat, StateSchema, StateType,
};
pub use types::{
    elliptic_curve, Bits, DigestAlgorithm, EllipticCurve, Occurences,
    OccurrencesError,
};

#[cfg(test)]
pub(crate) use schema::test;

mod verify {
    use crate::validation;

    /// Trait used for internal schema validation against some root schema
    pub trait SchemaVerify {
        fn schema_verify(&self, root: &Self) -> validation::Status;
    }
}
pub use verify::SchemaVerify;

/// Constants which are common to different schemata and can be recognized
/// by the software even if the specific schema is unknown, since this type ids
/// are reserved to a specific semantic meaning
///
/// These constants are also used by embedded validation procedures representing
/// standard metadata fields, state and transition types analyzed by them
// TODO: (LNPBPs) Make this part of the RGB generic schema LNPBP standard
pub mod constants {
    /// Ticker of the asset
    pub const FIELD_TYPE_TICKER: usize = 0x00;

    /// Contract or asset name
    pub const FIELD_TYPE_NAME: usize = 0x01;

    /// Ricardian contract text
    pub const FIELD_TYPE_CONTRACT_TEXT: usize = 0x02;

    /// Decimal precision for some sort of amount values used in a contract
    pub const FIELD_TYPE_PRECISION: usize = 0x03;

    /// Timestamp used in genesis to indicate moment of contract creation
    pub const FIELD_TYPE_TIMESTAMP: usize = 0x04;

    /// Generic comment about the contract or a state transitions
    pub const FIELD_TYPE_COMMENTARY: usize = 0x05;

    /// Data attached to a state transition in binary format
    pub const FIELD_TYPE_DATA: usize = 0x10;

    /// Format of the attached data, schema-specific
    // TODO: Use LNPBP-extended MIME types
    pub const FIELD_TYPE_DATA_FORMAT: usize = 0x11;

    /// [`FieldType`] that is used by the embedded validation procedure
    /// [`StandardProcedure::ProofOfReserve`]
    pub const FIELD_TYPE_LOCK_DESCRIPTOR: usize = 0xC0;

    /// [`FieldType`] that is used by the embedded validation procedure
    /// [`StandardProcedure::ProofOfReserve`]
    pub const FIELD_TYPE_LOCK_UTXO: usize = 0xC1;

    /// [`FieldType`] that is used by the embedded validation procedure
    /// [`StandardProcedure::ProofOfBurn`]
    pub const FIELD_TYPE_BURN_SUPPLY: usize = 0xB0;

    /// [`FieldType`] that is used by the embedded validation procedure
    /// [`StandardProcedure::ProofOfBurn`]
    pub const FIELD_TYPE_BURN_UTXO: usize = 0xB1;

    /// [`FieldType`] that is used by the embedded validation procedure
    /// [`StandardProcedure::ProofOfBurn`]
    pub const FIELD_TYPE_HISTORY_PROOF: usize = 0xB2;

    /// [`FieldType`] that is used by the embedded validation procedure
    /// [`StandardProcedure::ProofOfBurn`]
    pub const FIELD_TYPE_HISTORY_PROOF_FORMAT: usize = 0xB3;

    /// [`FieldType`] that is used by the embedded validation procedure
    /// [`StandardProcedure::InflationControlBySum`]
    pub const FIELD_TYPE_ISSUED_SUPPLY: usize = 0xA0;

    // --------

    /// Renomination of the contract parameters
    pub const STATE_TYPE_RENOMINATION_RIGHT: usize = 0x01;

    /// [`OwnedRightType`] that is used by the embedded validation procedure
    /// [`StandardProcedure::InflationControlBySum`]
    pub const STATE_TYPE_INFLATION_RIGHT: usize = 0xA0;

    /// [`OwnedRightType`] that is used by the embedded validation procedures
    /// [`StandardProcedure::NoInflationBySum`] and
    /// [`StandardProcedure::InflationControlBySum`]
    pub const STATE_TYPE_OWNED_AMOUNT: usize = 0xA1;

    /// [`OwnedRightType`] that is used by the embedded validation procedures
    /// [`StandardProcedure::NonfungibleInflation`] and
    /// [`StandardProcedure::IdentityTransfer`]
    pub const STATE_TYPE_OWNED_DATA: usize = 0xA2;

    /// [`OwnedRightType`] that is used by the embedded validation procedures
    /// [`StandardProcedure::NonfungibleInflation`] and
    /// [`StandardProcedure::IdentityTransfer`]
    pub const STATE_TYPE_OWNERSHIP_RIGHT: usize = 0xA3;

    /// Right to define epochs of asset replacement
    pub const STATE_TYPE_ISSUE_EPOCH_RIGHT: usize = 0xAA;

    /// Right to replace some of the state issued under the contract
    pub const STATE_TYPE_ISSUE_REPLACEMENT_RIGHT: usize = 0xAB;

    // --------

    /// Transitions transferring ownership over primary contract state
    pub const TRANSITION_TYPE_OWNERSHIP_TRANSFER: usize = 0x00;

    /// Transitions modifying primary contract state, possibly combining with
    /// ownership transfer
    pub const TRANSITION_TYPE_STATE_MODIFICATION: usize = 0x01;

    /// Transition performing renomination of contract metadata
    pub const TRANSITION_TYPE_RENOMINATION: usize = 0x10;

    /// [`TransitionType`] that is used by the embedded validation procedures
    /// [`StandardProcedure::NoInflationBySum`]
    pub const TRANSITION_TYPE_ISSUE: usize = 0xA0;

    /// Transition that defines certain grouping of other issue-related
    /// operations
    pub const TRANSITION_TYPE_ISSUE_EPOCH: usize = 0xA1;

    /// Transition burning some of the issued contract state.
    ///
    /// NB: It is not the same as [`TRANSITION_TYPE_RIGHTS_TERMINATION`], which
    /// terminates ability to utilize some rights (but not the state)
    pub const TRANSITION_TYPE_ISSUE_BURN: usize = 0xA2;

    /// Transition replacing some of the previously issued state with the new
    /// one
    pub const TRANSITION_TYPE_ISSUE_REPLACE: usize = 0xA3;

    /// Transition performing split of rights assigned to the same UTXO by
    /// a mistake
    pub const TRANSITION_TYPE_RIGHTS_SPLIT: usize = 0xF0;

    /// Transition making certain rights void without executing the right itself
    pub const TRANSITION_TYPE_RIGHTS_TERMINATION: usize = 0xFF;
}
