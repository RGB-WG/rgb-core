// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

mod nodes;
mod schema;
pub mod script;
mod state;
mod occurences;

pub use nodes::{
    ExtensionSchema, GenesisSchema, MetadataStructure, NodeSchema, NodeSubtype, NodeType,
    OwnedRightType, OwnedRightsStructure, PublicRightType, PublicRightsStructure, TransitionSchema,
};
pub use occurences::{Occurrences, OccurrencesError};
#[cfg(test)]
pub(crate) use schema::test;
pub use schema::{ExtensionType, FieldType, Schema, SchemaId, TransitionType};
pub use script::{VmScript, VmType};
pub use state::{DiscreteFiniteFieldFormat, StateSchema, StateType};

/// Trait used for internal schema validation against some root schema
pub(self) trait SchemaVerify {
    fn schema_verify(&self, root: &Self) -> crate::validation::Status;
}

/// Constants which are common to different schemata and can be recognized
/// by the software even if the specific schema is unknown, since this type ids
/// are reserved to a specific semantic meaning
///
/// These constants are also used by embedded validation procedures representing
/// standard metadata fields, state and transition types analyzed by them
// TODO #LNPBP(102): (LNPBPs) Make this part of the RGB generic schema LNPBP
//      standard
pub mod constants {
    /// Ticker of the asset
    pub const FIELD_TYPE_TICKER: u16 = 0x00;

    /// Contract or asset name
    pub const FIELD_TYPE_NAME: u16 = 0x01;

    /// Ricardian contract text
    pub const FIELD_TYPE_CONTRACT_TEXT: u16 = 0x02;

    /// Decimal precision for some sort of amount values used in a contract
    pub const FIELD_TYPE_PRECISION: u16 = 0x03;

    /// Timestamp used in genesis to indicate moment of contract creation
    pub const FIELD_TYPE_TIMESTAMP: u16 = 0x04;

    /// Generic comment about the contract or a state transitions
    pub const FIELD_TYPE_COMMENTARY: u16 = 0x05;

    /// Data attached to a state transition in binary format
    pub const FIELD_TYPE_DATA: u16 = 0x10;

    /// Format of the attached data, schema-specific
    // TODO #36: Use LNPBP-extended MIME types embedded to data containers
    pub const FIELD_TYPE_DATA_FORMAT: u16 = 0x11;

    /// [`FieldType`] that is used by validation procedures checking the issued
    /// supply & inflation
    pub const FIELD_TYPE_ISSUED_SUPPLY: u16 = 0xA0;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// burn. Must contain amount of the burned supply, expressed as
    /// revealed [`crate::value::Revealed`] data
    pub const FIELD_TYPE_BURN_SUPPLY: u16 = 0xB0;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// burn. Must contain [`bitcoin::OutPoint`] consensus-encoded data.
    pub const FIELD_TYPE_BURN_UTXO: u16 = 0xB1;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// burn. Must contain binary data ([`crate::data::Revealed::Bytes`])
    pub const FIELD_TYPE_HISTORY_PROOF: u16 = 0xB2;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// burn. Must contain format of the provided proofs defined in
    /// [`HistoryProofFormat`]
    pub const FIELD_TYPE_HISTORY_PROOF_FORMAT: u16 = 0xB3;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// reserves. Must contain [`wallet::descriptor::Expanded`] strict encoded
    /// data.
    pub const FIELD_TYPE_LOCK_DESCRIPTOR: u16 = 0xC0;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// reserves. Must contain [`bitcoin::OutPoint`] consensus-encoded data
    pub const FIELD_TYPE_LOCK_UTXO: u16 = 0xC1;

    // --------

    /// Renomination of the contract parameters
    pub const STATE_TYPE_RENOMINATION_RIGHT: u16 = 0x01;

    /// [`OwnedRightType`] that is used by the validation procedures checking
    /// asset inflation (applies to both fungible and non-fungible assets)
    pub const STATE_TYPE_INFLATION_RIGHT: u16 = 0xA0;

    /// [`OwnedRightType`] that is used by validation procedures checking for
    /// the equivalence relations between previous and new asset ownership
    /// (applies to both fungible and non-fungible assets).
    ///
    /// NB: STATE_TYPE_OWNERSHIP_RIGHT + N where N = 1..9 are reserved for
    ///     custom forms of ownership (like "engraved ownership" for NFT tokens)
    pub const STATE_TYPE_OWNERSHIP_RIGHT: u16 = 0xA1;

    /// Right to define epochs of asset replacement
    pub const STATE_TYPE_ISSUE_EPOCH_RIGHT: u16 = 0xAA;

    /// Right to replace some of the state issued under the contract
    pub const STATE_TYPE_ISSUE_REPLACEMENT_RIGHT: u16 = 0xAB;

    /// Right to replace some of the state issued under the contract
    pub const STATE_TYPE_ISSUE_REVOCATION_RIGHT: u16 = 0xAC;

    // --------

    /// Transitions transferring ownership over primary contract state
    pub const TRANSITION_TYPE_OWNERSHIP_TRANSFER: u16 = 0x00;

    /// Transitions modifying primary contract state, possibly combining with
    /// ownership transfer
    pub const TRANSITION_TYPE_STATE_MODIFICATION: u16 = 0x01;

    /// Transition performing renomination of contract metadata
    pub const TRANSITION_TYPE_RENOMINATION: u16 = 0x10;

    /// [`TransitionType`] that is used by the validation procedures checking
    /// asset inflation (applies to both fungible and non-fungible assets)
    pub const TRANSITION_TYPE_ISSUE: u16 = 0xA0;

    /// Transition that defines certain grouping of other issue-related
    /// operations
    pub const TRANSITION_TYPE_ISSUE_EPOCH: u16 = 0xA1;

    /// Transition burning some of the issued contract state.
    ///
    /// NB: It is not the same as [`TRANSITION_TYPE_RIGHTS_TERMINATION`], which
    /// terminates ability to utilize some rights (but not the state)
    pub const TRANSITION_TYPE_ISSUE_BURN: u16 = 0xA2;

    /// Transition replacing some of the previously issued state with the new
    /// one
    pub const TRANSITION_TYPE_ISSUE_REPLACE: u16 = 0xA3;

    /// Transition performing split of rights assigned to the same UTXO by
    /// a mistake
    pub const TRANSITION_TYPE_RIGHTS_SPLIT: u16 = 0xF0;

    /// Transition making certain rights void without executing the right itself
    pub const TRANSITION_TYPE_RIGHTS_TERMINATION: u16 = 0xFF;
}
