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

/// Constants used by embedded validation procedures representing standard
/// metadata fields, state and transition types analyzed by them
pub mod constants {
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

    /// [`OwnedRightType`] that is used by the embedded validation procedures
    /// [`StandardProcedure::NonfungibleInflation`] and
    /// [`StandardProcedure::IdentityTransfer`]
    pub const STATE_TYPE_NONFUNGIBLE_OWNERSHIP: usize = 0xA2;

    /// [`TransitionType`] that is used by the embedded validation procedures
    /// [`StandardProcedure::NonfungibleInflation`]
    pub const STATE_TYPE_NONFUNGIBLE_INFLATION: usize = 0xA3;

    /// [`OwnedRightType`] that is used by the embedded validation procedure
    /// [`StandardProcedure::InflationControlBySum`]
    pub const STATE_TYPE_FUNGIBLE_INFLATION: usize = 0xA0;

    /// [`OwnedRightType`] that is used by the embedded validation procedures
    /// [`StandardProcedure::NoInflationBySum`] and
    /// [`StandardProcedure::InflationControlBySum`]
    pub const STATE_TYPE_FUNGIBLE_ASSETS: usize = 0xA1;

    /// [`TransitionType`] that is used by the embedded validation procedures
    /// [`StandardProcedure::NoInflationBySum`]
    pub const TRANSITION_TYPE_FUNGIBLE_ISSUE: usize = 0xA0;
}
