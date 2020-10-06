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
    use crate::rgb::validation;

    /// Trait used for internal schema validation against some root schema
    pub trait SchemaVerify {
        fn schema_verify(&self, root: &Self) -> validation::Status;
    }
}
pub use verify::SchemaVerify;
