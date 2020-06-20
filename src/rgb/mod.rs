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

pub mod bech32;
mod contract;
pub mod schema;
mod stash;
pub mod vm;

pub mod prelude {
    use super::*;
    pub use super::{bech32, schema, vm};
    pub use contract::{
        amount, data, seal, Amount, Assignment, AssignmentsVariant, Contract, ContractId,
        FieldData, Genesis, Metadata, Node, SealDefinition, Transition, TransitionId,
    };
    pub use schema::{script, Schema, SchemaId, SimplicityScript};
    pub use stash::{Anchor, Consignment, Disclosure, Stash};
}

pub use prelude::*;
