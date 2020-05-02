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

mod anchor;
mod consignment;
mod contract;
mod interfaces;
pub mod schema;
mod stash;
pub mod vm;

pub mod prelude {
    pub use super::*;
    pub use anchor::Anchor;
    pub use consignment::Consignment;
    pub use contract::{
        amount, data, seal, Amount, Assignment, AssignmentsVariant, Contract, ContractId, Genesis,
        Node, SealDefinition, Transition, TransitionId,
    };
    pub use schema::script;
    pub use schema::{Schema, SchemaId, SimplicityScript};
    pub use stash::{CoordinatedTransition, CoordinatedUpdate, Stash};
}

pub use prelude::*;
