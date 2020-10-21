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

mod assignments;
#[macro_use]
pub mod data;
mod conceal;
mod metadata;
pub mod nodes;
pub mod seal;
pub mod value;

pub use assignments::{
    Assignments, ConfidentialState, DeclarativeStrategy, HashStrategy,
    OwnedRights, OwnedState, ParentOwnedRights, ParentPublicRights,
    PedersenStrategy, RevealedState, StateTypes,
};
pub use conceal::AutoConceal;
pub use metadata::Metadata;
pub use nodes::{ContractId, Extension, Genesis, Node, NodeId, Transition};
pub use seal::SealDefinition;
pub use value::AtomicValue;

use secp256k1zkp::Secp256k1 as Secp256k1zkp;
lazy_static! {
    /// Secp256k1zpk context object
    pub(crate) static ref SECP256K1_ZKP: Secp256k1zkp = Secp256k1zkp::with_caps(secp256k1zkp::ContextFlag::Commit);
}

/// Error returned when the requested data does not exist
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display(Debug)]
pub struct NoDataError;
