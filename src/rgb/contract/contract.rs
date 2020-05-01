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

use super::{Genesis, Transition};
use bitcoin::hashes::{sha256t, Hash};

// TODO: Check the data
static MIDSTATE_CONTRACT_ID: [u8; 32] = [
    25, 205, 224, 91, 171, 217, 131, 31, 140, 104, 5, 155, 127, 82, 14, 81, 58, 245, 79, 165, 114,
    243, 110, 60, 133, 174, 103, 187, 103, 230, 9, 106,
];

tagged_hash!(
    ContractId,
    ContractIdTag,
    MIDSTATE_CONTRACT_ID,
    doc = "Unique contract identifier equivalent to the contract genesis commitment hash"
);

/// The structure for a specific contract. Contract always have a part of the
/// information that is fully known (we use term *revealed*), i.e. the
/// information related to the state you have issued and the transfers you have
/// created, and partially-known (*partial*), like the one behind zero knowledge
/// proofs, merkle trees and blinded seals; this is an information you received
/// with *consignments* from other parties or that have resulted from the
/// [Stash::forget] and [Stash::prune] operations on your previously-owned
/// (but now transferred) state. To efficiently operate with privacy management
/// the revealed and partial state transitions are kept separate. We re-use
/// the same Transition data structures for both, but use generic polymorphism
/// with associated types to clearly distinguish transitions with partial and
/// revealed data underneath.
pub struct Contract {
    pub genesis: Genesis,
    pub revealed: Vec<Transition>,
    pub partial: Vec<Transition>,
}
