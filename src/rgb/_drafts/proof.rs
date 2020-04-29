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

use bitcoin::hashes::sha256d;
use bitcoin::Txid;

use super::{data::amount, ContractId, Seal, Transition};

///! Structures required for full validation of a given state transfer

/// Part of the LNPBP-4 multimessage commitment
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub enum CommitmentProofItem {
    /// We commit to the item at this place
    Placeholder,
    /// Some other commitment
    Hash(sha256d::Hash),
}

/// Whole LNPBP-5 multimessage commitment as a vector of individual commitments
pub type CommitmentProof = Vec<CommitmentProofItem>;

/// Proves information on how a given transition committment is placed withing
/// some LNPBP-5 multimessage commitment
#[derive(Clone, PartialEq, Debug, Display)]
#[display_from(Debug)]
pub struct MultimessageReveal {
    pub transition: Transition,
    pub commitment_proof: CommitmentProof,
}

/// Proves source of the state data.
/// The state is represented by a raw non-encrypted data is not provided
/// as a part of the proof, so we don't need this option here.
#[non_exhaustive]
#[derive(Clone, PartialEq, Debug, Display)]
#[display_from(Debug)]
pub enum DataReveal {
    /// Confidential amount disclosure
    Balance(amount::Proof),
}

/// Provides source for the seal data
#[derive(Clone, PartialEq, Debug, Display)]
#[display_from(Debug)]
pub struct StateReveal {
    /// Seal definition that contains an assigned state
    pub seal: Seal,
    /// Assigned state source data
    pub data_proof: DataReveal,
}

#[derive(Clone, PartialEq, Debug, Display)]
#[display_from(Debug)]
pub struct Proof {
    /// Contract id
    pub contract_id: ContractId,

    /// History of state transition (graph serialized in a linear vec)
    pub transition_history: Vec<MultimessageReveal>,

    /// Reveals information all all confidential states
    pub state_proofs: Vec<StateReveal>,

    /// Optional list of the witness transaction ids
    pub witness_txids: Option<Vec<Txid>>,
}
