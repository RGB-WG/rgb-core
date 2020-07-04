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

use core::iter::FromIterator;
use core::ops::{AddAssign, Try};

use bitcoin::{Transaction, Txid};

use super::schema::OccurrencesError;
use super::{schema, seal, AnchorId, NodeId, SchemaId};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display_from(Debug)]
pub struct TxResolverError;

pub type TxResolver = fn(&Txid) -> Result<Option<(Transaction, u64)>, TxResolverError>;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
#[repr(u8)]
pub enum Validity {
    Valid,
    UnresolvedTransactions,
    Invalid,
}

#[derive(Clone, Debug, Display, Default)]
#[display_from(Debug)]
pub struct Status {
    pub unresolved_txids: Vec<Txid>,
    pub failures: Vec<Failure>,
    pub warnings: Vec<Warning>,
    pub info: Vec<Info>,
}

impl AddAssign for Status {
    fn add_assign(&mut self, rhs: Self) {
        self.unresolved_txids.extend(rhs.unresolved_txids);
        self.failures.extend(rhs.failures);
        self.warnings.extend(rhs.warnings);
        self.info.extend(rhs.info);
    }
}

impl Try for Status {
    type Ok = Status;
    type Error = Failure;

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!()
    }

    fn from_error(v: Self::Error) -> Self {
        Status {
            unresolved_txids: vec![],
            failures: vec![v],
            warnings: vec![],
            info: vec![],
        }
    }

    fn from_ok(v: Self::Ok) -> Self {
        v
    }
}

impl FromIterator<Failure> for Status {
    fn from_iter<T: IntoIterator<Item = Failure>>(iter: T) -> Self {
        Self {
            failures: iter.into_iter().collect(),
            ..Self::default()
        }
    }
}

impl Status {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_failure(failure: Failure) -> Self {
        Self {
            failures: vec![failure],
            ..Self::default()
        }
    }

    pub fn add_failure(&mut self, failure: Failure) -> &Self {
        self.failures.push(failure);
        self
    }

    pub fn add_warning(&mut self, warning: Warning) -> &Self {
        self.warnings.push(warning);
        self
    }

    pub fn add_info(&mut self, info: Info) -> &Self {
        self.info.push(info);
        self
    }

    pub fn validity(&self) -> Validity {
        if !self.failures.is_empty() {
            Validity::Invalid
        } else if !self.unresolved_txids.is_empty() {
            Validity::UnresolvedTransactions
        } else {
            Validity::Valid
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display_from(Debug)]
pub enum Failure {
    SchemaUnknown(SchemaId),

    SchemaUnknownTransitionType(NodeId, schema::TransitionType),

    SchemaUnknownFieldType(NodeId, schema::FieldType),

    SchemaUnknownAssignmentType(NodeId, schema::AssignmentsType),

    SchemaDeniedScriptExtension(NodeId),

    // TODO: Replace with named values: this will reduce confusion for developers
    //       usize -> type_id; schema::Bits -> expected_bits
    SchemaMetaValueTooSmall(usize),
    SchemaMetaValueTooLarge(usize),
    SchemaStateValueTooSmall(usize),
    SchemaStateValueTooLarge(usize),
    SchemaMismatchedBits(usize, schema::Bits),
    SchemaWrongEnumValue(usize, u8),
    SchemaWrongDataLength(usize, u16, usize),
    SchemaMismatchedDataType(usize),
    SchemaMismatchedStateType(usize),

    SchemaMetaOccurencesError(NodeId, schema::FieldType, OccurrencesError),
    SchemaAncestorsOccurencesError(NodeId, schema::AssignmentsType, OccurrencesError),
    SchemaSealsOccurencesError(NodeId, schema::AssignmentsType, OccurrencesError),

    TransitionAbsent(NodeId),
    TransitionNotAnchored(NodeId),
    TransitionNotInAnchor(NodeId, AnchorId),
    TransitionAncestorWrongSealType {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::AssignmentsType,
    },
    TransitionAncestorWrongSeal {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::AssignmentsType,
        seal_index: u16,
    },
    TransitionAncestorConfidentialSeal {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::AssignmentsType,
        seal_index: u16,
    },
    TransitionAncestorIsNotWitnessInput {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::AssignmentsType,
        seal_index: u16,
        outpoint: bitcoin::OutPoint,
    },

    WitnessTransactionMissed(Txid),
    WitnessNoCommitment(NodeId, AnchorId, Txid),

    SimplicityIsNotSupportedYet,
    ScriptFailure(NodeId, u8),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display_from(Debug)]
pub enum Warning {
    EndpointTransitionNotFound(NodeId),
    EndpointDuplication(NodeId, seal::Confidential),
    EndpointTransitionSealNotFound(NodeId, seal::Confidential),
    AncestorsHeterogenousAssignments(NodeId, schema::AssignmentsType),
    ExcessiveTransition(NodeId),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display_from(Debug)]
pub enum Info {
    UncheckableConfidentialStateData(NodeId, usize),
}
