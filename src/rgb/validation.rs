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

use super::{schema, NodeId, SchemaId};

#[derive(Clone, Debug, Display, Default)]
#[display_from(Debug)]
pub struct Status {
    pub failures: Vec<Failure>,
    pub warnings: Vec<Warning>,
    pub info: Vec<Info>,
}

impl AddAssign for Status {
    fn add_assign(&mut self, rhs: Self) {
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

    pub fn is_valid(&self) -> bool {
        return self.failures.is_empty();
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display_from(Debug)]
pub enum Failure {
    SchemaUnknown(SchemaId),

    SchemaUnknownTransitionType(NodeId, schema::TransitionType),

    /// If the second parameter is `None` it means that error occurred during
    /// validation of a Genesis node
    SchemaUnknownFieldType(NodeId, Option<schema::TransitionType>, schema::FieldType),

    /// If the second parameter is `None` it means that error occurred during
    /// validation of a Genesis node
    SchemaUnknownAssignmentType(
        NodeId,
        Option<schema::TransitionType>,
        schema::AssignmentsType,
    ),

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
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display_from(Debug)]
pub enum Warning {}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display_from(Debug)]
pub enum Info {
    UncheckableConfidentialStateData(NodeId, usize),
}
