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

use super::{data, AssignmentsVariant};
use crate::bp;
use crate::rgb::{schema, Schema, SimplicityScript};
use std::collections::{BTreeMap, BTreeSet};

pub type Metadata = BTreeMap<schema::FieldType, BTreeSet<data::Revealed>>;
pub type Assignments = BTreeMap<schema::AssignmentsType, AssignmentsVariant>;

pub trait Node {
    /*
    fn field_types(&self) -> Set<schema::FieldType>;
    fn assignments_types(&self) -> Set<schema::AssignmentsType>;
    fn metadata(&self) -> Metadata;
    fn assignments(&self) -> Assignments;
    fn script(&self) -> SimplicityScript;
     */
}

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Genesis {
    pub schema: Schema,
    pub network: bp::Network,
    metadata: Metadata,
    assignments: Assignments,
    script: SimplicityScript,
}

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Transition {
    pub type_id: schema::TransitionType,
    metadata: Metadata,
    assignments: Assignments,
    script: SimplicityScript,
}

impl Node for Genesis {}

impl Node for Transition {}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use std::io;

    impl StrictEncode for Genesis {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e;
                    self.schema,
                    self.network,
                    self.metadata,
                    self.assignments,
                    self.script))
        }
    }

    impl StrictDecode for Genesis {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            Ok(Self {
                schema: Schema::strict_decode(&mut d)?,
                network: bp::Network::strict_decode(&mut d)?,
                metadata: Metadata::strict_decode(&mut d)?,
                assignments: Assignments::strict_decode(&mut d)?,
                script: SimplicityScript::strict_decode(&mut d)?,
            })
        }
    }

    impl StrictEncode for Transition {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e;
                    self.type_id,
                    self.metadata,
                    self.assignments,
                    self.script))
        }
    }

    impl StrictDecode for Transition {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            Ok(Self {
                type_id: schema::TransitionType::strict_decode(&mut d)?,
                metadata: Metadata::strict_decode(&mut d)?,
                assignments: Assignments::strict_decode(&mut d)?,
                script: SimplicityScript::strict_decode(&mut d)?,
            })
        }
    }
}
