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

use bitcoin::hashes::{sha256t, Hash};
use std::{collections::BTreeMap, io};

use super::{
    scripting, FieldFormat, FieldId, SealTypeId, StateFormat, Transition, TransitionTypeId,
};

static MIDSTATE_SHEMAID: [u8; 32] = [
    25, 205, 224, 91, 171, 217, 131, 31, 140, 104, 5, 155, 127, 82, 14, 81, 58, 245, 79, 165, 114,
    243, 110, 60, 133, 174, 103, 187, 103, 230, 9, 106,
];

tagged_hash!(
    SchemaId,
    SchemaIdTag,
    MIDSTATE_SHEMAID,
    doc = "Commitment-based schema identifier used for committing to the schema type"
);

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Schema {
    pub field_types: BTreeMap<FieldId, FieldFormat>,
    pub seal_types: BTreeMap<SealTypeId, StateFormat>,
    pub transitions: BTreeMap<TransitionTypeId, Transition>,
    pub script_library: Vec<u8>,
    pub script_extensions: scripting::Extensions,
}

mod strict_encoding {
    use super::*;
    use crate::paradigms::strict_encoding::Error;
    use crate::strict_encoding::{StrictDecode, StrictEncode};

    impl StrictEncode for Schema {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e;
                self.field_types,
                self.seal_types,
                self.transitions,
                self.script_library,
                self.script_extensions
            ))
        }
    }

    impl StrictDecode for Schema {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            Ok(Self {
                field_types: BTreeMap::strict_decode(&mut d)?,
                seal_types: BTreeMap::strict_decode(&mut d)?,
                transitions: BTreeMap::strict_decode(&mut d)?,
                script_library: Vec::strict_decode(&mut d)?,
                script_extensions: scripting::Extensions::strict_decode(&mut d)?,
            })
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod test {
    use super::{super::Occurences, *};
    use scripting::Scripting;

    #[test]
    fn schema_test() {
        const TRANSITION_VAL: usize = 0;
        const FIELD_VAL: usize = 5;
        const SEAL_VAL: usize = 1;

        let schema_transition = Transition {
            closes: bmap! {}.into(),
            defines: bmap! { SEAL_VAL => Occurences::Once }.into(),
            metadata: bmap! {
                FIELD_VAL => Occurences::Once,
            },
            scripting: Scripting {
                validation: scripting::Procedure::NoValidation,
                extensions: scripting::Extensions::ScriptsDenied,
            },
        };
        let schema = Schema {
            field_types: bmap! { FIELD_VAL => FieldFormat::String(10) },
            seal_types: bmap! { SEAL_VAL => StateFormat::Empty },
            transitions: bmap! {
                TRANSITION_VAL => schema_transition
            },
            script_library: vec![],
            script_extensions: scripting::Extensions::ScriptsDenied,
        };

        println!("{:#?}", schema);
    }
}
