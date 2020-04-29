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

use std::collections::BTreeMap;
use std::io;

use super::{FieldId, Occurences, Scripting};

pub type SealTypeId = usize; // Here we can use usize since encoding/decoding makes sure that it's u16
pub type TransitionTypeId = usize; // Here we can use usize since encoding/decoding makes sure that it's u16
pub type MetadataStructure = BTreeMap<FieldId, Occurences<u16>>;
pub type SealsStructure = BTreeMap<SealTypeId, Occurences<u16>>;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Transition {
    pub metadata: MetadataStructure,
    pub closes: SealsStructure,
    pub defines: SealsStructure,
    pub scripting: Scripting,
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};

    impl StrictEncode for Transition {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            self.metadata.strict_encode(&mut e)?;
            self.closes.strict_encode(&mut e)?;
            self.defines.strict_encode(&mut e)?;
            self.scripting.strict_encode(&mut e)
        }
    }

    impl StrictDecode for Transition {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            Ok(Self {
                metadata: MetadataStructure::strict_decode(&mut d)?,
                closes: SealsStructure::strict_decode(&mut d)?,
                defines: SealsStructure::strict_decode(&mut d)?,
                scripting: Scripting::strict_decode(&mut d)?,
            })
        }
    }
}
