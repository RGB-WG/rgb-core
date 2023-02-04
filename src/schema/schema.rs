// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::{BTreeMap, BTreeSet};

use amplify::Bytes32;
use baid58::ToBaid58;
use commit_verify::{strategies, CommitStrategy};

use super::{
    ExtensionSchema, GenesisSchema, OwnedRightType, PublicRightType, StateSchema, TransitionSchema,
    ValidationScript,
};
use crate::ext::RawArray;
use crate::LIB_NAME_RGB;

// Here we can use usize since encoding/decoding makes sure that it's u16
pub type FieldType = u16;
pub type ExtensionType = u16;
pub type TransitionType = u16;

/// Schema identifier.
///
/// Schema identifier commits to all of the schema data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, FromStr, Hex, Index, RangeOps)]
#[display(Self::to_baid58)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SchemaId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitStrategy for SchemaId {
    type Strategy = strategies::Strict;
}

impl ToBaid58<32> for SchemaId {
    const HRP: &'static str = "sch";
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_raw_array() }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Schema {
    /// Feature flags control which of the available RGB features are allowed
    /// for smart contracts created under this schema.
    ///
    /// NB: This is not the same as RGB protocol versioning: feature flag set
    /// is specific to a particular RGB protocol version. The only currently
    /// defined RGB version is RGBv1; future versions may change the whole
    /// structure of Schema data, use of feature flags, re-define their meaning
    /// or do other backward-incompatible changes (RGB protocol versions are
    /// not interoperable and backward-incompatible by definitions and the
    /// nature of client-side-validation which does not allow upgrades).
    pub rgb_features: u16,
    pub root_id: SchemaId,

    pub type_system: Vec<u8>, // TODO: TypeSystem,
    pub field_types: BTreeMap<FieldType, ()>,
    pub owned_right_types: BTreeMap<OwnedRightType, StateSchema>,
    pub public_right_types: BTreeSet<PublicRightType>,
    pub genesis: GenesisSchema,
    pub extensions: BTreeMap<ExtensionType, ExtensionSchema>,
    pub transitions: BTreeMap<TransitionType, TransitionSchema>,

    /// Validation code.
    pub script: ValidationScript,
}

impl Schema {
    #[inline]
    pub fn schema_id(&self) -> SchemaId { todo!() }
}

impl PartialEq for Schema {
    fn eq(&self, other: &Self) -> bool { self.schema_id() == other.schema_id() }
}

impl Eq for Schema {}

#[cfg(test)]
mod test {
    use strict_encoding::StrictDumb;

    use super::*;

    #[test]
    fn display() {
        let dumb = SchemaId::strict_dumb();
        assert_eq!(dumb.to_string(), "11111111111111111111111111111111");
        assert_eq!(
            &format!("{dumb::^#}"),
            "sch:11111111111111111111111111111111#dallas-liter-marco"
        );

        let less_dumb = SchemaId::from_raw_array(*b"EV4350-'4vwj'4;v-w94w'e'vFVVDhpq");
        assert_eq!(less_dumb.to_string(), "5ffNUkMTVSnWquPLT6xKb7VmAxUbw8CUNqCkUWsZfkwz");
        assert_eq!(
            &format!("{less_dumb::^#}"),
            "sch:5ffNUkMTVSnWquPLT6xKb7VmAxUbw8CUNqCkUWsZfkwz#hotel-urgent-child"
        );
    }
}
