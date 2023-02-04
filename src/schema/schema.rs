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

use amplify::flags::FlagVec;
use bitcoin_hashes::{sha256, sha256t};

use super::{ExtensionSchema, GenesisSchema, OwnedRightType, PublicRightType, TransitionSchema};
use crate::schema::StateSchema;
use crate::script::OverrideRules;
use crate::ValidationScript;

// Here we can use usize since encoding/decoding makes sure that it's u16
pub type FieldType = u16;
pub type ExtensionType = u16;
pub type TransitionType = u16;

static MIDSTATE_SHEMA_ID: [u8; 32] = [
    0x81, 0x73, 0x33, 0x7c, 0xcb, 0xc4, 0x8b, 0xd1, 0x24, 0x89, 0x65, 0xcd, 0xd0, 0xcd, 0xb6, 0xc8,
    0x7a, 0xa2, 0x14, 0x81, 0x7d, 0x57, 0x39, 0x22, 0x28, 0x90, 0x74, 0x8f, 0x26, 0x75, 0x8e, 0xea,
];

/// Tag used for [`SchemaId`] hash type
pub struct SchemaIdTag;

impl sha256t::Tag for SchemaIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_SHEMA_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Commitment-based schema identifier used for committing to the schema type
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[wrapper(Debug, BorrowSlice)]
pub struct SchemaId(sha256t::Hash<SchemaIdTag>);

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
    #[cfg_attr(feature = "serde", serde(with = "serde_with::rust::display_fromstr"))]
    pub rgb_features: FlagVec,
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

    /// Defines whether subschemata are allowed to replace (override) the code
    ///
    /// Subschemata not overriding the main schema code MUST set the virtual
    /// machine type to the same as in the parent schema and set byte code
    /// to be empty (zero-length)
    pub override_rules: OverrideRules,
}

impl Schema {
    #[inline]
    pub fn schema_id(&self) -> SchemaId { todo!() }
}

impl PartialEq for Schema {
    fn eq(&self, other: &Self) -> bool { self.schema_id() == other.schema_id() }
}

impl Eq for Schema {}
