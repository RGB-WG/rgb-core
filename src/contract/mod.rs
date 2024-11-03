// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

mod schema;
mod state;
mod operations;
mod commit;

pub use commit::{ContractId, OpId, SchemaId};
pub use operations::{
    Extension, ExtensionType, Genesis, GenesisHeader, Identity, Input, Inputs, Opout, Transition, TransitionType,
};
pub use schema::{Schema, Validators, VmSchema, SCHEMA_LIBS_MAX_COUNT};
pub use seal::RgbSeal;
pub use state::{
    Assign, AssignmentType, Assignments, AttachId, FieldArray, GlobalState, GlobalStateType, GlobalValues, MetaType,
    Metadata, MetadataError, State, TypedAssigns, UnverifiedState, VerifiableState, GLOBAL_STATE_MAX_ITEMS,
    STATE_DATA_MAX_LEN, TYPED_ASSIGNMENTS_MAX_ITEMS,
};

use crate::LIB_NAME_RGB_COMMIT;

mod seal {
    use std::fmt::{Debug, Display};

    use amplify::Bytes32;
    use commit_verify::CommitEncode;
    use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

    pub trait RgbSeal:
        Copy
        + Ord
        + Debug
        + Display
        + StrictEncode
        + StrictDecode
        + StrictDumb
        + CommitEncode<CommitmentId: Into<Bytes32>>
    {
        /// Seal parameters must commit to:
        /// - used layer 1
        /// - used hash functions (in witness)
        /// - used witness ordering algorithm (including PoW etc.)
        type Params: Copy + Ord + Debug + Display + StrictEncode + StrictDecode + StrictDumb;

        fn params() -> Self::Params;
    }
}

/// Fast-forward version code
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display)]
#[display("RGB/1.{0}")]
#[derive(StrictType, StrictEncode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Ffv(u16);

mod _ffv {
    use strict_encoding::{DecodeError, ReadTuple, StrictDecode, TypedRead};

    use crate::Ffv;

    impl StrictDecode for Ffv {
        fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
            let ffv = reader.read_tuple(|r| r.read_field().map(Self))?;
            if ffv != Ffv::default() {
                Err(DecodeError::DataIntegrityError(format!(
                    "unsupported fast-forward version code belonging to a future RGB version. Please update your \
                     software, or, if the problem persists, contact your vendor providing the following version \
                     information: {ffv}"
                )))
            } else {
                Ok(ffv)
            }
        }
    }
}

#[macro_export]
macro_rules! impl_serde_baid64 {
    ($ty:ty) => {
        #[cfg(feature = "serde")]
        mod _serde {
            use amplify::ByteArray;
            use serde::de::Error;
            use serde::{Deserialize, Deserializer, Serialize, Serializer};

            use super::*;

            impl Serialize for $ty {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: Serializer {
                    if serializer.is_human_readable() {
                        self.to_string().serialize(serializer)
                    } else {
                        self.to_byte_array().serialize(serializer)
                    }
                }
            }

            impl<'de> Deserialize<'de> for $ty {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where D: Deserializer<'de> {
                    if deserializer.is_human_readable() {
                        let s = String::deserialize(deserializer)?;
                        Self::from_str(&s).map_err(D::Error::custom)
                    } else {
                        let bytes = <[u8; 32]>::deserialize(deserializer)?;
                        Ok(Self::from_byte_array(bytes))
                    }
                }
            }
        }
    };
}
