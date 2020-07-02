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

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

/// For now, Simplicity script is not implemented, so we use a byte array as a
/// placeholder for script data
pub type SimplicityScript = Vec<u8>;

#[non_exhaustive]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive,
)]
#[display_from(Debug)]
pub enum GenesisAction {}

#[non_exhaustive]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive,
)]
#[display_from(Debug)]
#[repr(u8)]
pub enum TransitionAction {
    GenerateBlank = 0,
}

#[non_exhaustive]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive,
)]
#[display_from(Debug)]
#[repr(u8)]
pub enum AssignmentAction {
    Validate = 0,
}

pub type GenesisAbi = BTreeMap<GenesisAction, Procedure>;
pub type TransitionAbi = BTreeMap<TransitionAction, Procedure>;
pub type AssignmentAbi = BTreeMap<AssignmentAction, Procedure>;

#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub enum Procedure {
    Standard(StandardProcedure),
    Simplicity { offset: u32 },
}

#[non_exhaustive]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive,
)]
#[display_from(Debug)]
#[repr(u8)]
pub enum StandardProcedure {
    ConfidentialAmount = 1,
    IssueControl = 2,
    Prunning = 3,
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};

    impl_enum_strict_encoding!(GenesisAction);
    impl_enum_strict_encoding!(TransitionAction);
    impl_enum_strict_encoding!(AssignmentAction);

    impl_enum_strict_encoding!(StandardProcedure);

    impl StrictEncode for Procedure {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            Ok(match self {
                Self::Simplicity { offset } => strict_encode_list!(e; 0u8, offset),
                Self::Standard(proc_id) => strict_encode_list!(e; 0xFFu8, proc_id),
            })
        }
    }

    impl StrictDecode for Procedure {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            Ok(match u8::strict_decode(&mut d)? {
                0u8 => Self::Simplicity {
                    offset: u32::strict_decode(&mut d)?,
                },
                0xFFu8 => Self::Standard(StandardProcedure::strict_decode(&mut d)?),
                x => Err(Error::EnumValueNotKnown("script::Procedure".to_string(), x))?,
            })
        }
    }
}
