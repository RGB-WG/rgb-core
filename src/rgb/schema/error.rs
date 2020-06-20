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

use super::{FieldType, OccurencesError};
use crate::rgb::contract::data;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub enum Error {
    InvalidValue(data::Revealed),
    MinMaxBoundsOnLargeInt,

    OccurencesNotMet(OccurencesError),

    UnknownField(FieldType),
    InvalidField(FieldType, Box<Error>),

    InvalidTransitionId(usize),
    //InvalidBoundSeal(seal::Type, Box<Error>),
    //InvalidBoundSealId(seal::Type),
    //InvalidBoundSealValue(seal::Type, StateFormat, data::Revealed),
    //InvalidOutputBalanceBulletProof(usize),
}
