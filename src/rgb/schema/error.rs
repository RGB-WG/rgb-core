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

use super::OccurencesError;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub enum Error {
    MinMaxBoundsOnLargeInt,
    OccurencesNotMet(OccurencesError),
    /*
    UnknownField(transition::metadata::Type),
    InvalidField(transition::metadata::Type, Box<SchemaError>),

    InvalidTransitionId(usize),

    InvalidOutputBalanceBulletProof(usize),
     */
}
