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

use crate::csv;

// TODO: Convert Amount to a Pedersen commitment format
construct_uint!(Amount, 4);
impl csv::serialize::FromConsensus for Amount { }


#[non_exhaustive]
#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum Data {
    Balance(Amount),
    Binary(Box<[u8]>),
    // TODO: Add other supported bound state types according to the schema
}
