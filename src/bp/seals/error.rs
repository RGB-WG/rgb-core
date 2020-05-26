// LNP/BP Core Library implementing LNPBP specifications & standards
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

use crate::bp::dbc;

#[derive(Clone, PartialEq, Debug, Display, From, Error)]
#[display_from(Debug)]
pub enum Error {
    InvalidSealDefinition,
    SpentTxout,
    MediumAccessError,
    CommitmentError(dbc::Error),
    ResolverError,
    ResolverLying,
}

impl From<dbc::Error> for Error {
    fn from(err: dbc::Error) -> Self {
        Self::CommitmentError(err)
    }
}
