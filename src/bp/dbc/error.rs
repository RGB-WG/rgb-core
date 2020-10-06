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

use crate::bp;
use crate::lnpbp1;

/// Different error types which may happen during deterministic bitcoin
/// commitment generation procedures
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// Indicates failure of applying commitment tweak to a public key
    #[from]
    Lnpbp1Commitment(lnpbp1::Error),

    /// Unable to verify commitment due to an incorrect proof data structure
    InvalidProofStructure,

    /// Can't deserealized public key from bitcoin script push op code
    InvalidKeyData,

    /// Wrong witness version, may be you need to upgrade used library version
    UnsupportedWitnessVersion,

    /// Miniscript was unable to parse provided script data; they are either
    /// invalid or miniscript library contains a bug
    #[from(crate::bp::scripts::PubkeyParseError)]
    LockscriptParseError,

    /// Provided script contains no keys, so commitment or its verification is
    /// impossible
    LockscriptContainsNoKeys,

    /// Bitcoin script contains public key hashes with no matching public
    /// keys provided. Commitment procedure fails since it can't ensure that
    /// commitment include all public key.
    LockscriptContainsUnknownHashes,

    /// Attempt to commit into LockScript has failed: the key that must contain
    /// the commitment/tweak was not found either in plain nor hash form in
    /// any of the script branches
    LockscriptKeyNotFound,
}

impl From<bp::scripts::Error> for Error {
    fn from(err: bp::scripts::Error) -> Self {
        match err {
            bp::scripts::Error::InvalidKeyData => Error::InvalidKeyData,
            bp::scripts::Error::UnsupportedWitnessVersion => {
                Error::UnsupportedWitnessVersion
            }
        }
    }
}
