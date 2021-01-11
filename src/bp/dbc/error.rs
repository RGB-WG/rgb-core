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

    /// LNPBP-2 standard requires OP_RETURN-based commitments to be produced
    /// only if serialized version of a tweaked pubkey starts with `02` byte.
    /// This error indicates that the provided public key does not satisfy this
    /// condition
    InvalidOpReturnKey,

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

    /// Policy compilation error
    #[from]
    #[display(inner)]
    PolicyCompilation(miniscript::policy::compiler::CompilerError),
}

impl From<bp::descriptor::Error> for Error {
    fn from(err: bp::descriptor::Error) -> Self {
        match err {
            bp::descriptor::Error::InvalidKeyData => Error::InvalidKeyData,
            bp::descriptor::Error::UnsupportedWitnessVersion => {
                Error::UnsupportedWitnessVersion
            }
            bp::descriptor::Error::PolicyCompilation(err) => {
                Error::PolicyCompilation(err)
            }
        }
    }
}
