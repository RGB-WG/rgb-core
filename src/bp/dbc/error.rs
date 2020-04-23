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

use crate::bp::LockScriptParseError;
use bitcoin::secp256k1;

#[derive(Debug, Display, Error, From)]
#[display_from(Debug)]
pub enum Error {
    //#[derive_from(secp256k1::Error)]
    Secp256k1(secp256k1::Error),

    //#[derive_from(LockScriptParseError<bitcoin::PublicKey>)]
    LockScript(LockScriptParseError<bitcoin::PublicKey>),
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        Self::Secp256k1(err)
    }
}

impl From<LockScriptParseError<bitcoin::PublicKey>> for Error {
    fn from(err: LockScriptParseError<bitcoin::PublicKey>) -> Self {
        Self::LockScript(err)
    }
}
