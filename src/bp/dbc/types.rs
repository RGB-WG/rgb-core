// LNP/BP Rust Library
// Written in 2019 by
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

use bitcoin::{hashes::sha256, secp256k1};

use super::Error;
use crate::bp::LockScript;

pub trait Container: Sized {
    type Supplement;
    type Host;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        host: &Self::Host,
    ) -> Result<Self, Error>;

    fn deconstruct(self) -> (Proof, Self::Supplement);

    fn to_proof(&self) -> Proof;
    fn into_proof(self) -> Proof;
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
pub struct Proof {
    pub pubkey: secp256k1::PublicKey,
    pub script_info: ScriptInfo,
}

impl From<secp256k1::PublicKey> for Proof {
    fn from(pubkey: secp256k1::PublicKey) -> Self {
        Self {
            pubkey,
            script_info: ScriptInfo::None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ScriptInfo {
    None,
    LockScript(LockScript),
    Taproot(sha256::Hash),
}

pub(super) mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use num_derive::{FromPrimitive, ToPrimitive};
    use num_traits::{FromPrimitive, ToPrimitive};
    use std::io;

    #[derive(FromPrimitive, ToPrimitive)]
    #[repr(u8)]
    pub(in super::super) enum EncodingTag {
        None = 0,
        LockScript = 1,
        Taproot = 2,
    }
    impl_enum_strict_encoding!(EncodingTag);

    impl StrictEncode for ScriptInfo {
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
            Ok(match self {
                ScriptInfo::None => EncodingTag::None.strict_encode(&mut e)?,
                ScriptInfo::LockScript(val) => strict_encode_list!(e; EncodingTag::LockScript, val),
                ScriptInfo::Taproot(val) => strict_encode_list!(e; EncodingTag::Taproot, val),
            })
        }
    }

    impl StrictDecode for ScriptInfo {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
            let format = EncodingTag::strict_decode(&mut d)?;
            Ok(match format {
                EncodingTag::None => ScriptInfo::None,
                EncodingTag::LockScript => {
                    ScriptInfo::LockScript(LockScript::strict_decode(&mut d)?)
                }
                EncodingTag::Taproot => ScriptInfo::Taproot(sha256::Hash::strict_decode(&mut d)?),
            })
        }
    }

    impl StrictEncode for Proof {
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
            Ok(strict_encode_list!(e; self.pubkey, self.script_info))
        }
    }

    impl StrictDecode for Proof {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
            Ok(Self {
                pubkey: secp256k1::PublicKey::strict_decode(&mut d)?,
                script_info: ScriptInfo::strict_decode(&mut d)?,
            })
        }
    }
}
