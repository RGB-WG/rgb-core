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

use std::str::FromStr;

use bitcoin::secp256k1;
use bitcoin::util::bip32::ChildNumber;
use miniscript::descriptor::{DescriptorKeyParseError, DescriptorPublicKey};
use miniscript::ToPublicKey;

use crate::SECP256K1;

/// Errors related to extended descriptor parsing
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ParseError {
    /// Wrong key format: "{_0}"
    /// It must be in a form of miniscript descriptor public key, optionally
    /// followed by `+` sign and hex-encoded representation of a tweaking
    /// factor.
    WrongFormat(String),

    /// Provided tweaking factor can't be converted into a valid Secp256k1
    /// curve point ({_0})
    WrongTweakFormat(String),

    // TODO: (new) Once miniscript will do a better descriptor parse errors,
    //       change this
    /// Miniscript returned public key string parsing error:
    /// {_0}
    Other(String),
}

impl From<DescriptorKeyParseError> for ParseError {
    fn from(err: DescriptorKeyParseError) -> Self {
        ParseError::Other(err.to_string())
    }
}

/// Public key information that can be used as a part of Bitcoin Core/miniscript
/// descriptors and parsed/serialized into string. Unlike
/// [`miniscript::DescriptorPublicKey`] type can contain tweaking factor applied
/// to a public key after derication. In string-serialized form this factor
/// can be given as an optional extension after `+` sign.
#[derive(Clone, PartialEq, Eq, Debug, Display)]
pub enum PublicKey {
    /// Public key or extended public key without tweaking factor information
    #[display("{_0}")]
    Native(DescriptorPublicKey),

    /// Public key or extended public key with tweaking information
    #[display("{_0}+{_1}")]
    Tweaked(DescriptorPublicKey, secp256k1::SecretKey),
}

impl FromStr for PublicKey {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('+');
        Ok(match (parts.next(), parts.next(), parts.next()) {
            (Some(key), None, _) => {
                PublicKey::Native(DescriptorPublicKey::from_str(key)?)
            }
            (Some(key), Some(tweak), None) => {
                let dpk = DescriptorPublicKey::from_str(key)?;
                let sk =
                    secp256k1::SecretKey::from_str(tweak).map_err(|_| {
                        ParseError::WrongTweakFormat(tweak.to_string())
                    })?;
                let _ = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sk);
                PublicKey::Tweaked(dpk, sk)
            }
            _ => return Err(ParseError::WrongFormat(s.to_string())),
        })
    }
}

impl PublicKey {
    /// Returns whether key has embedded tweaking information
    pub fn has_tweak(&self) -> bool {
        match self {
            PublicKey::Native(_) => false,
            PublicKey::Tweaked(_, _) => true,
        }
    }

    /// Returns reference to a tweaking factor (in form of
    /// [`Option::Some`]`(`[`secp256k1::SecretKey`]`)` for
    /// [`PublicKey::Tweaked`] variant, or [`Option::None`] otherwise
    pub fn as_tweaking_factor(&self) -> Option<&secp256k1::SecretKey> {
        match self {
            PublicKey::Native(_) => None,
            PublicKey::Tweaked(_, tweak_factor) => Some(tweak_factor),
        }
    }

    /// Returns reference to an untweaked [`DescriptorPublicKey`] value
    pub fn as_descriptor_public_key(&self) -> &DescriptorPublicKey {
        match self {
            PublicKey::Native(pk) | PublicKey::Tweaked(pk, _) => pk,
        }
    }

    /// Converts into a tweaking factor value (in form of
    /// [`Option::Some`]`(`[`secp256k1::SecretKey`]`)` for
    /// [`PublicKey::Tweaked`] variant, or [`Option::None`] otherwise
    pub fn into_tweaking_factor(self) -> Option<secp256k1::SecretKey> {
        match self {
            PublicKey::Native(_) => None,
            PublicKey::Tweaked(_, tweak_factor) => Some(tweak_factor),
        }
    }

    /// Converts into an untweaked [`DescriptorPublicKey`] value
    pub fn into_descriptor_public_key(self) -> DescriptorPublicKey {
        match self {
            PublicKey::Native(pk) | PublicKey::Tweaked(pk, _) => pk,
        }
    }

    /// Converts into an untweaked [`DescriptorPublicKey`] value, optionally
    /// using derivation into a child with `index`
    pub fn to_tweaked_public_key(
        &self,
        index: Option<u32>,
    ) -> Option<secp256k1::PublicKey> {
        self.as_tweaking_factor().and_then(|factor| {
            let dpk = self.as_descriptor_public_key().clone();
            let mut pk = match index {
                Some(index) => {
                    dpk.derive(ChildNumber::Normal { index })
                        .to_public_key()
                        .key
                }
                None => dpk.to_public_key().key,
            };
            pk.add_exp_assign(&SECP256K1, &factor[..]).ok()?;
            Some(pk)
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};

    #[test]
    fn test_success() {
        let dpk = vec![
            "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*",
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1",
            "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8"
        ];
        let tweak =
            secp256k1::SecretKey::from_slice(&sha256::Hash::hash(b"test"))
                .unwrap();
        let tdpk = dpk
            .iter()
            .map(|k| format!("{}+{:x}", k, tweak))
            .collect::<Vec<_>>();

        for pkstr in dpk {
            let pk = PublicKey::from_str(pkstr).unwrap();
            assert_eq!(pk.has_tweak(), false);
            assert_eq!(pk.as_tweaking_factor(), None);
            assert_eq!(pk.to_tweaked_public_key(None), None);
            assert_eq!(pk.into_tweaking_factor(), None);
        }

        for pkstr in tdpk {
            let pk = PublicKey::from_str(&pkstr).unwrap();
            assert_eq!(pk.has_tweak(), true);

            assert_eq!(pk.as_tweaking_factor().unwrap(), &tweak);
            assert_ne!(
                pk.to_tweaked_public_key(None).unwrap(),
                pk.clone().into_descriptor_public_key().to_public_key().key
            );
            assert_eq!(pk.into_tweaking_factor().unwrap(), tweak);
        }
    }
}
