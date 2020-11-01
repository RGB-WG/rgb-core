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

use bitcoin::hashes::hash160;
use bitcoin::secp256k1;
use bitcoin::util::bip32::ChildNumber;
use miniscript::descriptor::{DescriptorKeyParseError, DescriptorPublicKey};
use miniscript::{MiniscriptKey, ToPublicKey};
use std::hash::{Hash, Hasher};

use crate::SECP256K1;

/// Errors related to extended descriptor parsing
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ParseError {
    /// Wrong key format: "{0}"
    /// It must be in a form of miniscript descriptor public key, optionally
    /// followed by `+` sign and hex-encoded representation of a tweaking
    /// factor.
    WrongFormat(String),

    /// Provided tweaking factor can't be converted into a valid Secp256k1
    /// curve point ({0})
    WrongTweakFormat(String),

    // TODO: (new) Once miniscript will do a better descriptor parse errors,
    //       change this
    /// Miniscript returned public key string parsing error:
    /// {0}
    Other(String),
}

impl From<DescriptorKeyParseError> for ParseError {
    fn from(err: DescriptorKeyParseError) -> Self {
        ParseError::Other(err.to_string())
    }
}

pub trait MaybeTweakPair {
    /// Returns whether key has embedded tweaking information
    fn has_tweak(&self) -> bool;

    /// Returns reference to a tweaking factor (in form of
    /// [`Option::Some`]`(`[`secp256k1::SecretKey`]`)` for
    /// [`PublicKey::Tweaked`] variant, or [`Option::None`] otherwise
    fn as_tweaking_factor(&self) -> Option<&secp256k1::SecretKey>;

    /// Returns reference to an untweaked [`DescriptorPublicKey`] value
    fn as_descriptor_public_key(&self) -> &DescriptorPublicKey;

    /// Converts into a tweaking factor value (in form of
    /// [`Option::Some`]`(`[`secp256k1::SecretKey`]`)` for
    /// [`PublicKey::Tweaked`] variant, or [`Option::None`] otherwise
    fn into_tweaking_factor(self) -> Option<secp256k1::SecretKey>;

    /// Converts into an untweaked [`DescriptorPublicKey`] value
    fn into_descriptor_public_key(self) -> DescriptorPublicKey;

    /// Converts into an untweaked [`DescriptorPublicKey`] value, optionally
    /// using derivation into a child with `index`
    fn to_tweaked_public_key(&self, index: Option<u32>)
        -> secp256k1::PublicKey;
}

/// Representation of a public key with attached tweaking factor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display("{pubkey}+{tweak}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct PubkeyWithTweak {
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::rust::display_fromstr")
    )]
    pub pubkey: DescriptorPublicKey,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::rust::display_fromstr")
    )]
    pub tweak: secp256k1::SecretKey,
}

impl Hash for PubkeyWithTweak {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pubkey.hash(state);
        self.tweak.as_ref().hash(state);
    }
}

impl FromStr for PubkeyWithTweak {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('+');

        Ok(match (parts.next(), parts.next(), parts.next()) {
            (Some(key), Some(tweak), None) => {
                let pubkey = DescriptorPublicKey::from_str(key)?;
                let tweak =
                    secp256k1::SecretKey::from_str(tweak).map_err(|_| {
                        ParseError::WrongTweakFormat(tweak.to_string())
                    })?;
                let _ =
                    secp256k1::PublicKey::from_secret_key(&SECP256K1, &tweak);
                PubkeyWithTweak { pubkey, tweak }
            }
            _ => return Err(ParseError::WrongFormat(s.to_string())),
        })
    }
}

impl MaybeTweakPair for PubkeyWithTweak {
    /// Returns whether key has embedded tweaking information
    fn has_tweak(&self) -> bool {
        true
    }

    /// Returns reference to a tweaking factor (in form of
    /// [`Option::Some`]`(`[`secp256k1::SecretKey`]`)` for
    /// [`PublicKey::Tweaked`] variant, or [`Option::None`] otherwise
    fn as_tweaking_factor(&self) -> Option<&secp256k1::SecretKey> {
        Some(&self.tweak)
    }

    /// Returns reference to an untweaked [`DescriptorPublicKey`] value
    fn as_descriptor_public_key(&self) -> &DescriptorPublicKey {
        &self.pubkey
    }

    /// Converts into a tweaking factor value (in form of
    /// [`Option::Some`]`(`[`secp256k1::SecretKey`]`)` for
    /// [`PublicKey::Tweaked`] variant, or [`Option::None`] otherwise
    fn into_tweaking_factor(self) -> Option<secp256k1::SecretKey> {
        Some(self.tweak)
    }

    /// Converts into an untweaked [`DescriptorPublicKey`] value
    fn into_descriptor_public_key(self) -> DescriptorPublicKey {
        self.pubkey
    }

    /// Converts into an untweaked [`DescriptorPublicKey`] value, optionally
    /// using derivation into a child with `index`
    fn to_tweaked_public_key(
        &self,
        index: Option<u32>,
    ) -> secp256k1::PublicKey {
        let dpk = self.as_descriptor_public_key().clone();
        let mut pk = match index {
            Some(index) => {
                dpk.derive(ChildNumber::Normal { index })
                    .to_public_key()
                    .key
            }
            None => dpk.to_public_key().key,
        };
        pk.add_exp_assign(&SECP256K1, &self.tweak[..]).expect(
            "Tweaking with secret key can fail with negligible probability",
        );
        pk
    }
}

impl MiniscriptKey for PubkeyWithTweak {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash {
        self.clone()
    }
}

impl ToPublicKey for PubkeyWithTweak {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        bitcoin::PublicKey {
            compressed: true,
            key: self.to_tweaked_public_key(None),
        }
    }

    fn hash_to_hash160(hash: &Self::Hash) -> hash160::Hash {
        hash.to_public_key().to_pubkeyhash()
    }
}

/// Public key information that can be used as a part of Bitcoin Core/miniscript
/// descriptors and parsed/serialized into string. Unlike
/// [`miniscript::DescriptorPublicKey`] type can contain tweaking factor applied
/// to a public key after derication. In string-serialized form this factor
/// can be given as an optional extension after `+` sign.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum PubkeyExtended {
    /// Public key or extended public key without tweaking factor information
    #[display(inner)]
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::rust::display_fromstr")
    )]
    Native(DescriptorPublicKey),

    /// Public key or extended public key with tweaking information
    #[display(inner)]
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::rust::display_fromstr")
    )]
    Tweaked(PubkeyWithTweak),
}

impl Hash for PubkeyExtended {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            PubkeyExtended::Native(pk) => pk.hash(state),
            PubkeyExtended::Tweaked(tpk) => tpk.hash(state),
        }
    }
}

impl FromStr for PubkeyExtended {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s.contains('+') {
            PubkeyExtended::Tweaked(PubkeyWithTweak::from_str(s)?)
        } else {
            PubkeyExtended::Native(DescriptorPublicKey::from_str(s)?)
        })
    }
}

impl PubkeyExtended {
    /// Returns whether key has embedded tweaking information
    pub fn has_tweak(&self) -> bool {
        match self {
            PubkeyExtended::Native(_) => false,
            PubkeyExtended::Tweaked(_) => true,
        }
    }

    /// Returns reference to a tweaking factor (in form of
    /// [`Option::Some`]`(`[`secp256k1::SecretKey`]`)` for
    /// [`PublicKey::Tweaked`] variant, or [`Option::None`] otherwise
    pub fn as_tweaking_factor(&self) -> Option<&secp256k1::SecretKey> {
        match self {
            PubkeyExtended::Native(_) => None,
            PubkeyExtended::Tweaked(t) => t.as_tweaking_factor(),
        }
    }

    /// Returns reference to an untweaked [`DescriptorPublicKey`] value
    pub fn as_descriptor_public_key(&self) -> &DescriptorPublicKey {
        match self {
            PubkeyExtended::Native(pk) => pk,
            PubkeyExtended::Tweaked(pk) => pk.as_descriptor_public_key(),
        }
    }

    /// Converts into a tweaking factor value (in form of
    /// [`Option::Some`]`(`[`secp256k1::SecretKey`]`)` for
    /// [`PublicKey::Tweaked`] variant, or [`Option::None`] otherwise
    pub fn into_tweaking_factor(self) -> Option<secp256k1::SecretKey> {
        match self {
            PubkeyExtended::Native(_) => None,
            PubkeyExtended::Tweaked(tpk) => tpk.into_tweaking_factor(),
        }
    }

    /// Converts into an untweaked [`DescriptorPublicKey`] value
    pub fn into_descriptor_public_key(self) -> DescriptorPublicKey {
        match self {
            PubkeyExtended::Native(pk) => pk,
            PubkeyExtended::Tweaked(pk) => pk.into_descriptor_public_key(),
        }
    }

    /// Converts into an untweaked [`DescriptorPublicKey`] value, optionally
    /// using derivation into a child with `index`
    pub fn to_tweaked_public_key(
        &self,
        index: Option<u32>,
    ) -> secp256k1::PublicKey {
        match self {
            PubkeyExtended::Native(_) => {
                self.clone()
                    .into_descriptor_public_key()
                    .to_public_key()
                    .key
            }
            PubkeyExtended::Tweaked(tpk) => tpk.to_tweaked_public_key(index),
        }
    }
}

impl MiniscriptKey for PubkeyExtended {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash {
        self.clone()
    }
}

impl ToPublicKey for PubkeyExtended {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        bitcoin::PublicKey {
            compressed: true,
            key: self.to_tweaked_public_key(None),
        }
    }

    fn hash_to_hash160(hash: &Self::Hash) -> hash160::Hash {
        hash.to_public_key().to_pubkeyhash()
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
            let pk = PubkeyExtended::from_str(pkstr).unwrap();

            assert_eq!(pk.to_pubkeyhash(), pk);
            assert_eq!(
                pk.to_public_key(),
                pk.as_descriptor_public_key().to_public_key()
            );

            assert_eq!(pk.has_tweak(), false);
            assert_eq!(pk.as_tweaking_factor(), None);
            assert_eq!(pk.to_tweaked_public_key(None), pk.to_public_key().key);
            assert_eq!(pk.into_tweaking_factor(), None);
        }

        for pkstr in tdpk {
            let pk = PubkeyExtended::from_str(&pkstr).unwrap();
            assert_eq!(pk.has_tweak(), true);

            assert_eq!(pk.to_pubkeyhash(), pk);
            assert_eq!(pk.to_public_key().key, pk.to_tweaked_public_key(None));

            assert_eq!(pk.as_tweaking_factor().unwrap(), &tweak);
            assert_ne!(
                pk.to_tweaked_public_key(None),
                pk.clone().into_descriptor_public_key().to_public_key().key
            );
            assert_eq!(pk.into_tweaking_factor().unwrap(), tweak);
        }
    }
}
