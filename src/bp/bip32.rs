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

use core::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::iter::FromIterator;
use std::str::FromStr;

use bitcoin::secp256k1;
use bitcoin::util::bip32::{
    self, ChainCode, ChildNumber, DerivationPath, Error, ExtendedPrivKey,
    ExtendedPubKey, Fingerprint,
};

/// Trait that allows possibly failable conversion from a type into a
/// derivation path
pub trait IntoDerivationPath {
    /// Convers a given type into a [`DerivationPath`] with possible error
    fn into_derivation_path(self) -> Result<DerivationPath, Error>;
}

impl IntoDerivationPath for DerivationPath {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        Ok(self)
    }
}

impl IntoDerivationPath for String {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        self.parse()
    }
}

impl<'a> IntoDerivationPath for &'a str {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        self.parse()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum DerivationStep {
    Normal(u32),
    Hardened(u32),
    WildcardNormal,
    WildcardHardened,
}

impl PartialOrd for DerivationStep {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        unimplemented!()
    }
}

impl Ord for DerivationStep {
    fn cmp(&self, other: &Self) -> Ordering {
        unimplemented!()
    }
}

impl Display for DerivationStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        unimplemented!()
    }
}

impl FromStr for DerivationStep {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        unimplemented!()
    }
}

impl From<u32> for DerivationStep {
    fn from(_: u32) -> Self {
        unimplemented!()
    }
}

impl From<ChildNumber> for DerivationStep {
    fn from(_: ChildNumber) -> Self {
        unimplemented!()
    }
}

impl TryFrom<DerivationStep> for ChildNumber {
    type Error = ();

    fn try_from(value: DerivationStep) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl Default for DerivationStep {
    fn default() -> Self {
        unimplemented!()
    }
}

pub trait IntoDerivationTemplate {
    fn into_derivation_template() -> DerivationTemplate {
        unimplemented!()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub struct DerivationTemplate(Vec<DerivationStep>);

impl From<DerivationPath> for DerivationTemplate {
    fn from(_: DerivationPath) -> Self {
        unimplemented!()
    }
}

impl FromIterator<ChildNumber> for DerivationTemplate {
    fn from_iter<T: IntoIterator<Item = ChildNumber>>(iter: T) -> Self {
        unimplemented!()
    }
}

impl FromIterator<DerivationStep> for DerivationTemplate {
    fn from_iter<T: IntoIterator<Item = DerivationStep>>(iter: T) -> Self {
        unimplemented!()
    }
}

impl TryFrom<String> for DerivationTemplate {
    type Error = bip32::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl TryFrom<&str> for DerivationTemplate {
    type Error = bip32::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl FromStr for DerivationTemplate {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        unimplemented!()
    }
}

impl Display for DerivationTemplate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        unimplemented!()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub struct DerivationInfo {
    pub fingerprint: Fingerprint,
    pub derivation: DerivationTemplate,
}

pub trait Encode {
    fn encode(&self) -> [u8; 78];
}

pub trait Decode: Sized {
    fn decode(data: &[u8]) -> Result<Self, bitcoin::util::bip32::Error>;
}

impl Encode for ExtendedPrivKey {
    /// Extended private key binary encoding according to BIP 32
    fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(
            &match self.network {
                bitcoin::Network::Bitcoin => [0x04, 0x88, 0xAD, 0xE4],
                bitcoin::Network::Testnet | bitcoin::Network::Regtest => {
                    [0x04, 0x35, 0x83, 0x94]
                }
            }[..],
        );
        ret[4] = self.depth as u8;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&self.private_key[..]);
        ret
    }
}

impl Encode for ExtendedPubKey {
    /// Extended public key binary encoding according to BIP 32
    fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(
            &match self.network {
                bitcoin::Network::Bitcoin => [0x04u8, 0x88, 0xB2, 0x1E],
                bitcoin::Network::Testnet | bitcoin::Network::Regtest => {
                    [0x04u8, 0x35, 0x87, 0xCF]
                }
            }[..],
        );
        ret[4] = self.depth as u8;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45..78].copy_from_slice(&self.public_key.key.serialize()[..]);
        ret
    }
}

impl Decode for ExtendedPrivKey {
    /// Decoding extended private key from binary data according to BIP 32
    fn decode(
        data: &[u8],
    ) -> Result<ExtendedPrivKey, bitcoin::util::bip32::Error> {
        if data.len() != 78 {
            return Err(bitcoin::util::bip32::Error::InvalidChildNumberFormat);
        }

        let mut slice: [u8; 4] = [0u8; 4];
        slice.copy_from_slice(&data[9..13]);
        let cn_int: u32 = u32::from_be_bytes(slice);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let network = if data[0..4] == [0x04u8, 0x88, 0xAD, 0xE4] {
            bitcoin::Network::Bitcoin
        } else if data[0..4] == [0x04u8, 0x35, 0x83, 0x94] {
            bitcoin::Network::Testnet
        } else {
            return Err(
                bitcoin::util::bip32::Error::CannotDeriveFromHardenedKey,
            );
        };

        Ok(ExtendedPrivKey {
            network,
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number,
            chain_code: ChainCode::from(&data[13..45]),
            private_key: bitcoin::PrivateKey {
                compressed: true,
                network,
                key: secp256k1::SecretKey::from_slice(&data[46..78]).map_err(
                    |e| {
                        bitcoin::util::bip32::Error::CannotDeriveFromHardenedKey
                    },
                )?,
            },
        })
    }
}

impl Decode for ExtendedPubKey {
    /// Decoding extended public key from binary data according to BIP 32
    fn decode(
        data: &[u8],
    ) -> Result<ExtendedPubKey, bitcoin::util::bip32::Error> {
        if data.len() != 78 {
            return Err(bitcoin::util::bip32::Error::InvalidChildNumberFormat);
        }

        let mut slice: [u8; 4] = [0u8; 4];
        slice.copy_from_slice(&data[9..13]);
        let cn_int: u32 = u32::from_be_bytes(slice);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        Ok(ExtendedPubKey {
            network: if data[0..4] == [0x04u8, 0x88, 0xB2, 0x1E] {
                bitcoin::Network::Bitcoin
            } else if data[0..4] == [0x04u8, 0x35, 0x87, 0xCF] {
                bitcoin::Network::Testnet
            } else {
                return Err(
                    bitcoin::util::bip32::Error::CannotDeriveFromHardenedKey,
                );
            },
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number,
            chain_code: ChainCode::from(&data[13..45]),
            public_key: bitcoin::PublicKey::from_slice(&data[45..78]).map_err(
                |e| bitcoin::util::bip32::Error::CannotDeriveFromHardenedKey,
            )?,
        })
    }
}
