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
use core::ops::RangeInclusive;
use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::iter::FromIterator;
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::secp256k1;
use bitcoin::util::bip32::{
    self, ChainCode, ChildNumber, DerivationPath, Error, ExtendedPrivKey,
    ExtendedPubKey, Fingerprint,
};
use bitcoin::Network;

use crate::strict_encoding::{self, StrictDecode, StrictEncode};

/// Magical version bytes for xpub: bitcoin mainnet public key for P2PKH or P2SH
pub const VERSION_MAGIC_XPUB: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// Magical version bytes for xprv: bitcoin mainnet private key for P2PKH or
/// P2SH
pub const VERSION_MAGIC_XPRV: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Magical version bytes for ypub: bitcoin mainnet public key for P2WPKH in
/// P2SH
pub const VERSION_MAGIC_YPUB: [u8; 4] = [0x04, 0x9D, 0x7C, 0xB2];
/// Magical version bytes for yprv: bitcoin mainnet private key for P2WPKH in
/// P2SH
pub const VERSION_MAGIC_YPRV: [u8; 4] = [0x04, 0x9D, 0x78, 0x78];
/// Magical version bytes for zpub: bitcoin mainnet public key for P2WPKH
pub const VERSION_MAGIC_ZPUB: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
/// Magical version bytes for zprv: bitcoin mainnet private key for P2WPKH
pub const VERSION_MAGIC_ZPRV: [u8; 4] = [0x04, 0xB2, 0x43, 0x0C];
/// Magical version bytes for Ypub: bitcoin mainnet public key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_YPUB_MULTISIG: [u8; 4] = [0x02, 0x95, 0xb4, 0x3f];
/// Magical version bytes for Yprv: bitcoin mainnet private key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_YPRV_MULTISIG: [u8; 4] = [0x02, 0x95, 0xb0, 0x05];
/// Magical version bytes for Zpub: bitcoin mainnet public key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_ZPUB_MULTISIG: [u8; 4] = [0x02, 0xaa, 0x7e, 0xd3];
/// Magical version bytes for Zprv: bitcoin mainnet private key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_ZPRV_MULTISIG: [u8; 4] = [0x02, 0xaa, 0x7a, 0x99];

/// Magical version bytes for tpub: bitcoin testnet/regtest public key for
/// P2PKH or P2SH
pub const VERSION_MAGIC_TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
/// Magical version bytes for tprv: bitcoin testnet/regtest private key for
/// P2PKH or P2SH
pub const VERSION_MAGIC_TPRV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
/// Magical version bytes for upub: bitcoin testnet/regtest public key for
/// P2WPKH in P2SH
pub const VERSION_MAGIC_UPUB: [u8; 4] = [0x04, 0x4A, 0x52, 0x62];
/// Magical version bytes for uprv: bitcoin testnet/regtest private key for
/// P2WPKH in P2SH
pub const VERSION_MAGIC_UPRV: [u8; 4] = [0x04, 0x4A, 0x4E, 0x28];
/// Magical version bytes for vpub: bitcoin testnet/regtest public key for
/// P2WPKH
pub const VERSION_MAGIC_VPUB: [u8; 4] = [0x04, 0x5F, 0x1C, 0xF6];
/// Magical version bytes for vprv: bitcoin testnet/regtest private key for
/// P2WPKH
pub const VERSION_MAGIC_VPRV: [u8; 4] = [0x04, 0x5F, 0x18, 0xBC];
/// Magical version bytes for Upub: bitcoin testnet/regtest public key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_UPUB_MULTISIG: [u8; 4] = [0x02, 0x42, 0x89, 0xef];
/// Magical version bytes for Uprv: bitcoin testnet/regtest private key for
/// multi-signature P2WSH in P2SH
pub const VERSION_MAGIC_UPRV_MULTISIG: [u8; 4] = [0x02, 0x42, 0x85, 0xb5];
/// Magical version bytes for Zpub: bitcoin testnet/regtest public key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_VPUB_MULTISIG: [u8; 4] = [0x02, 0x57, 0x54, 0x83];
/// Magical version bytes for Zprv: bitcoin testnet/regtest private key for
/// multi-signature P2WSH
pub const VERSION_MAGIC_VPRV_MULTISIG: [u8; 4] = [0x02, 0x57, 0x50, 0x48];

/// Structure holding 4 verion bytes with magical numbers representing different
/// versions of extended public and private keys according to BIP-32.
/// Key version stores raw bytes without their check, interpretation or
/// verification; for these purposes special helpers structures implementing
/// [VersionResolver] are used.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct KeyVersion([u8; 4]);

/// Trait which must be implemented by helpers which do construction,
/// interpretation, verification and cross-conversion of extended public and
/// private key version magic bytes from [KeyVersion]
pub trait VersionResolver:
    Copy
    + Clone
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + ::std::hash::Hash
    + fmt::Debug
{
    /// Type that defines recognized network options
    type Network;

    /// Type that defines possible applications fro public and private keys
    /// (types of scriptPubkey descriptors in which they can be used)
    type Application;

    /// Constructor for [KeyVersion] with given network, application scope and
    /// key type (public or private)
    fn resolve(
        network: Self::Network,
        applicable_for: Self::Application,
        is_priv: bool,
    ) -> KeyVersion;

    /// Detects whether provided version corresponds to an extended public key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn is_pub(_: &KeyVersion) -> Option<bool> {
        return None;
    }

    /// Detects whether provided version corresponds to an extended private key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn is_prv(_: &KeyVersion) -> Option<bool> {
        return None;
    }

    /// Detects network used by the provided key version bytes.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn network(_: &KeyVersion) -> Option<Self::Network> {
        return None;
    }

    /// Detects application scope defined by the provided key version bytes.
    /// Application scope is a types of scriptPubkey descriptors in which given
    /// extended public/private keys can be used.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn application(_: &KeyVersion) -> Option<Self::Application> {
        return None;
    }

    /// Returns BIP 32 derivation path for the provided key version.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    fn derivation_path(_: &KeyVersion) -> Option<DerivationPath> {
        return None;
    }

    /// Converts version into version corresponding to an extended public key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    fn make_pub(_: &KeyVersion) -> Option<KeyVersion> {
        return None;
    }

    /// Converts version into version corresponding to an extended private key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    fn make_prv(_: &KeyVersion) -> Option<KeyVersion> {
        return None;
    }
}

impl KeyVersion {
    /// Detects whether provided version corresponds to an extended public key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn is_pub<R: VersionResolver>(&self) -> Option<bool> {
        R::is_pub(&self)
    }

    /// Detects whether provided version corresponds to an extended private key.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn is_prv<R: VersionResolver>(&self) -> Option<bool> {
        R::is_prv(&self)
    }

    /// Detects network used by the provided key version bytes.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn network<R: VersionResolver>(&self) -> Option<R::Network> {
        R::network(&self)
    }

    /// Detects application scope defined by the provided key version bytes.
    /// Application scope is a types of scriptPubkey descriptors in which given
    /// extended public/private keys can be used.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn application<R: VersionResolver>(&self) -> Option<R::Application> {
        R::application(&self)
    }

    /// Returns BIP 32 derivation path for the provided key version.
    /// Returns `None` if the version is not recognized/unknown to the resolver.
    pub fn derivation_path<R: VersionResolver>(
        &self,
    ) -> Option<DerivationPath> {
        R::derivation_path(&self)
    }

    /// Converts version into version corresponding to an extended public key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    pub fn try_to_pub<R: VersionResolver>(&self) -> Option<KeyVersion> {
        R::make_pub(&self)
    }

    /// Converts version into version corresponding to an extended private key.
    /// Returns `None` if the resolver does not know how to perform conversion.
    pub fn try_to_prv<R: VersionResolver>(&self) -> Option<KeyVersion> {
        R::make_prv(&self)
    }
}

/// Default resolver knowing native [bitcoin::network::constants::Network]
/// and BIP 32 and SLIP 132-defined key applications with [KeyApplications]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DefaultResolver;

/// SLIP 132-defined key applications defining types of scriptPubkey descriptors
/// in which they can be used
#[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum KeyApplication {
    /// xprv/xpub: keys that can be used for P2PKH and multisig P2SH
    /// scriptPubkey descriptors.
    Legacy,
    /// zprv/zpub: keys that can be used for P2WPKH scriptPubkey descriptors
    SegWitV0Singlesig,
    /// yprv/ypub: keys that can be used for P2WPKH-in-P2SH scriptPubkey
    /// descriptors
    SegWitLegacySinglesig,
    /// Zprv/Zpub: keys that can be used for multisig P2WSH scriptPubkey
    /// descriptors
    SegWitV0Miltisig,
    /// Yprv/Ypub: keys that can be used for multisig P2WSH-in-P2SH
    /// scriptPubkey descriptors
    SegWitLegacyMultisig,
}

impl StrictEncode for KeyApplication {
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        let val = match self {
            KeyApplication::Legacy => 0u8,
            KeyApplication::SegWitLegacySinglesig => 1u8,
            KeyApplication::SegWitLegacyMultisig => 2u8,
            KeyApplication::SegWitV0Singlesig => 3u8,
            KeyApplication::SegWitV0Miltisig => 4u8,
        };
        val.strict_encode(e)
    }
}

impl StrictDecode for KeyApplication {
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        Ok(match u8::strict_decode(d)? {
            0 => KeyApplication::Legacy,
            1 => KeyApplication::SegWitLegacySinglesig,
            2 => KeyApplication::SegWitLegacyMultisig,
            3 => KeyApplication::SegWitV0Singlesig,
            4 => KeyApplication::SegWitV0Miltisig,
            other => Err(strict_encoding::Error::EnumValueNotKnown(
                s!("KeyApplication"),
                other,
            ))?,
        })
    }
}

/// Error for an unknown enum representation; either string or numeric
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display(Debug)]
pub struct EnumReprError;

impl FromStr for KeyApplication {
    type Err = EnumReprError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "pkh" => KeyApplication::Legacy,
            "sh" => KeyApplication::Legacy,
            "wpkh" => KeyApplication::SegWitV0Singlesig,
            "wsh" => KeyApplication::SegWitV0Miltisig,
            "wpkh-sh" => KeyApplication::SegWitLegacySinglesig,
            "wsh-sh" => KeyApplication::SegWitLegacyMultisig,
            _ => Err(EnumReprError)?,
        })
    }
}

impl KeyVersion {
    /// Tries to construct [KeyVersion] object from a byte slice. If byte slice
    /// length is not equal to 4, returns `None`
    pub fn from_slice(version_slice: &[u8]) -> Option<KeyVersion> {
        if version_slice.len() != 4 {
            return None;
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(version_slice);
        Some(KeyVersion::from_bytes(bytes))
    }

    /// Constructs [KeyVersion] from a fixed 4 bytes values
    pub fn from_bytes(version_bytes: [u8; 4]) -> KeyVersion {
        KeyVersion(version_bytes)
    }

    /// Constructs [KeyVersion from a `u32`-representation of the version
    /// bytes (the representation must be in bing endian format)
    pub fn from_u32(version: u32) -> KeyVersion {
        KeyVersion(version.to_be_bytes())
    }

    /// Converts version bytes into `u32` representation in big endian format
    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// Returns slice representing internal version bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns internal representation of version bytes
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Constructs 4-byte array containing version byte values
    pub fn to_bytes(&self) -> [u8; 4] {
        self.0
    }

    /// Converts into 4-byte array containing version byte values
    pub fn into_bytes(self) -> [u8; 4] {
        self.0
    }
}

impl VersionResolver for DefaultResolver {
    type Network = Network;
    type Application = KeyApplication;

    fn resolve(
        network: Self::Network,
        applicable_for: Self::Application,
        is_priv: bool,
    ) -> KeyVersion {
        match (network, applicable_for, is_priv) {
            (Network::Bitcoin, KeyApplication::Legacy, false) => {
                KeyVersion(VERSION_MAGIC_XPUB)
            }
            (Network::Bitcoin, KeyApplication::Legacy, true) => {
                KeyVersion(VERSION_MAGIC_XPRV)
            }
            (
                Network::Bitcoin,
                KeyApplication::SegWitLegacySinglesig,
                false,
            ) => KeyVersion(VERSION_MAGIC_YPUB),
            (Network::Bitcoin, KeyApplication::SegWitLegacySinglesig, true) => {
                KeyVersion(VERSION_MAGIC_YPRV)
            }
            (Network::Bitcoin, KeyApplication::SegWitV0Singlesig, false) => {
                KeyVersion(VERSION_MAGIC_ZPUB)
            }
            (Network::Bitcoin, KeyApplication::SegWitV0Singlesig, true) => {
                KeyVersion(VERSION_MAGIC_ZPRV)
            }
            (Network::Bitcoin, KeyApplication::SegWitLegacyMultisig, false) => {
                KeyVersion(VERSION_MAGIC_YPUB_MULTISIG)
            }
            (Network::Bitcoin, KeyApplication::SegWitLegacyMultisig, true) => {
                KeyVersion(VERSION_MAGIC_YPRV_MULTISIG)
            }
            (Network::Bitcoin, KeyApplication::SegWitV0Miltisig, false) => {
                KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG)
            }
            (Network::Bitcoin, KeyApplication::SegWitV0Miltisig, true) => {
                KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG)
            }
            (_, KeyApplication::Legacy, false) => {
                KeyVersion(VERSION_MAGIC_TPUB)
            }
            (_, KeyApplication::Legacy, true) => KeyVersion(VERSION_MAGIC_TPRV),
            (_, KeyApplication::SegWitLegacySinglesig, false) => {
                KeyVersion(VERSION_MAGIC_UPUB)
            }
            (_, KeyApplication::SegWitLegacySinglesig, true) => {
                KeyVersion(VERSION_MAGIC_UPRV)
            }
            (_, KeyApplication::SegWitV0Singlesig, false) => {
                KeyVersion(VERSION_MAGIC_VPUB)
            }
            (_, KeyApplication::SegWitV0Singlesig, true) => {
                KeyVersion(VERSION_MAGIC_VPRV)
            }
            (_, KeyApplication::SegWitLegacyMultisig, false) => {
                KeyVersion(VERSION_MAGIC_UPUB_MULTISIG)
            }
            (_, KeyApplication::SegWitLegacyMultisig, true) => {
                KeyVersion(VERSION_MAGIC_UPRV_MULTISIG)
            }
            (_, KeyApplication::SegWitV0Miltisig, false) => {
                KeyVersion(VERSION_MAGIC_VPUB_MULTISIG)
            }
            (_, KeyApplication::SegWitV0Miltisig, true) => {
                KeyVersion(VERSION_MAGIC_VPRV_MULTISIG)
            }
        }
    }

    fn is_pub(kv: &KeyVersion) -> Option<bool> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG => Some(true),
            &VERSION_MAGIC_XPRV
            | &VERSION_MAGIC_YPRV
            | &VERSION_MAGIC_ZPRV
            | &VERSION_MAGIC_TPRV
            | &VERSION_MAGIC_UPRV
            | &VERSION_MAGIC_VPRV
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG => Some(false),
            _ => None,
        }
    }

    fn is_prv(kv: &KeyVersion) -> Option<bool> {
        DefaultResolver::is_pub(kv).map(|v| !v)
    }

    fn network(kv: &KeyVersion) -> Option<Self::Network> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPRV
            | &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_YPRV
            | &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_ZPRV
            | &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_ZPUB_MULTISIG => Some(Network::Bitcoin),
            &VERSION_MAGIC_TPRV
            | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_UPRV
            | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_VPRV
            | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_UPRV_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG => Some(Network::Testnet),
            _ => None,
        }
    }

    fn application(kv: &KeyVersion) -> Option<Self::Application> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB | &VERSION_MAGIC_XPRV | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_TPRV => Some(KeyApplication::Legacy),
            &VERSION_MAGIC_YPUB | &VERSION_MAGIC_YPRV | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_UPRV => {
                Some(KeyApplication::SegWitLegacySinglesig)
            }
            &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG => {
                Some(KeyApplication::SegWitLegacyMultisig)
            }
            &VERSION_MAGIC_ZPUB | &VERSION_MAGIC_ZPRV | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_VPRV => Some(KeyApplication::SegWitV0Singlesig),
            &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG => {
                Some(KeyApplication::SegWitV0Miltisig)
            }
            _ => None,
        }
    }

    fn derivation_path(kv: &KeyVersion) -> Option<DerivationPath> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB | &VERSION_MAGIC_XPRV => {
                Some(DerivationPath::from(vec![
                    ChildNumber::Hardened { index: 44 },
                    ChildNumber::Hardened { index: 0 },
                ]))
            }
            &VERSION_MAGIC_TPUB | &VERSION_MAGIC_TPRV => {
                Some(DerivationPath::from(vec![
                    ChildNumber::Hardened { index: 44 },
                    ChildNumber::Hardened { index: 1 },
                ]))
            }
            &VERSION_MAGIC_YPUB | &VERSION_MAGIC_YPRV => {
                Some(DerivationPath::from(vec![
                    ChildNumber::Hardened { index: 49 },
                    ChildNumber::Hardened { index: 0 },
                ]))
            }
            &VERSION_MAGIC_UPUB | &VERSION_MAGIC_UPRV => {
                Some(DerivationPath::from(vec![
                    ChildNumber::Hardened { index: 49 },
                    ChildNumber::Hardened { index: 1 },
                ]))
            }
            &VERSION_MAGIC_ZPUB | &VERSION_MAGIC_ZPRV => {
                Some(DerivationPath::from(vec![
                    ChildNumber::Hardened { index: 84 },
                    ChildNumber::Hardened { index: 0 },
                ]))
            }
            &VERSION_MAGIC_VPUB | &VERSION_MAGIC_VPRV => {
                Some(DerivationPath::from(vec![
                    ChildNumber::Hardened { index: 84 },
                    ChildNumber::Hardened { index: 1 },
                ]))
            }
            _ => None,
        }
    }

    fn make_pub(kv: &KeyVersion) -> Option<KeyVersion> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPRV => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_XPUB))
            }
            &VERSION_MAGIC_YPRV => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_YPUB))
            }
            &VERSION_MAGIC_ZPRV => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPUB))
            }
            &VERSION_MAGIC_TPRV => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_TPUB))
            }
            &VERSION_MAGIC_UPRV => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_UPUB))
            }
            &VERSION_MAGIC_VPRV => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_VPUB))
            }
            &VERSION_MAGIC_YPRV_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_YPUB_MULTISIG))
            }
            &VERSION_MAGIC_ZPRV_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPUB_MULTISIG))
            }
            &VERSION_MAGIC_UPRV_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_UPUB_MULTISIG))
            }
            &VERSION_MAGIC_VPRV_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_VPUB_MULTISIG))
            }
            &VERSION_MAGIC_XPUB
            | &VERSION_MAGIC_YPUB
            | &VERSION_MAGIC_ZPUB
            | &VERSION_MAGIC_TPUB
            | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG => Some(kv.clone()),
            _ => None,
        }
    }

    fn make_prv(kv: &KeyVersion) -> Option<KeyVersion> {
        match kv.as_bytes() {
            &VERSION_MAGIC_XPUB => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_XPRV))
            }
            &VERSION_MAGIC_YPUB => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_YPRV))
            }
            &VERSION_MAGIC_ZPUB => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPRV))
            }
            &VERSION_MAGIC_TPUB => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_TPRV))
            }
            &VERSION_MAGIC_UPUB => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_UPRV))
            }
            &VERSION_MAGIC_VPUB => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_VPRV))
            }
            &VERSION_MAGIC_YPUB_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_YPRV_MULTISIG))
            }
            &VERSION_MAGIC_ZPUB_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_ZPRV_MULTISIG))
            }
            &VERSION_MAGIC_UPUB_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_UPRV_MULTISIG))
            }
            &VERSION_MAGIC_VPUB_MULTISIG => {
                Some(KeyVersion::from_bytes(VERSION_MAGIC_VPRV_MULTISIG))
            }
            &VERSION_MAGIC_XPRV
            | &VERSION_MAGIC_YPRV
            | &VERSION_MAGIC_ZPRV
            | &VERSION_MAGIC_TPRV
            | &VERSION_MAGIC_UPRV
            | &VERSION_MAGIC_VPRV
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG => Some(kv.clone()),
            _ => None,
        }
    }
}

/// Extension trait allowing to add more methods to [`DerivationPath`] type
pub trait DerivationPathMaster {
    fn master() -> Self;
    fn is_master(&self) -> bool;
}

impl DerivationPathMaster for DerivationPath {
    /// Returns derivation path for a master key (i.e. empty derivation path)
    fn master() -> DerivationPath {
        vec![].into()
    }

    /// Returns whether derivation path represents master key (i.e. it's length
    /// is empty). True for `m` path.
    fn is_master(&self) -> bool {
        self.into_iter().len() == 0
    }
}

/// Trait that allows possibly failable conversion from a type into a
/// derivation path
pub trait IntoDerivationPath {
    /// Converts a given type into a [`DerivationPath`] with possible error
    fn into_derivation_path(self) -> Result<DerivationPath, Error>;
}

impl IntoDerivationPath for DerivationPath {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        Ok(self)
    }
}

impl IntoDerivationPath for Vec<ChildNumber> {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        Ok(self.into())
    }
}

impl<'a> IntoDerivationPath for &'a [ChildNumber] {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        Ok(self.into())
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

pub trait HardenedNormalSplit {
    fn hardened_normal_split(&self) -> (DerivationPath, Vec<u32>);
}

impl HardenedNormalSplit for DerivationPath {
    fn hardened_normal_split(&self) -> (DerivationPath, Vec<u32>) {
        let mut terminal_path = vec![];
        let branch_path = self
            .into_iter()
            .rev()
            .by_ref()
            .skip_while(|child| {
                if let ChildNumber::Normal { index } = child {
                    terminal_path.push(index);
                    true
                } else {
                    false
                }
            })
            .cloned()
            .collect::<DerivationPath>();
        let branch_path = branch_path.into_iter().rev().cloned().collect();
        let terminal_path = terminal_path.into_iter().rev().cloned().collect();
        (branch_path, terminal_path)
    }
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
// master_xpub/branch_path=branch_xpub/terminal_path/index_ranges
pub struct DerivationComponents {
    pub master_xpub: ExtendedPubKey,
    pub branch_path: DerivationPath,
    pub branch_xpub: ExtendedPubKey,
    pub terminal_path: Vec<u32>,
    pub index_ranges: Option<Vec<DerivationRange>>,
}

impl DerivationComponents {
    pub fn count(&self) -> u32 {
        match self.index_ranges {
            None => u32::MAX,
            Some(ref ranges) => {
                ranges.iter().fold(0u32, |sum, range| sum + range.count())
            }
        }
    }

    pub fn derivation_path(&self) -> DerivationPath {
        self.branch_path.extend(self.terminal_path())
    }

    pub fn terminal_path(&self) -> DerivationPath {
        DerivationPath::from_iter(
            self.terminal_path
                .iter()
                .map(|i| ChildNumber::Normal { index: *i }),
        )
    }

    pub fn index_ranges_string(&self) -> String {
        self.index_ranges
            .as_ref()
            .map(|ranges| {
                ranges
                    .iter()
                    .map(DerivationRange::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default()
    }

    pub fn child(&self, child: u32) -> ExtendedPubKey {
        let derivation = self
            .terminal_path()
            .into_child(ChildNumber::Normal { index: child });
        self.branch_xpub
            .derive_pub(&crate::SECP256K1, &derivation)
            .expect("Non-hardened derivation does not fail")
    }

    pub fn public_key(&self, index: u32) -> bitcoin::PublicKey {
        self.child(index).public_key
    }
}

impl Display for DerivationComponents {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}]{}/",
            self.master_xpub.fingerprint(),
            self.derivation_path()
                .to_string()
                .strip_prefix("m")
                .unwrap_or(&self.derivation_path().to_string())
        )?;
        if let Some(_) = self.index_ranges {
            f.write_str(&self.index_ranges_string())
        } else {
            f.write_str("*")
        }
    }
}

#[derive(Wrapper, Clone, PartialEq, Eq, Hash, Debug, From)]
pub struct DerivationRange(RangeInclusive<u32>);

impl PartialOrd for DerivationRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.start().partial_cmp(&other.start()) {
            Some(Ordering::Equal) => self.end().partial_cmp(&other.end()),
            other => other,
        }
    }
}

impl Ord for DerivationRange {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.start().cmp(&other.start()) {
            Ordering::Equal => self.end().cmp(&other.end()),
            other => other,
        }
    }
}

impl DerivationRange {
    pub fn count(&self) -> u32 {
        let inner = self.as_inner();
        inner.end() - inner.start() + 1
    }

    pub fn start(&self) -> u32 {
        *self.as_inner().start()
    }

    pub fn end(&self) -> u32 {
        *self.as_inner().end()
    }
}

impl Display for DerivationRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let inner = self.as_inner();
        if inner.start() == inner.end() {
            write!(f, "{}", inner.start())
        } else {
            write!(f, "{}-{}", inner.start(), inner.end())
        }
    }
}

impl StrictEncode for DerivationRange {
    fn strict_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, strict_encoding::Error> {
        Ok(strict_encode_list!(e; self.start(), self.end()))
    }
}

impl StrictDecode for DerivationRange {
    fn strict_decode<D: io::Read>(
        mut d: D,
    ) -> Result<Self, strict_encoding::Error> {
        Ok(Self::from_inner(RangeInclusive::new(
            u32::strict_decode(&mut d)?,
            u32::strict_decode(&mut d)?,
        )))
    }
}
