// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2021 by
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

use std::fmt::Debug;
use std::str::FromStr;

use bitcoin::util::base58;
use bitcoin::util::bip32::{
    self, ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey,
};
use bitcoin::Network;

use crate::bp::bip32::Decode;

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

/// Extended public and private key processing errors
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// Error in BASE58 key encoding
    #[from(base58::Error)]
    Base58,

    /// A pk->pk derivation was attempted on a hardened key
    CannotDeriveFromHardenedKey,

    /// A child number was provided ({0}) that was out of range
    InvalidChildNumber(u32),

    /// Invalid child number format.
    InvalidChildNumberFormat,

    /// Invalid derivation path format.
    InvalidDerivationPathFormat,

    /// Unrecognized or unsupported extended key prefix (please check SLIP 32
    /// for possible values)
    UnknownSlip32Prefix,

    /// Failure in tust bitcoin library
    InteralFailure,
}

impl From<bip32::Error> for Error {
    fn from(err: bip32::Error) -> Self {
        match err {
            bip32::Error::CannotDeriveFromHardenedKey => {
                Error::CannotDeriveFromHardenedKey
            }
            bip32::Error::InvalidChildNumber(no) => {
                Error::InvalidChildNumber(no)
            }
            bip32::Error::InvalidChildNumberFormat => {
                Error::InvalidChildNumberFormat
            }
            bip32::Error::InvalidDerivationPathFormat => {
                Error::InvalidDerivationPathFormat
            }
            bip32::Error::Ecdsa(_) | bip32::Error::RngError(_) => {
                Error::InteralFailure
            }
        }
    }
}

/// Structure holding 4 version bytes with magical numbers representing
/// different versions of extended public and private keys according to BIP-32.
/// Key version stores raw bytes without their check, interpretation or
/// verification; for these purposes special helpers structures implementing
/// [`VersionResolver`] are used.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct KeyVersion([u8; 4]);

/// Trait which must be implemented by helpers which do construction,
/// interpretation, verification and cross-conversion of extended public and
/// private key version magic bytes from [`KeyVersion`]
pub trait VersionResolver:
    Copy + Clone + PartialEq + Eq + PartialOrd + Ord + std::hash::Hash + Debug
{
    /// Type that defines recognized network options
    type Network;

    /// Type that defines possible applications fro public and private keys
    /// (types of scriptPubkey descriptors in which they can be used)
    type Application;

    /// Constructor for [`KeyVersion`] with given network, application scope and
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

/// Default resolver knowing native [`bitcoin::network::constants::Network`]
/// and BIP 32 and SLIP 132-defined key applications with [`KeyApplications`]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DefaultResolver;

/// SLIP 132-defined key applications defining types of scriptPubkey descriptors
/// in which they can be used
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Copy, Clone, PartialEq, Eq, Debug, Display, StrictEncode, StrictDecode,
)]
#[lnpbp_crate(crate)]
#[non_exhaustive]
pub enum KeyApplication {
    /// xprv/xpub: keys that can be used for P2PKH and multisig P2SH
    /// scriptPubkey descriptors.
    #[display("hashed")]
    #[cfg_attr(feature = "serde", serde(rename = "hashed"))]
    Hashed,

    /// zprv/zpub: keys that can be used for P2WPKH scriptPubkey descriptors
    #[display("segwit")]
    #[cfg_attr(feature = "serde", serde(rename = "segwit"))]
    SegWit,

    /// Zprv/Zpub: keys that can be used for multisig P2WSH scriptPubkey
    /// descriptors
    #[display("segwit-multisig")]
    #[cfg_attr(feature = "serde", serde(rename = "segwit-multisig"))]
    SegWitMiltisig,

    /// yprv/ypub: keys that can be used for P2WPKH-in-P2SH scriptPubkey
    /// descriptors
    #[display("nested")]
    #[cfg_attr(feature = "serde", serde(rename = "nested"))]
    Nested,

    /// Yprv/Ypub: keys that can be used for multisig P2WSH-in-P2SH
    /// scriptPubkey descriptors
    #[display("nested-multisig")]
    #[cfg_attr(feature = "serde", serde(rename = "nested-multisig"))]
    NestedMultisig,
}

/// Unknown string representation of [`KeyApplication`] enum
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display(doc_comments)]
pub struct UnknownKeyApplicationError;

impl FromStr for KeyApplication {
    type Err = UnknownKeyApplicationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "pkh" => KeyApplication::Hashed,
            "sh" => KeyApplication::Hashed,
            "wpkh" => KeyApplication::SegWit,
            "wsh" => KeyApplication::SegWitMiltisig,
            "wpkh-sh" => KeyApplication::Nested,
            "wsh-sh" => KeyApplication::NestedMultisig,
            _ => Err(UnknownKeyApplicationError)?,
        })
    }
}

impl KeyVersion {
    /// Tries to construct [`KeyVersion`] object from a byte slice. If byte
    /// slice length is not equal to 4, returns `None`
    pub fn from_slice(version_slice: &[u8]) -> Option<KeyVersion> {
        if version_slice.len() != 4 {
            return None;
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(version_slice);
        Some(KeyVersion::from_bytes(bytes))
    }

    /// Constructs [`KeyVersion`] from a fixed 4 bytes values
    pub fn from_bytes(version_bytes: [u8; 4]) -> KeyVersion {
        KeyVersion(version_bytes)
    }

    /// Constructs [`KeyVersion`] from a `u32`-representation of the version
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
            (Network::Bitcoin, KeyApplication::Hashed, false) => {
                KeyVersion(VERSION_MAGIC_XPUB)
            }
            (Network::Bitcoin, KeyApplication::Hashed, true) => {
                KeyVersion(VERSION_MAGIC_XPRV)
            }
            (Network::Bitcoin, KeyApplication::Nested, false) => {
                KeyVersion(VERSION_MAGIC_YPUB)
            }
            (Network::Bitcoin, KeyApplication::Nested, true) => {
                KeyVersion(VERSION_MAGIC_YPRV)
            }
            (Network::Bitcoin, KeyApplication::SegWit, false) => {
                KeyVersion(VERSION_MAGIC_ZPUB)
            }
            (Network::Bitcoin, KeyApplication::SegWit, true) => {
                KeyVersion(VERSION_MAGIC_ZPRV)
            }
            (Network::Bitcoin, KeyApplication::NestedMultisig, false) => {
                KeyVersion(VERSION_MAGIC_YPUB_MULTISIG)
            }
            (Network::Bitcoin, KeyApplication::NestedMultisig, true) => {
                KeyVersion(VERSION_MAGIC_YPRV_MULTISIG)
            }
            (Network::Bitcoin, KeyApplication::SegWitMiltisig, false) => {
                KeyVersion(VERSION_MAGIC_ZPUB_MULTISIG)
            }
            (Network::Bitcoin, KeyApplication::SegWitMiltisig, true) => {
                KeyVersion(VERSION_MAGIC_ZPRV_MULTISIG)
            }
            (_, KeyApplication::Hashed, false) => {
                KeyVersion(VERSION_MAGIC_TPUB)
            }
            (_, KeyApplication::Hashed, true) => KeyVersion(VERSION_MAGIC_TPRV),
            (_, KeyApplication::Nested, false) => {
                KeyVersion(VERSION_MAGIC_UPUB)
            }
            (_, KeyApplication::Nested, true) => KeyVersion(VERSION_MAGIC_UPRV),
            (_, KeyApplication::SegWit, false) => {
                KeyVersion(VERSION_MAGIC_VPUB)
            }
            (_, KeyApplication::SegWit, true) => KeyVersion(VERSION_MAGIC_VPRV),
            (_, KeyApplication::NestedMultisig, false) => {
                KeyVersion(VERSION_MAGIC_UPUB_MULTISIG)
            }
            (_, KeyApplication::NestedMultisig, true) => {
                KeyVersion(VERSION_MAGIC_UPRV_MULTISIG)
            }
            (_, KeyApplication::SegWitMiltisig, false) => {
                KeyVersion(VERSION_MAGIC_VPUB_MULTISIG)
            }
            (_, KeyApplication::SegWitMiltisig, true) => {
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
            | &VERSION_MAGIC_TPRV => Some(KeyApplication::Hashed),
            &VERSION_MAGIC_YPUB | &VERSION_MAGIC_YPRV | &VERSION_MAGIC_UPUB
            | &VERSION_MAGIC_UPRV => Some(KeyApplication::Nested),
            &VERSION_MAGIC_YPUB_MULTISIG
            | &VERSION_MAGIC_YPRV_MULTISIG
            | &VERSION_MAGIC_UPUB_MULTISIG
            | &VERSION_MAGIC_UPRV_MULTISIG => {
                Some(KeyApplication::NestedMultisig)
            }
            &VERSION_MAGIC_ZPUB | &VERSION_MAGIC_ZPRV | &VERSION_MAGIC_VPUB
            | &VERSION_MAGIC_VPRV => Some(KeyApplication::SegWit),
            &VERSION_MAGIC_ZPUB_MULTISIG
            | &VERSION_MAGIC_ZPRV_MULTISIG
            | &VERSION_MAGIC_VPUB_MULTISIG
            | &VERSION_MAGIC_VPRV_MULTISIG => {
                Some(KeyApplication::SegWitMiltisig)
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

pub trait FromSlip32 {
    fn from_slip32_str(s: &str) -> Result<Self, Error>
    where
        Self: Sized;
}

impl FromSlip32 for ExtendedPubKey {
    fn from_slip32_str(s: &str) -> Result<Self, Error> {
        let mut data = base58::from_check(s)?;

        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&data[0..4]);
        let slice = match prefix {
            VERSION_MAGIC_XPUB
            | VERSION_MAGIC_YPUB
            | VERSION_MAGIC_ZPUB
            | VERSION_MAGIC_YPUB_MULTISIG
            | VERSION_MAGIC_ZPUB_MULTISIG => VERSION_MAGIC_XPUB,

            VERSION_MAGIC_TPUB
            | VERSION_MAGIC_UPUB
            | VERSION_MAGIC_VPUB
            | VERSION_MAGIC_UPUB_MULTISIG
            | VERSION_MAGIC_VPUB_MULTISIG => VERSION_MAGIC_TPUB,

            _ => Err(Error::UnknownSlip32Prefix)?,
        };
        data[0..4].copy_from_slice(&slice);

        let xpub = ExtendedPubKey::decode(&data)?;

        Ok(xpub)
    }
}

impl FromSlip32 for ExtendedPrivKey {
    fn from_slip32_str(s: &str) -> Result<Self, Error> {
        let mut data = base58::from_check(s)?;

        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&data[0..4]);
        let slice = match prefix {
            VERSION_MAGIC_XPRV
            | VERSION_MAGIC_YPRV
            | VERSION_MAGIC_ZPRV
            | VERSION_MAGIC_YPRV_MULTISIG
            | VERSION_MAGIC_ZPRV_MULTISIG => VERSION_MAGIC_XPRV,

            VERSION_MAGIC_TPRV
            | VERSION_MAGIC_UPRV
            | VERSION_MAGIC_VPRV
            | VERSION_MAGIC_UPRV_MULTISIG
            | VERSION_MAGIC_VPRV_MULTISIG => VERSION_MAGIC_TPRV,

            _ => Err(Error::UnknownSlip32Prefix)?,
        };
        data[0..4].copy_from_slice(&slice);

        let xprv = ExtendedPrivKey::decode(&data)?;

        Ok(xprv)
    }
}
