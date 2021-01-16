// LNP/BP Core Library implementing LNPBP specifications & standards
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

use std::cmp::Ordering;
use std::fmt::{Debug, Display};
use std::{convert::TryFrom, fmt, io, str::FromStr};

use bitcoin::hashes::hex::{self, FromHex, ToHex};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::BlockHash;

use crate::lightning_encoding;
use crate::strict_encoding::{
    self, strict_deserialize, strict_serialize, StrictDecode, StrictEncode,
};

/// P2P network magic number: prefix identifying network on which node operates
pub type P2pMagicNumber = u32;
/// Magic number prefixing Pubkey or Prvkey data according to BIP32 spec
pub type Bip32MagicNumber = u32;

// TODO: (new) Move constants to rust-bitcoin
/// Magic number used in P2P networking protocol by bitcoin mainnet
pub const P2P_MAGIC_MAINNET: P2pMagicNumber = 0xD9B4BEF9;
/// Magic number used in P2P networking protocol by bitcoin testnet v3
pub const P2P_MAGIC_TESTNET: P2pMagicNumber = 0x0709110B;
/// Magic number used in P2P networking protocol by bitcoin regtests
pub const P2P_MAGIC_REGTEST: P2pMagicNumber = 0xDAB5BFFA;
/// Magic number used in P2P networking protocol by bitcoin signet
pub const P2P_MAGIC_SIGNET: P2pMagicNumber = 0x40CF030A;

/// P2P network magic number: prefix identifying network on which node operates.
/// This enum defines known magic network numbers, plus adds support to
/// arbitrary unknown with [P2pNetworkId::Other] variant.
/// This enum differs from bitcoin::Network in its ability to support
/// non-standard and non-predefined networks
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[non_exhaustive]
#[repr(u32)]
pub enum P2pNetworkId {
    /// Bitcoin magic number for mainnet P2P communications
    Mainnet,

    /// Bitcoin magic number for testnet P2P communications
    Testnet,

    /// Bitcoin magic number for regtest P2P communications
    Regtest,

    /// Bitcoin magic number for signet P2P communications
    Signet,

    /// Other magic number, implying some unknown network
    Other(P2pMagicNumber),
}

impl P2pNetworkId {
    pub fn from_magic(magic: P2pMagicNumber) -> Self {
        match magic {
            m if m == P2pNetworkId::Mainnet.as_magic() => P2pNetworkId::Mainnet,
            m if m == P2pNetworkId::Testnet.as_magic() => P2pNetworkId::Testnet,
            m if m == P2pNetworkId::Regtest.as_magic() => P2pNetworkId::Regtest,
            m if m == P2pNetworkId::Signet.as_magic() => P2pNetworkId::Signet,
            m => P2pNetworkId::Other(m),
        }
    }

    pub fn as_magic(&self) -> P2pMagicNumber {
        match self {
            P2pNetworkId::Mainnet => P2P_MAGIC_MAINNET,
            P2pNetworkId::Testnet => P2P_MAGIC_TESTNET,
            P2pNetworkId::Regtest => P2P_MAGIC_REGTEST,
            P2pNetworkId::Signet => P2P_MAGIC_SIGNET,
            P2pNetworkId::Other(n) => *n,
        }
    }
}

impl StrictEncode for P2pNetworkId {
    #[inline]
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        Ok(self.as_magic().strict_encode(e)?)
    }
}

impl StrictDecode for P2pNetworkId {
    #[inline]
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        Ok(Self::from_magic(u32::strict_decode(d)?))
    }
}

impl Debug for P2pNetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({:#x?})", self, self.as_magic())
    }
}

impl Display for P2pNetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            P2pNetworkId::Mainnet => f.write_str("mainnet"),
            P2pNetworkId::Testnet => f.write_str("testnet"),
            P2pNetworkId::Regtest => f.write_str("regtest"),
            P2pNetworkId::Signet => f.write_str("signet"),
            P2pNetworkId::Other(_) => f.write_str("unknown"),
        }
    }
}

impl From<P2pMagicNumber> for P2pNetworkId {
    fn from(magic: P2pMagicNumber) -> Self {
        P2pNetworkId::from_magic(magic)
    }
}

impl From<P2pNetworkId> for P2pMagicNumber {
    fn from(network: P2pNetworkId) -> Self {
        network.as_magic()
    }
}

impl From<bitcoin::Network> for P2pNetworkId {
    fn from(bn: bitcoin::Network) -> Self {
        match bn {
            bitcoin::Network::Bitcoin => P2pNetworkId::Mainnet,
            bitcoin::Network::Testnet => P2pNetworkId::Testnet,
            bitcoin::Network::Regtest => P2pNetworkId::Regtest,
            bitcoin::Network::Signet => P2pNetworkId::Signet,
        }
    }
}

/// Indicates that [`bitcoin::Network`] does not has a correspondense for a
/// given [`P2pNetworkId`] variant
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display(Debug)]
pub struct ConversionImpossibleError;

impl TryFrom<P2pNetworkId> for bitcoin::Network {
    type Error = ConversionImpossibleError;
    fn try_from(bn: P2pNetworkId) -> Result<Self, Self::Error> {
        Ok(match bn {
            P2pNetworkId::Mainnet => bitcoin::Network::Bitcoin,
            P2pNetworkId::Testnet => bitcoin::Network::Testnet,
            P2pNetworkId::Regtest => bitcoin::Network::Regtest,
            P2pNetworkId::Signet => bitcoin::Network::Signet,
            P2pNetworkId::Other(magic) if magic == P2P_MAGIC_MAINNET => {
                bitcoin::Network::Bitcoin
            }
            P2pNetworkId::Other(magic) if magic == P2P_MAGIC_TESTNET => {
                bitcoin::Network::Testnet
            }
            P2pNetworkId::Other(magic) if magic == P2P_MAGIC_REGTEST => {
                bitcoin::Network::Regtest
            }
            _ => Err(ConversionImpossibleError)?,
        })
    }
}

hash_newtype!(
    AssetId,
    sha256d::Hash,
    32,
    doc = "Universal asset identifier for on-chain and off-chain assets; for \
           on-chain assets matches genesis hash of the chain, but displayed in \
           normal, non-reverse order",
    false
);
impl strict_encoding::Strategy for AssetId {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}
impl lightning_encoding::Strategy for AssetId {
    type Strategy = lightning_encoding::strategies::AsBitcoinHash;
}

impl From<BlockHash> for AssetId {
    fn from(block_hash: BlockHash) -> Self {
        AssetId::from_inner(block_hash.into_inner())
    }
}

/// Genesis block hash for bitcoin mainnet
pub(crate) const GENESIS_HASH_MAINNET: &[u8] = &[
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46,
    0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
    0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Genesis block hash for bitcoin testnet v3
pub(crate) const GENESIS_HASH_TESTNET: &[u8] = &[
    0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71, 0x08, 0xf4, 0xa3, 0x0f,
    0xd9, 0xce, 0xc3, 0xae, 0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
    0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
];

/// Genesis block hash for bitcoin regtest network(s)
pub(crate) const GENESIS_HASH_REGTEST: &[u8] = &[
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60,
    0x43, 0xeb, 0x5b, 0xbf, 0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
    0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

/// Genesis block hash for bitcoin signet (default network)
pub(crate) const GENESIS_HASH_SIGNET: &[u8] = &[
    0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf,
    0x32, 0xb2, 0xbb, 0xc9, 0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25,
    0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00,
];

/// Genesis block hash for liquid v1 sidechain
pub(crate) const GENESIS_HASH_LIQUIDV1: &[u8] = &[
    0x14, 0x66, 0x27, 0x58, 0x36, 0x22, 0x0d, 0xb2, 0x94, 0x4c, 0xa0, 0x59,
    0xa3, 0xa1, 0x0e, 0xf6, 0xfd, 0x2e, 0xa6, 0x84, 0xb0, 0x68, 0x8d, 0x2c,
    0x37, 0x92, 0x96, 0x88, 0x8a, 0x20, 0x60, 0x03,
];

lazy_static! {
    /// Bitcoin mainnet chain parameters
    static ref CHAIN_PARAMS_MAINNET: ChainParams = ChainParams {
        name: "bitcoin".to_string(),
        p2p_magic: P2pNetworkId::Mainnet,
        genesis_hash: BlockHash::from_slice(GENESIS_HASH_MAINNET)
            .expect("Bitcoin genesis hash contains invalid binary data"),
        bip70_name: "main".to_string(),
        bip173_prefix: "bc".to_string(),
        p2p_port: 8333,
        rpc_port: 8332,
        ln_height: 504500,
        // TODO: (new) update with first RGB release
        rgb_height: 650000,
        format: ChainFormat::Bitcoin,
        dust_limit: 546,
        native_asset: AssetParams {
            ticker: "BTC".to_string(),
            unit_of_accounting: "Bitcoin".to_string(),
            indivisible_unit: "satoshi".to_string(),
            divisibility: 100_000_000,
            asset_id: AssetId::from_slice(GENESIS_HASH_MAINNET)
                .expect("Bitcoin genesis hash contains invalid binary data"),
            asset_system: AssetSystem::NativeBlockchain,
        },
        is_testnet: false,
        is_pow: true,
    };

    /// Bitcoin testnet chain parameters
    static ref CHAIN_PARAMS_TESTNET: ChainParams = ChainParams {
        name: "testnet".to_string(),
        p2p_magic: P2pNetworkId::Testnet,
        genesis_hash: BlockHash::from_slice(GENESIS_HASH_TESTNET)
            .expect("Bitcoin testnet genesis hash contains invalid binary data"),
        bip70_name: "test".to_string(),
        bip173_prefix: "tb".to_string(),
        p2p_port: 18333,
        rpc_port: 18332,
        ln_height: 1,
        // TODO: (new) update with first RGB release
        rgb_height: 1835500,
        format: ChainFormat::Bitcoin,
        dust_limit: 546,
        native_asset: AssetParams {
            ticker: "tBTC".to_string(),
            unit_of_accounting: "Test Bitcoin".to_string(),
            indivisible_unit: "Test satoshi".to_string(),
            divisibility: 100_000_000,
            asset_id: AssetId::from_slice(GENESIS_HASH_TESTNET)
                .expect("Bitcoin testnet genesis hash contains invalid binary data"),
            asset_system: AssetSystem::NativeBlockchain,
        },
        is_testnet: true,
        is_pow: true,
    };

    /// Bitcoin regtest chain parameters
    static ref CHAIN_PARAMS_REGTEST: ChainParams = ChainParams {
        name: "regtest".to_string(),
        p2p_magic: P2pNetworkId::Regtest,
        genesis_hash: BlockHash::from_slice(GENESIS_HASH_REGTEST)
            .expect("Bitcoin regtest genesis hash contains invalid binary data"),
        bip70_name: "regtest".to_string(),
        bip173_prefix: "tb".to_string(),
        p2p_port: 28333,
        rpc_port: 28332,
        ln_height: 1,
        rgb_height: 1,
        format: ChainFormat::Bitcoin,
        dust_limit: 546,
        native_asset: AssetParams {
            ticker: "tBTC".to_string(),
            unit_of_accounting: "Test Bitcoin".to_string(),
            indivisible_unit: "Test satoshi".to_string(),
            divisibility: 100_000_000,
            asset_id: AssetId::from_slice(GENESIS_HASH_REGTEST)
                .expect("Bitcoin regtest genesis hash contains invalid binary data"),
            asset_system: AssetSystem::NativeBlockchain,
        },
        is_testnet: true,
        is_pow: false,
    };

    /// Bitcoin signet chain parameters
    static ref CHAIN_PARAMS_SIGNET: ChainParams = ChainParams {
        name: "signet".to_string(),
        p2p_magic: P2pNetworkId::Signet,
        genesis_hash: BlockHash::from_slice(GENESIS_HASH_SIGNET)
            .expect("Bitcoin signet genesis hash contains invalid binary data"),
        bip70_name: "signet".to_string(),
        bip173_prefix: "tb".to_string(),
        p2p_port: 38333,
        rpc_port: 38332,
        ln_height: 1,
        rgb_height: 1,
        format: ChainFormat::Bitcoin,
        dust_limit: 546,
        native_asset: AssetParams {
            ticker: "sBTC".to_string(),
            unit_of_accounting: "Signet Bitcoin".to_string(),
            indivisible_unit: "Signet satoshi".to_string(),
            divisibility: 100_000_000,
            asset_id: AssetId::from_slice(GENESIS_HASH_SIGNET)
                .expect("Bitcoin signet genesis hash contains invalid binary data"),
            asset_system: AssetSystem::NativeBlockchain,
        },
        is_testnet: true,
        is_pow: false,
    };

    /// Liquid V1 chain parameters
    static ref CHAIN_PARAMS_LIQUIDV1: ChainParams = ChainParams {
        name: "liquidv1".to_string(),
        // TODO: (new) check Liquid network magic number and change this if needed
        p2p_magic: P2pNetworkId::Mainnet,
        genesis_hash: BlockHash::from_slice(GENESIS_HASH_LIQUIDV1)
            .expect("Liquid V1 genesis hash contains invalid binary data"),
        bip70_name: "liquidv1".to_string(),
        bip173_prefix: "ex".to_string(),
        p2p_port: 7042,
        rpc_port: 7041,
        ln_height: 1,
        rgb_height: 1_000_000,
        format: ChainFormat::Elements,
        dust_limit: 546,
        native_asset: AssetParams {
            ticker: "LBTC".to_string(),
            unit_of_accounting: "Liquid Bitcoin".to_string(),
            indivisible_unit: "Liquid satoshi".to_string(),
            divisibility: 100_000_000,
            asset_id: AssetId::from_slice(GENESIS_HASH_LIQUIDV1)
                .expect("Liquid V1 genesis hash contains invalid binary data"),
            asset_system: AssetSystem::NativeBlockchain,
        },
        is_testnet: false,
        is_pow: false,
    };
}

/// Enum identifying format for transaction & block structure in a given chain.
/// Right now only two structures are supported: Bitcoin format and
/// Elements format, extended with confidential transaction-specific structures.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    Hash,
    FromPrimitive,
    ToPrimitive,
)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[non_exhaustive]
#[repr(u8)]
pub enum ChainFormat {
    /// Bitcoin standard format (bitcoin networks, litecoin)
    Bitcoin = 0,
    /// Confidential transactions format
    Elements = 1,
}
impl_enum_strict_encoding!(ChainFormat);

/// Layers on which a given asset can operate
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    Hash,
    FromPrimitive,
    ToPrimitive,
)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[repr(u8)]
pub enum AssetLayer {
    /// Native chain asset(s), which can operate both on the layer of
    /// blockchain and payment/state channels (Bitcoin, sidechain-specific
    /// asset(s), like liquidBTC or confidential assets in Liquid)
    Layer1and2 = 1,

    /// Derived assets, which are created and defined above blockchain (like
    /// RGB), but also can be used on top of payment/state channels
    Layer2and3 = 2,
}
impl_enum_strict_encoding!(AssetLayer);

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    Hash,
    FromPrimitive,
    ToPrimitive,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[display(Debug)]
#[non_exhaustive]
#[repr(u8)]
pub enum AssetSystem {
    /// Native blockchain asset, including liquid bitcoin in LiquidV1 network
    NativeBlockchain = 0,

    /// Liquid confidential assets used in LiquidV1 network
    ConfidentialAssets = 1,

    /// RGB confidential assets
    RgbContract = 2,
}
impl_enum_strict_encoding!(AssetSystem);

/// Parameters for a given asset, which are shared between different types of
/// Layer 1, 2 and 3 assets.
#[derive(Clone, PartialOrd, Ord, Debug, Display, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[display(Debug)]
pub struct AssetParams {
    /// Short asset name, or ticker, like BTC for bitcoin. Case-sensitive with
    /// default use of uppercase.
    pub ticker: String,

    /// Full name for a given asset as a unit of accounting, for instance
    /// "Bitcoin". Also case-sensitive.
    pub unit_of_accounting: String,

    /// Full name for the smallest indivisible unit, like "satoshi" for
    /// Bitcoin network
    pub indivisible_unit: String,

    /// Number of smallest indivisible units inside the unit of accounting
    pub divisibility: u64,

    /// Identifier of the asset; for native chain assets matches to the
    /// genesis block hash of the chain itself (i.e.
    /// [ChainParams::genesis_hash]), for other assets are specific to a given
    /// asset system: for confidential assets this is an `AssetId`, for
    /// RGB – hash of asset genesis transition, i.e. `ContractId`.
    pub asset_id: AssetId,

    /// [AssetSystem] in which asset is defined
    pub asset_system: AssetSystem,
}

impl PartialEq for AssetParams {
    fn eq(&self, other: &Self) -> bool {
        // There negligible change that any two hashes will collide, however we
        // are taking responsible approach here:
        self.asset_id == other.asset_id
            && self.asset_system == other.asset_system
    }
}

impl Eq for AssetParams {}

impl StrictEncode for AssetParams {
    #[inline]
    fn strict_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, strict_encoding::Error> {
        Ok(strict_encode_list!(e;
            self.ticker,
            self.unit_of_accounting,
            self.indivisible_unit,
            self.divisibility,
            self.asset_id,
            self.asset_system
        ))
    }
}

impl StrictDecode for AssetParams {
    #[inline]
    fn strict_decode<D: io::Read>(
        mut d: D,
    ) -> Result<Self, strict_encoding::Error> {
        Ok(strict_decode_self!(d;
            ticker,
            unit_of_accounting,
            indivisible_unit,
            divisibility,
            asset_id,
            asset_system
        ))
    }
}

/// Full set of parameters which uniquely define given blockchain,
/// corresponding P2P network and RPC interface of fully validating nodes
#[derive(
    Clone, PartialOrd, Ord, Debug, Display, Hash, StrictEncode, StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
#[lnpbp_crate(crate)]
pub struct ChainParams {
    /// Hash of the genesis block, uniquely defining chain
    pub genesis_hash: BlockHash,

    /// Blockchain name, including version:
    /// - mainnet for Bitcoin mainnet
    /// - testnet3 for Bitcoin testnet version 3
    /// - regtest for Bitcoin regtest networks
    /// - signet for Bitcoin signet and private signet networks
    /// - liquidv1 for Liquid network v1
    pub name: String,

    /// Magic number used as prefix in P2P network API
    pub p2p_magic: P2pNetworkId,

    /// Network name according to BIP 70, which may be different from
    /// [ChainParams::name]. Not widely used these days, but we still have to
    /// account for standard.
    pub bip70_name: String,

    /// HRP bech32 address prefix as defined in BIP 173
    pub bip173_prefix: String,

    /// Default port for P2P network
    pub p2p_port: u16,

    /// Default port for full validating node RPC interface
    pub rpc_port: u16,

    /// Block number from which Lightning network support had started using
    /// the given chain
    pub ln_height: u32,

    /// Block number from which RGB had started using the given chain
    pub rgb_height: u32,

    /// Format of chain-specific data. See [ChainFormat] for more information
    pub format: ChainFormat,

    /// Dust limit for the given chain; 0 if none dust limit applies
    pub dust_limit: u64,

    /// Parameters of the native chain asset (can be only one; it is the asset
    /// in which miners are got paid).
    pub native_asset: AssetParams,

    /// Flag indicating any kind of testnet network that do not operate with
    /// real economic values
    pub is_testnet: bool,

    /// Flag indicating blockchains that use PoW consensus algorithm
    pub is_pow: bool,
}

impl PartialEq for ChainParams {
    fn eq(&self, other: &Self) -> bool {
        self.genesis_hash == other.genesis_hash
    }
}

impl Eq for ChainParams {}

/// A set of recommended standard networks. Differs from bitcoin::Network in
/// ability to support non-standard and non-predefined networks
#[derive(Clone, Debug, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[non_exhaustive]
#[repr(u32)]
pub enum Chain {
    /// Bitcoin mainnet
    Mainnet,

    /// Bitcoin testnet version 3
    Testnet3,

    /// Bitcoin regtest network, with provided genesis hash to distinguish
    /// different private networks
    Regtest(BlockHash),

    /// Default bitcoin signet network
    Signet,

    /// Some private bitcoin signet network, with provided genesis hash to
    /// distinguish private networks from each other
    SignetCustom(BlockHash),

    /// Liquidv1 sidechain & network by Blockstream
    LiquidV1,

    /// All other networks/chains, providing full information on chain
    /// parameters
    Other(ChainParams),
}

impl Default for Chain {
    fn default() -> Self {
        Chain::Signet
    }
}

impl PartialEq for Chain {
    fn eq(&self, other: &Self) -> bool {
        self.chain_params().eq(&other.chain_params())
    }
}

impl Eq for Chain {}

impl PartialOrd for Chain {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.chain_params().partial_cmp(&other.chain_params())
    }
}

impl Ord for Chain {
    fn cmp(&self, other: &Self) -> Ordering {
        self.chain_params().cmp(&other.chain_params())
    }
}

impl Chain {
    /// Returns chain parameters [ChainParams] for a given chain id
    pub fn chain_params(&self) -> ChainParams {
        match self {
            Chain::Mainnet => CHAIN_PARAMS_MAINNET.clone(),
            Chain::Testnet3 => CHAIN_PARAMS_TESTNET.clone(),
            Chain::Regtest(hash) => {
                let mut regtest = CHAIN_PARAMS_REGTEST.clone();
                regtest.genesis_hash = *hash;
                regtest
            }
            Chain::Signet => CHAIN_PARAMS_SIGNET.clone(),
            Chain::SignetCustom(hash) => {
                let mut signet = CHAIN_PARAMS_SIGNET.clone();
                signet.genesis_hash = *hash;
                signet
            }
            Chain::LiquidV1 => CHAIN_PARAMS_LIQUIDV1.clone(),
            Chain::Other(params) => params.clone(),
        }
    }

    /// Returns hash of genesis block
    pub fn as_genesis_hash(&self) -> &BlockHash {
        match self {
            Chain::Mainnet => &CHAIN_PARAMS_MAINNET.genesis_hash,
            Chain::Testnet3 => &CHAIN_PARAMS_TESTNET.genesis_hash,
            Chain::Regtest(hash) => hash,
            Chain::Signet => &CHAIN_PARAMS_SIGNET.genesis_hash,
            Chain::SignetCustom(hash) => hash,
            Chain::LiquidV1 => &CHAIN_PARAMS_LIQUIDV1.genesis_hash,
            Chain::Other(params) => &params.genesis_hash,
        }
    }

    /// Gueses chain from the given genesis block hash, returning
    /// [Option::None] if the hash is unknown. This implies that for
    /// custom signet and some regtest networks with modified genesis the
    /// function will fail.
    pub fn from_genesis_hash(hash: &BlockHash) -> Option<Self> {
        match hash {
            h if *h == CHAIN_PARAMS_MAINNET.genesis_hash => Some(Self::Mainnet),
            h if *h == CHAIN_PARAMS_TESTNET.genesis_hash => {
                Some(Self::Testnet3)
            }
            h if *h == CHAIN_PARAMS_SIGNET.genesis_hash => Some(Self::Signet),
            h if *h == CHAIN_PARAMS_REGTEST.genesis_hash => {
                Some(Self::Regtest(*h))
            }
            h if *h == CHAIN_PARAMS_LIQUIDV1.genesis_hash => {
                Some(Self::LiquidV1)
            }
            _ => None,
        }
    }
}

impl StrictEncode for Chain {
    #[inline]
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        Ok(self.chain_params().strict_encode(e)?)
    }
}

impl StrictDecode for Chain {
    #[inline]
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        Ok(Self::from(ChainParams::strict_decode(d)?))
    }
}

impl From<ChainParams> for Chain {
    fn from(params: ChainParams) -> Self {
        match params {
            p if p == Chain::Mainnet.chain_params() => Chain::Mainnet,
            p if p == Chain::Testnet3.chain_params() => Chain::Testnet3,
            p if p == Chain::Signet.chain_params() => Chain::Signet,
            p if p == Chain::LiquidV1.chain_params() => Chain::LiquidV1,
            p if p == Chain::Regtest(p.genesis_hash).chain_params() => {
                Chain::Regtest(p.genesis_hash)
            }
            p if p == Chain::SignetCustom(p.genesis_hash).chain_params() => {
                Chain::SignetCustom(p.genesis_hash)
            }
            p => Chain::Other(p),
        }
    }
}

impl From<bitcoin::Network> for Chain {
    fn from(bn: bitcoin::Network) -> Self {
        match bn {
            bitcoin::Network::Bitcoin => Chain::Mainnet,
            bitcoin::Network::Testnet => Chain::Testnet3,
            bitcoin::Network::Regtest => {
                Chain::Regtest(CHAIN_PARAMS_REGTEST.genesis_hash)
            }
            bitcoin::Network::Signet => Chain::Signet,
        }
    }
}

impl TryFrom<Chain> for bitcoin::Network {
    type Error = ConversionImpossibleError;
    fn try_from(chain: Chain) -> Result<Self, Self::Error> {
        bitcoin::Network::try_from(&chain)
    }
}

impl TryFrom<&Chain> for bitcoin::Network {
    type Error = ConversionImpossibleError;
    fn try_from(chain: &Chain) -> Result<Self, Self::Error> {
        Ok(match chain {
            Chain::Mainnet => bitcoin::Network::Bitcoin,
            Chain::Testnet3 => bitcoin::Network::Testnet,
            Chain::Regtest(hash)
                if hash == &CHAIN_PARAMS_REGTEST.genesis_hash =>
            {
                bitcoin::Network::Regtest
            }
            _ => Err(ConversionImpossibleError)?,
        })
    }
}

impl Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Chain::Mainnet => write!(f, "bitcoin"),
            Chain::Testnet3 => write!(f, "testnet"),
            Chain::Regtest(hash) if &hash[..] == GENESIS_HASH_REGTEST => {
                write!(f, "regtest")
            }
            Chain::Regtest(hash) => write!(f, "regtest:{}", hash),
            Chain::Signet => write!(f, "signet"),
            Chain::SignetCustom(hash) if &hash[..] == GENESIS_HASH_SIGNET => {
                write!(f, "signet")
            }
            Chain::SignetCustom(hash) => write!(f, "signet:{}", hash),
            Chain::LiquidV1 => write!(f, "liquidv1"),
            Chain::Other(params)
                if &params.genesis_hash[..] == GENESIS_HASH_MAINNET =>
            {
                write!(f, "bitcoin")
            }
            Chain::Other(params)
                if &params.genesis_hash[..] == GENESIS_HASH_TESTNET =>
            {
                write!(f, "testnet")
            }
            Chain::Other(params)
                if &params.genesis_hash[..] == GENESIS_HASH_REGTEST =>
            {
                write!(f, "regtest")
            }
            Chain::Other(params)
                if &params.genesis_hash[..] == GENESIS_HASH_SIGNET =>
            {
                write!(f, "signet")
            }
            Chain::Other(params)
                if &params.genesis_hash[..] == GENESIS_HASH_LIQUIDV1 =>
            {
                write!(f, "liquidv1")
            }
            Chain::Other(params) => {
                write!(f, "other:{}", strict_serialize(params)?.to_hex())
            }
        }
    }
}

/// Chain data parse errors
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ParseError {
    /// The provided string does not matches any known chain; chain parameters
    /// can't be guessed. Please use `other:0x<hex_encoded_parameters>` for
    /// all non-standard networks.
    WrongNetworkName,

    /// Chain parameters can't be decoded. Please check that they are provided
    /// as a hexadecimal string starting with `0x` sign (case is irrelevant).
    #[from(strict_encoding::Error)]
    ChainParamsEncoding,

    /// Can't decode value for genesis (chain) hash, please make sure that the
    /// provided string contains
    #[from]
    GenesisHashEncoding(hex::Error),
}

impl FromStr for Chain {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase() {
            s if s == CHAIN_PARAMS_MAINNET.name
                || s == CHAIN_PARAMS_MAINNET.bip70_name
                || s == CHAIN_PARAMS_MAINNET.bip173_prefix =>
            {
                Ok(Chain::Mainnet)
            }
            // Here we do not use `tb` prefix, since it matches multiple options
            s if s == CHAIN_PARAMS_TESTNET.name
                || s == CHAIN_PARAMS_TESTNET.bip70_name =>
            {
                Ok(Chain::Testnet3)
            }
            s if s == CHAIN_PARAMS_REGTEST.name
                || s == CHAIN_PARAMS_REGTEST.bip70_name =>
            {
                Ok(Chain::Regtest(CHAIN_PARAMS_REGTEST.genesis_hash))
            }
            s if s == CHAIN_PARAMS_SIGNET.name
                || s == CHAIN_PARAMS_SIGNET.bip70_name =>
            {
                Ok(Chain::Signet)
            }
            s if s == CHAIN_PARAMS_LIQUIDV1.name
                || s == CHAIN_PARAMS_LIQUIDV1.bip70_name =>
            {
                Ok(Chain::LiquidV1)
            }
            s => {
                let mut parts = s.split(':');
                let prefix =
                    parts.next().ok_or(ParseError::WrongNetworkName)?;
                let data = parts.next().ok_or(ParseError::WrongNetworkName)?;
                parts
                    .next()
                    .map_or(Ok(()), |_| Err(ParseError::WrongNetworkName))?;
                match prefix {
                    "regtest" => Ok(Chain::Regtest(BlockHash::from_hex(data)?)),
                    "signet" => {
                        Ok(Chain::SignetCustom(BlockHash::from_hex(data)?))
                    }
                    "other" => Ok(Chain::Other(strict_deserialize(
                        &Vec::from_hex(data)
                            .map_err(|_| ParseError::ChainParamsEncoding)?,
                    )?)),
                    _ => Err(ParseError::WrongNetworkName),
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::strict_encoding::test::test_suite;

    #[test]
    fn test_p2p_magic_number_byteorder() {
        let mainnet_bytes = &[0xF9u8, 0xBEu8, 0xB4u8, 0xD9u8][..];
        let testnet_bytes = &[0x0Bu8, 0x11u8, 0x09u8, 0x07u8][..];
        let regtest_bytes = &[0xFAu8, 0xBFu8, 0xB5u8, 0xDAu8][..];
        let signet_bytes = &[0x0Au8, 0x03u8, 0xCFu8, 0x40u8][..];
        let random_bytes = [0xA1u8, 0xA2u8, 0xA3u8, 0xA4u8];

        assert_eq!(P2P_MAGIC_MAINNET.to_le_bytes(), mainnet_bytes);
        assert_eq!(P2P_MAGIC_TESTNET.to_le_bytes(), testnet_bytes);
        assert_eq!(P2P_MAGIC_REGTEST.to_le_bytes(), regtest_bytes);
        assert_eq!(P2P_MAGIC_SIGNET.to_le_bytes(), signet_bytes);

        assert_eq!(P2P_MAGIC_MAINNET, bitcoin::Network::Bitcoin.magic());
        assert_eq!(P2P_MAGIC_TESTNET, bitcoin::Network::Testnet.magic());
        assert_eq!(P2P_MAGIC_REGTEST, bitcoin::Network::Regtest.magic());

        let other = P2pNetworkId::Other(u32::from_le_bytes(random_bytes));

        let bp_mainnet = P2pNetworkId::strict_decode(mainnet_bytes).unwrap();
        let bp_testnet = P2pNetworkId::strict_decode(testnet_bytes).unwrap();
        let bp_regtest = P2pNetworkId::strict_decode(regtest_bytes).unwrap();
        let bp_signet = P2pNetworkId::strict_decode(signet_bytes).unwrap();
        let bp_other = P2pNetworkId::strict_decode(&random_bytes[..]).unwrap();
        assert_eq!(bp_other, other);

        test_suite(&bp_mainnet, &mainnet_bytes, 4);
        test_suite(&bp_testnet, &testnet_bytes, 4);
        test_suite(&bp_regtest, &regtest_bytes, 4);
        test_suite(&bp_signet, &signet_bytes, 4);
        test_suite(&bp_other, &random_bytes, 4);
    }

    #[test]
    fn test_p2p_magic_number_fmt() {
        assert_eq!(format!("{}", P2pNetworkId::Mainnet), "mainnet");
        assert_eq!(format!("{}", P2pNetworkId::Testnet), "testnet");
        assert_eq!(format!("{}", P2pNetworkId::Regtest), "regtest");
        assert_eq!(format!("{}", P2pNetworkId::Signet), "signet");
        assert_eq!(format!("{}", P2pNetworkId::Other(0x01)), "unknown");

        assert_eq!(
            format!("{:?}", P2pNetworkId::Mainnet),
            format!("mainnet({:#x?})", P2P_MAGIC_MAINNET)
        );
        assert_eq!(
            format!("{:?}", P2pNetworkId::Testnet),
            format!("testnet({:#x?})", P2P_MAGIC_TESTNET)
        );
        assert_eq!(
            format!("{:?}", P2pNetworkId::Regtest),
            format!("regtest({:#x?})", P2P_MAGIC_REGTEST)
        );
        assert_eq!(
            format!("{:?}", P2pNetworkId::Signet),
            format!("signet({:#x?})", P2P_MAGIC_SIGNET)
        );
        assert_eq!(
            format!("{:?}", P2pNetworkId::Other(0x01u32)),
            format!("unknown({:#x?})", 0x01u32)
        );
    }

    #[test]
    fn test_p2p_magic_number_from() {
        assert_eq!(
            P2pNetworkId::from(P2P_MAGIC_MAINNET),
            P2pNetworkId::Mainnet
        );
        assert_eq!(
            P2pNetworkId::from(P2P_MAGIC_TESTNET),
            P2pNetworkId::Testnet
        );
        assert_eq!(
            P2pNetworkId::from(P2P_MAGIC_REGTEST),
            P2pNetworkId::Regtest
        );
        assert_eq!(P2pNetworkId::from(P2P_MAGIC_SIGNET), P2pNetworkId::Signet);
        assert_eq!(
            P2pNetworkId::from(0x0102030),
            P2pNetworkId::Other(0x0102030)
        );

        assert_eq!(
            P2P_MAGIC_MAINNET,
            P2pMagicNumber::from(P2pNetworkId::Mainnet)
        );
        assert_eq!(
            P2P_MAGIC_TESTNET,
            P2pMagicNumber::from(P2pNetworkId::Testnet)
        );
        assert_eq!(
            P2P_MAGIC_REGTEST,
            P2pMagicNumber::from(P2pNetworkId::Regtest)
        );
        assert_eq!(
            P2P_MAGIC_SIGNET,
            P2pMagicNumber::from(P2pNetworkId::Signet)
        );
        assert_eq!(
            0x0102030,
            P2pMagicNumber::from(P2pNetworkId::Other(0x0102030))
        );

        assert_eq!(
            P2pNetworkId::from(bitcoin::Network::Bitcoin),
            P2pNetworkId::Mainnet
        );
        assert_eq!(
            P2pNetworkId::from(bitcoin::Network::Testnet),
            P2pNetworkId::Testnet
        );
        assert_eq!(
            P2pNetworkId::from(bitcoin::Network::Regtest),
            P2pNetworkId::Regtest
        );

        assert_eq!(
            bitcoin::Network::try_from(P2pNetworkId::Mainnet).unwrap(),
            bitcoin::Network::Bitcoin
        );
        assert_eq!(
            bitcoin::Network::try_from(P2pNetworkId::Testnet).unwrap(),
            bitcoin::Network::Testnet
        );
        assert_eq!(
            bitcoin::Network::try_from(P2pNetworkId::Regtest).unwrap(),
            bitcoin::Network::Regtest
        );

        assert_eq!(
            bitcoin::Network::try_from(P2pNetworkId::Other(P2P_MAGIC_MAINNET))
                .unwrap(),
            bitcoin::Network::Bitcoin
        );
        assert_eq!(
            bitcoin::Network::try_from(P2pNetworkId::Other(P2P_MAGIC_TESTNET))
                .unwrap(),
            bitcoin::Network::Testnet
        );
        assert_eq!(
            bitcoin::Network::try_from(P2pNetworkId::Other(P2P_MAGIC_REGTEST))
                .unwrap(),
            bitcoin::Network::Regtest
        );
    }

    #[test]
    #[should_panic = "ConversionImpossibleError"]
    fn test_p2p_network_id_other() {
        bitcoin::Network::try_from(P2pNetworkId::Other(0xA1A2A3A4)).unwrap();
    }

    #[test]
    fn test_chain_param_enums() {
        test_enum_u8_exhaustive!(ChainFormat;
            ChainFormat::Bitcoin => 0,
            ChainFormat::Elements => 1
        );

        test_enum_u8_exhaustive!(AssetLayer;
            AssetLayer::Layer1and2 => 1,
            AssetLayer::Layer2and3 => 2
        );

        test_enum_u8_exhaustive!(AssetSystem;
            AssetSystem::NativeBlockchain => 0,
            AssetSystem::ConfidentialAssets => 1,
            AssetSystem::RgbContract => 2
        );
    }

    #[test]
    fn test_asset_params_eq() {
        let asset1 = AssetParams {
            ticker: "AAA".to_string(),
            unit_of_accounting: "Aaa".to_string(),
            indivisible_unit: "a".to_string(),
            divisibility: 0,
            asset_id: Default::default(),
            asset_system: AssetSystem::NativeBlockchain,
        };

        let asset2 = AssetParams {
            ticker: "AAA".to_string(),
            unit_of_accounting: "Aaa".to_string(),
            indivisible_unit: "a".to_string(),
            divisibility: 0,
            asset_id: Default::default(),
            asset_system: AssetSystem::ConfidentialAssets,
        };

        let asset3 = AssetParams {
            ticker: "BBB".to_string(),
            unit_of_accounting: "Bbb".to_string(),
            indivisible_unit: "b".to_string(),
            divisibility: 1,
            asset_id: Default::default(),
            asset_system: AssetSystem::NativeBlockchain,
        };

        let asset4 = AssetParams {
            ticker: "AAA".to_string(),
            unit_of_accounting: "Aaa".to_string(),
            indivisible_unit: "a".to_string(),
            divisibility: 0,
            asset_id: AssetId::hash(b"asset"),
            asset_system: AssetSystem::NativeBlockchain,
        };

        assert_eq!(asset1, asset1);
        assert_eq!(asset1, asset3);
        assert_ne!(asset1, asset2);
        assert_ne!(asset1, asset4);
        assert_ne!(asset2, asset3);
        assert_ne!(asset2, asset4);
        assert_ne!(asset3, asset4);
    }

    #[test]
    fn test_chain_params() {
        assert_eq!(Chain::Mainnet.chain_params(), *CHAIN_PARAMS_MAINNET);
        assert_eq!(Chain::Testnet3.chain_params(), *CHAIN_PARAMS_TESTNET);
        assert_eq!(
            Chain::Regtest(
                BlockHash::from_slice(&GENESIS_HASH_REGTEST).unwrap()
            )
            .chain_params(),
            *CHAIN_PARAMS_REGTEST
        );
        assert_eq!(Chain::Signet.chain_params(), *CHAIN_PARAMS_SIGNET);
        assert_eq!(
            Chain::SignetCustom(
                BlockHash::from_slice(&GENESIS_HASH_SIGNET).unwrap()
            )
            .chain_params(),
            *CHAIN_PARAMS_SIGNET
        );
        assert_eq!(Chain::LiquidV1.chain_params(), *CHAIN_PARAMS_LIQUIDV1);

        assert_eq!(Chain::Mainnet, Chain::Mainnet);
        assert_eq!(
            Chain::Signet,
            Chain::SignetCustom(
                BlockHash::from_slice(&GENESIS_HASH_SIGNET).unwrap()
            )
        );
        assert_ne!(Chain::Mainnet, Chain::LiquidV1);
        assert_ne!(Chain::Mainnet, Chain::Testnet3);
        assert_ne!(Chain::Mainnet, Chain::Signet);
        assert_ne!(Chain::Signet, Chain::Testnet3);
        assert_eq!(
            Chain::Signet,
            Chain::Regtest(
                BlockHash::from_slice(&GENESIS_HASH_SIGNET).unwrap()
            )
        );
        assert_ne!(Chain::Signet, Chain::SignetCustom(BlockHash::hash(b"")));
    }

    #[test]
    fn test_chain_encode() {
        const DATA_CHAINPARAMS_MAINNET: [u8; 142] = [
            0x6f, 0xe2, 0x8c, 0xa, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2,
            0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a,
            0x8, 0x9c, 0x68, 0xd6, 0x19, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0,
            0x62, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0xf9, 0xbe, 0xb4, 0xd9,
            0x4, 0x0, 0x6d, 0x61, 0x69, 0x6e, 0x2, 0x0, 0x62, 0x63, 0x8d, 0x20,
            0x8c, 0x20, 0xb4, 0xb2, 0x7, 0x0, 0x10, 0xeb, 0x9, 0x0, 0x0, 0x22,
            0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x42, 0x54, 0x43, 0x7,
            0x0, 0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x7, 0x0, 0x73,
            0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0x0, 0xe1, 0xf5, 0x5, 0x0, 0x0,
            0x0, 0x0, 0x6f, 0xe2, 0x8c, 0xa, 0xb6, 0xf1, 0xb3, 0x72, 0xc1,
            0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65,
            0xe1, 0x5a, 0x8, 0x9c, 0x68, 0xd6, 0x19, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x1,
        ];
        const DATA_CHAINPARAMS_TESTNET: [u8; 153] = [
            0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71, 0x8, 0xf4, 0xa3,
            0xf, 0xd9, 0xce, 0xc3, 0xae, 0xba, 0x79, 0x97, 0x20, 0x84, 0xe9,
            0xe, 0xad, 0x1, 0xea, 0x33, 0x9, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0,
            0x74, 0x65, 0x73, 0x74, 0x6e, 0x65, 0x74, 0xb, 0x11, 0x9, 0x7, 0x4,
            0x0, 0x74, 0x65, 0x73, 0x74, 0x2, 0x0, 0x74, 0x62, 0x9d, 0x47,
            0x9c, 0x47, 0x1, 0x0, 0x0, 0x0, 0xec, 0x1, 0x1c, 0x0, 0x0, 0x22,
            0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x74, 0x42, 0x54,
            0x43, 0xc, 0x0, 0x54, 0x65, 0x73, 0x74, 0x20, 0x42, 0x69, 0x74,
            0x63, 0x6f, 0x69, 0x6e, 0xc, 0x0, 0x54, 0x65, 0x73, 0x74, 0x20,
            0x73, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0x0, 0xe1, 0xf5, 0x5,
            0x0, 0x0, 0x0, 0x0, 0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
            0x8, 0xf4, 0xa3, 0xf, 0xd9, 0xce, 0xc3, 0xae, 0xba, 0x79, 0x97,
            0x20, 0x84, 0xe9, 0xe, 0xad, 0x1, 0xea, 0x33, 0x9, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x1, 0x1,
        ];
        const DATA_CHAINPARAMS_SIGNET: [u8; 158] = [
            0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63,
            0xaf, 0x32, 0xb2, 0xbb, 0xc9, 0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c,
            0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x8, 0x0, 0x0, 0x0, 0x6, 0x0,
            0x73, 0x69, 0x67, 0x6e, 0x65, 0x74, 0xa, 0x3, 0xcf, 0x40, 0x6, 0x0,
            0x73, 0x69, 0x67, 0x6e, 0x65, 0x74, 0x2, 0x0, 0x74, 0x62, 0xbd,
            0x95, 0xbc, 0x95, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
            0x22, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x73, 0x42,
            0x54, 0x43, 0xe, 0x0, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x74, 0x20,
            0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0xe, 0x0, 0x53, 0x69,
            0x67, 0x6e, 0x65, 0x74, 0x20, 0x73, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x0, 0xe1, 0xf5, 0x5, 0x0, 0x0, 0x0, 0x0, 0xf6, 0x1e, 0xee,
            0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2,
            0xbb, 0xc9, 0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 0xe9,
            0x73, 0x98, 0x81, 0x8, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
        ];
        const DATA_CHAINPARAMS_LIQUID: [u8; 162] = [
            0x14, 0x66, 0x27, 0x58, 0x36, 0x22, 0xd, 0xb2, 0x94, 0x4c, 0xa0,
            0x59, 0xa3, 0xa1, 0xe, 0xf6, 0xfd, 0x2e, 0xa6, 0x84, 0xb0, 0x68,
            0x8d, 0x2c, 0x37, 0x92, 0x96, 0x88, 0x8a, 0x20, 0x60, 0x3, 0x8,
            0x0, 0x6c, 0x69, 0x71, 0x75, 0x69, 0x64, 0x76, 0x31, 0xf9, 0xbe,
            0xb4, 0xd9, 0x8, 0x0, 0x6c, 0x69, 0x71, 0x75, 0x69, 0x64, 0x76,
            0x31, 0x2, 0x0, 0x65, 0x78, 0x82, 0x1b, 0x81, 0x1b, 0x1, 0x0, 0x0,
            0x0, 0x40, 0x42, 0xf, 0x0, 0x1, 0x22, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x4, 0x0, 0x4c, 0x42, 0x54, 0x43, 0xe, 0x0, 0x4c, 0x69, 0x71,
            0x75, 0x69, 0x64, 0x20, 0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e,
            0xe, 0x0, 0x4c, 0x69, 0x71, 0x75, 0x69, 0x64, 0x20, 0x73, 0x61,
            0x74, 0x6f, 0x73, 0x68, 0x69, 0x0, 0xe1, 0xf5, 0x5, 0x0, 0x0, 0x0,
            0x0, 0x14, 0x66, 0x27, 0x58, 0x36, 0x22, 0xd, 0xb2, 0x94, 0x4c,
            0xa0, 0x59, 0xa3, 0xa1, 0xe, 0xf6, 0xfd, 0x2e, 0xa6, 0x84, 0xb0,
            0x68, 0x8d, 0x2c, 0x37, 0x92, 0x96, 0x88, 0x8a, 0x20, 0x60, 0x3,
            0x0, 0x0, 0x0,
        ];

        test_encode!(
            (DATA_CHAINPARAMS_MAINNET, Chain),
            (DATA_CHAINPARAMS_TESTNET, Chain),
            (DATA_CHAINPARAMS_SIGNET, Chain),
            (DATA_CHAINPARAMS_LIQUID, Chain)
        );
    }

    #[test]
    fn test_chain_genesis_hashes() {
        assert_eq!(
            GENESIS_HASH_MAINNET,
            &[
                0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6,
                0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65,
                0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
        );

        assert_eq!(
            GENESIS_HASH_TESTNET,
            &[
                0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71, 0x08, 0xf4,
                0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae, 0xba, 0x79, 0x97, 0x20,
                0x84, 0xe9, 0x0e, 0xad, 0x01, 0xea, 0x33, 0x09, 0x00, 0x00,
                0x00, 0x00,
            ]
        );

        assert_eq!(
            GENESIS_HASH_REGTEST,
            &[
                0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf,
                0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf, 0x28, 0xc3, 0x4f, 0x3a,
                0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88,
                0x91, 0x0f,
            ]
        );

        assert_eq!(
            GENESIS_HASH_SIGNET,
            &[
                0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0,
                0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9, 0x7c, 0x9f, 0xf9, 0xf0,
                0x1f, 0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x08, 0x00,
                0x00, 0x00,
            ]
        );

        assert_eq!(
            GENESIS_HASH_LIQUIDV1,
            &[
                0x14, 0x66, 0x27, 0x58, 0x36, 0x22, 0x0d, 0xb2, 0x94, 0x4c,
                0xa0, 0x59, 0xa3, 0xa1, 0x0e, 0xf6, 0xfd, 0x2e, 0xa6, 0x84,
                0xb0, 0x68, 0x8d, 0x2c, 0x37, 0x92, 0x96, 0x88, 0x8a, 0x20,
                0x60, 0x03,
            ]
        );

        let random_hash = BlockHash::hash(b"random string");

        assert_eq!(&Chain::Mainnet.as_genesis_hash()[..], GENESIS_HASH_MAINNET);
        assert_eq!(
            &Chain::Testnet3.as_genesis_hash()[..],
            GENESIS_HASH_TESTNET
        );
        assert_eq!(
            &Chain::Regtest(
                BlockHash::from_slice(GENESIS_HASH_REGTEST).unwrap()
            )
            .as_genesis_hash()[..],
            GENESIS_HASH_REGTEST
        );
        assert_eq!(
            &Chain::Regtest(random_hash).as_genesis_hash()[..],
            &random_hash[..]
        );
        assert_eq!(&Chain::Signet.as_genesis_hash()[..], GENESIS_HASH_SIGNET);
        assert_eq!(
            &Chain::SignetCustom(
                BlockHash::from_slice(GENESIS_HASH_SIGNET).unwrap()
            )
            .as_genesis_hash()[..],
            GENESIS_HASH_SIGNET
        );
        assert_eq!(
            &Chain::SignetCustom(random_hash).as_genesis_hash()[..],
            &random_hash[..]
        );
        assert_eq!(
            &Chain::LiquidV1.as_genesis_hash()[..],
            GENESIS_HASH_LIQUIDV1
        );
        assert_eq!(
            &Chain::Other(Chain::Mainnet.chain_params()).as_genesis_hash()[..],
            GENESIS_HASH_MAINNET
        );
        let mut chain_params = Chain::Mainnet.chain_params();
        chain_params.genesis_hash = random_hash;
        assert_eq!(
            &Chain::Other(chain_params).as_genesis_hash()[..],
            &random_hash[..]
        );

        assert_eq!(
            Chain::from_genesis_hash(
                &BlockHash::from_slice(GENESIS_HASH_MAINNET).unwrap()
            )
            .unwrap(),
            Chain::Mainnet
        );
        assert_eq!(
            Chain::from_genesis_hash(
                &BlockHash::from_slice(GENESIS_HASH_TESTNET).unwrap()
            )
            .unwrap(),
            Chain::Testnet3
        );
        assert_eq!(
            Chain::from_genesis_hash(
                &BlockHash::from_slice(GENESIS_HASH_SIGNET).unwrap()
            )
            .unwrap(),
            Chain::Signet
        );
        assert_eq!(
            Chain::from_genesis_hash(
                &BlockHash::from_slice(GENESIS_HASH_LIQUIDV1).unwrap()
            )
            .unwrap(),
            Chain::LiquidV1
        );
        let regtest = Chain::from_genesis_hash(
            &BlockHash::from_slice(GENESIS_HASH_REGTEST).unwrap(),
        )
        .unwrap();
        assert_eq!(regtest, Chain::Regtest(*regtest.as_genesis_hash()));
        assert_ne!(regtest, Chain::Regtest(random_hash));
        assert_eq!(Chain::from_genesis_hash(&random_hash), None);
    }

    #[test]
    fn test_chains() {
        let random_hash = BlockHash::hash(b"rascafvsdg");

        assert_eq!(Chain::Mainnet, Chain::from(CHAIN_PARAMS_MAINNET.clone()));
        assert_eq!(Chain::Testnet3, Chain::from(CHAIN_PARAMS_TESTNET.clone()));
        assert_eq!(
            Chain::Regtest(CHAIN_PARAMS_REGTEST.genesis_hash),
            Chain::from(CHAIN_PARAMS_REGTEST.clone())
        );
        assert_ne!(
            Chain::Regtest(random_hash),
            Chain::from(CHAIN_PARAMS_REGTEST.clone())
        );
        assert_eq!(Chain::Signet, Chain::from(CHAIN_PARAMS_SIGNET.clone()));
        assert_eq!(
            Chain::SignetCustom(CHAIN_PARAMS_SIGNET.genesis_hash),
            Chain::from(CHAIN_PARAMS_SIGNET.clone())
        );
        assert_ne!(
            Chain::SignetCustom(random_hash),
            Chain::from(CHAIN_PARAMS_SIGNET.clone())
        );
        assert_eq!(Chain::LiquidV1, Chain::from(CHAIN_PARAMS_LIQUIDV1.clone()));

        assert_eq!(Chain::Mainnet, Chain::from(bitcoin::Network::Bitcoin));
        assert_eq!(Chain::Testnet3, Chain::from(bitcoin::Network::Testnet));
        assert_eq!(
            Chain::Regtest(CHAIN_PARAMS_REGTEST.genesis_hash),
            Chain::from(bitcoin::Network::Regtest)
        );

        assert_eq!(
            bitcoin::Network::try_from(Chain::Mainnet).unwrap(),
            bitcoin::Network::Bitcoin
        );
        assert_eq!(
            bitcoin::Network::try_from(Chain::Testnet3).unwrap(),
            bitcoin::Network::Testnet
        );
        assert_eq!(
            bitcoin::Network::try_from(Chain::Regtest(
                CHAIN_PARAMS_REGTEST.genesis_hash
            ))
            .unwrap(),
            bitcoin::Network::Regtest
        );
        assert_eq!(
            bitcoin::Network::try_from(Chain::Regtest(
                CHAIN_PARAMS_SIGNET.genesis_hash
            ))
            .unwrap_err(),
            ConversionImpossibleError
        );
        assert_eq!(
            bitcoin::Network::try_from(Chain::SignetCustom(
                CHAIN_PARAMS_REGTEST.genesis_hash
            ))
            .unwrap_err(),
            ConversionImpossibleError
        );
        assert_eq!(
            bitcoin::Network::try_from(Chain::Regtest(random_hash))
                .unwrap_err(),
            ConversionImpossibleError
        );
        assert_eq!(
            bitcoin::Network::try_from(Chain::SignetCustom(random_hash))
                .unwrap_err(),
            ConversionImpossibleError
        );
    }

    #[test]
    fn test_chains_display() {
        let custom_hash = BlockHash::hash(b"00350429507202701943");
        assert_eq!(format!("{}", Chain::Mainnet), "bitcoin");
        assert_eq!(format!("{}", Chain::Testnet3), "testnet");
        assert_eq!(format!("{}", Chain::Signet), "signet");
        assert_eq!(format!("{}", Chain::LiquidV1), "liquidv1");
        assert_eq!(
            format!("{}", Chain::Regtest(CHAIN_PARAMS_REGTEST.genesis_hash)),
            "regtest"
        );
        assert_eq!(
            format!(
                "{}",
                Chain::SignetCustom(CHAIN_PARAMS_SIGNET.genesis_hash)
            ),
            "signet"
        );
        assert_eq!(
            format!("{}", Chain::Regtest(custom_hash)),
            format!("regtest:{}", custom_hash)
        );
        assert_eq!(
            format!("{}", Chain::SignetCustom(custom_hash)),
            format!("signet:{}", custom_hash)
        );

        assert_eq!(
            format!("{}", Chain::Other(CHAIN_PARAMS_MAINNET.clone())),
            "bitcoin"
        );
        assert_eq!(
            format!("{}", Chain::Other(CHAIN_PARAMS_TESTNET.clone())),
            "testnet"
        );
        assert_eq!(
            format!("{}", Chain::Other(CHAIN_PARAMS_REGTEST.clone())),
            "regtest"
        );
        assert_eq!(
            format!("{}", Chain::Other(CHAIN_PARAMS_SIGNET.clone())),
            "signet"
        );
        assert_eq!(
            format!("{}", Chain::Other(CHAIN_PARAMS_LIQUIDV1.clone())),
            "liquidv1"
        );

        let mut custom_params = CHAIN_PARAMS_MAINNET.clone();
        custom_params.genesis_hash = custom_hash;
        assert_eq!(format!("{}", Chain::Other(custom_params.clone())), "other:0e1b741ef47d9c526fd4a3a67b421ed924feb5a31deb485eb9a67e19495269a20700626974636f696ef9beb4d904006d61696e020062638d208c20b4b2070010eb090000220200000000000003004254430700426974636f696e07007361746f73686900e1f505000000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000000001");

        assert_eq!(Chain::from_str("bitcoin").unwrap(), Chain::Mainnet);
        assert_eq!(Chain::from_str("testnet").unwrap(), Chain::Testnet3);
        assert_eq!(
            Chain::from_str("regtest").unwrap(),
            Chain::Regtest(CHAIN_PARAMS_REGTEST.genesis_hash)
        );
        assert_eq!(
            Chain::from_str(
                "regtest:a2695249197ea6b95e48eb1da3b5fe24d91e427ba6a3d46f529c7df41e741b0e"
            )
            .unwrap(),
            Chain::Regtest(custom_hash)
        );
        assert_eq!(Chain::from_str("signet").unwrap(), Chain::Signet);
        assert_eq!(
            Chain::from_str(
                "signet:a2695249197ea6b95e48eb1da3b5fe24d91e427ba6a3d46f529c7df41e741b0e"
            )
            .unwrap(),
            Chain::SignetCustom(custom_hash)
        );
        assert_eq!(Chain::from_str("liquidv1").unwrap(), Chain::LiquidV1);

        assert_eq!(Chain::from_str("Bitcoin").unwrap(), Chain::Mainnet);
        assert_eq!(Chain::from_str("bItcOin").unwrap(), Chain::Mainnet);

        assert_eq!(Chain::from_str("bc").unwrap(), Chain::Mainnet);
        assert_eq!(Chain::from_str("main").unwrap(), Chain::Mainnet);

        assert_eq!(
            Chain::from_str("aljsic").unwrap_err(),
            ParseError::WrongNetworkName
        );
        assert_eq!(
            Chain::from_str("other:0e1b741ef47d9c526fd4a3a67b421ed924feb5a31deb485eb9a67e19495269a20700626974636f696ef9beb4d904006d61696e020062638d208c20b4b2070010eb090000220200000000000003004254430700426974636f696e07007361746f73686900e1f505000000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000000001").unwrap(),
            Chain::Other(custom_params)
        );
    }
}
