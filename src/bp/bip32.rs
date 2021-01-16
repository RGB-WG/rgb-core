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
use regex::Regex;
use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Display, Formatter};
use std::io;
use std::iter::FromIterator;
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::hashes::hash160;
use bitcoin::util::bip32::{
    self, ChainCode, ChildNumber, DerivationPath, Error, ExtendedPrivKey,
    ExtendedPubKey, Fingerprint,
};
use bitcoin::{secp256k1, PublicKey};
use miniscript::{DescriptorPublicKeyCtx, MiniscriptKey, ToPublicKey};

use crate::strict_encoding::{self, StrictDecode, StrictEncode};

/// Constant determining BIP32 boundary for u32 values after which index
/// is treated as hardened
pub const HARDENED_INDEX_BOUNDARY: u32 = 1 << 31;

/// Derivation path index is outside of the allowed range: 0..2^31 for
/// unhardened derivation and 2^31..2^32 for hardened
#[derive(
    Clone,
    Copy,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Default,
    Display,
    Error,
    From,
)]
#[display(doc_comments)]
#[from(bitcoin::util::bip32::Error)]
pub struct IndexOverflowError;

/// Index for unhardened children derivation; ensures that the wrapped value
/// < 2^31
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Default, Display, From,
)]
#[display(inner)]
pub struct UnhardenedIndex(
    #[from(u8)]
    #[from(u16)]
    u32,
);

impl UnhardenedIndex {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn one() -> Self {
        Self(1)
    }

    pub fn into_u32(self) -> u32 {
        self.0
    }

    pub fn try_increment(self) -> Result<Self, IndexOverflowError> {
        if self.0 >= HARDENED_INDEX_BOUNDARY {
            return Err(IndexOverflowError);
        }
        Ok(Self(self.0 + 1))
    }

    pub fn try_decrement(self) -> Result<Self, IndexOverflowError> {
        if self.0 == 0 {
            return Err(IndexOverflowError);
        }
        Ok(Self(self.0 - 1))
    }
}

// TODO: Replace with `#[derive(Into)]` & `#[into(u32)]` once apmplify_derive
//       will support into derivations
impl Into<u32> for UnhardenedIndex {
    fn into(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for UnhardenedIndex {
    type Error = IndexOverflowError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value >= HARDENED_INDEX_BOUNDARY {
            return Err(IndexOverflowError);
        }
        Ok(UnhardenedIndex(value))
    }
}

impl TryFrom<u64> for UnhardenedIndex {
    type Error = IndexOverflowError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > ::core::u32::MAX as u64 {
            return Err(IndexOverflowError);
        }
        (value as u32).try_into()
    }
}

impl TryFrom<usize> for UnhardenedIndex {
    type Error = IndexOverflowError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > ::core::u32::MAX as usize {
            return Err(IndexOverflowError);
        }
        (value as u32).try_into()
    }
}

impl From<UnhardenedIndex> for ChildNumber {
    fn from(idx: UnhardenedIndex) -> Self {
        ChildNumber::Normal { index: idx.0 }
    }
}

/// Index for hardened children derivation; ensures that the wrapped value
/// >= 2^31
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Default, Display,
)]
#[display("{0}'")]
pub struct HardenedIndex(u32);

impl HardenedIndex {
    pub fn zero() -> Self {
        Self(HARDENED_INDEX_BOUNDARY)
    }

    pub fn one() -> Self {
        Self(HARDENED_INDEX_BOUNDARY + 1)
    }

    pub fn from_ordinal(index: impl Into<u32>) -> Self {
        Self(index.into() | HARDENED_INDEX_BOUNDARY)
    }

    pub fn into_u32(self) -> u32 {
        self.0
    }

    pub fn into_ordinal(self) -> u32 {
        self.0 ^ HARDENED_INDEX_BOUNDARY
    }

    pub fn try_increment(self) -> Result<Self, IndexOverflowError> {
        if self.0 == ::core::u32::MAX {
            return Err(IndexOverflowError);
        }
        Ok(Self(self.0 + 1))
    }

    pub fn try_decrement(self) -> Result<Self, IndexOverflowError> {
        if self.0 <= HARDENED_INDEX_BOUNDARY {
            return Err(IndexOverflowError);
        }
        Ok(Self(self.0 - 1))
    }
}

// TODO: Replace with `#[derive(Into)]` & `#[into(u32)]` once apmplify_derive
//       will support into derivations
impl Into<u32> for HardenedIndex {
    fn into(self) -> u32 {
        self.0
    }
}

impl From<u8> for HardenedIndex {
    fn from(index: u8) -> Self {
        Self(index as u32 | HARDENED_INDEX_BOUNDARY)
    }
}

impl From<u16> for HardenedIndex {
    fn from(index: u16) -> Self {
        Self(index as u32 | HARDENED_INDEX_BOUNDARY)
    }
}

impl From<u32> for HardenedIndex {
    fn from(index: u32) -> Self {
        Self(index as u32 | HARDENED_INDEX_BOUNDARY)
    }
}

impl TryFrom<u64> for HardenedIndex {
    type Error = IndexOverflowError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > ::core::u32::MAX as u64 {
            return Err(IndexOverflowError);
        }
        Ok((value as u32).into())
    }
}

impl TryFrom<usize> for HardenedIndex {
    type Error = IndexOverflowError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > ::core::u32::MAX as usize {
            return Err(IndexOverflowError);
        }
        Ok((value as u32).into())
    }
}

impl From<HardenedIndex> for ChildNumber {
    fn from(index: HardenedIndex) -> Self {
        ChildNumber::Hardened {
            index: index.into_ordinal(),
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

impl IntoDerivationPath for Vec<u32> {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        Ok(self
            .into_iter()
            .map(ChildNumber::from)
            .collect::<Vec<_>>()
            .into())
    }
}

impl<'a> IntoDerivationPath for &'a [u32] {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        Ok(self
            .into_iter()
            .cloned()
            .map(ChildNumber::from)
            .collect::<Vec<_>>()
            .into())
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
// [master_xpub]/branch_path=[branch_xpub]/terminal_path/index_ranges
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
            None => ::core::u32::MAX,
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
        if f.alternate() {
            write!(f, "[{}]/", self.master_xpub.fingerprint())?;
        } else {
            write!(f, "[{}]/", self.master_xpub)?;
        }
        f.write_str(self.branch_path.to_string().trim_start_matches("m"))?;
        if f.alternate() {
            f.write_str("/")?;
        } else {
            write!(f, "=[{}]/", self.branch_xpub)?;
        }
        f.write_str(self.terminal_path().to_string().trim_start_matches("m"))?;
        if let Some(_) = self.index_ranges {
            f.write_str(&self.index_ranges_string())
        } else {
            f.write_str("*")
        }
    }
}

#[derive(
    Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
)]
#[display(inner)]
pub struct ComponentsParseError(pub String);

impl FromStr for DerivationComponents {
    type Err = ComponentsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref RE_DERIVATION: Regex = Regex::new(
                r"(?x)^
                \[(?P<xpub>[xyztuvXYZTUV]pub[1-9A-HJ-NP-Za-km-z]{107,108})\]
                (?P<deriv>(/[0-9]{1,10}[h']?)+)
                (/(?P<range>\*|([0-9]{1,10}([,-][0-9]{1,10})*)))?
                $",
            )
            .expect("Regexp expression for `DerivationComponents` is broken");
        }

        let mut split = s.split('=');
        let (branch, terminal) = match (split.next(), split.next(), split.next()) {
            (Some(branch), Some(terminal), None) => (Some(branch), terminal),
            (Some(terminal), None, None) => (None, terminal),
            (None, None, None) => unreachable!(),
            _ => Err(ComponentsParseError(s!("Derivation components string must contain at most two parts separated by `=`")))?
        };

        let caps = if let Some(caps) = RE_DERIVATION.captures(terminal) {
            caps
        } else {
            Err(ComponentsParseError(s!(
                "Wrong composition of derivation components data"
            )))?
        };

        let branch_xpub = ExtendedPubKey::from_str(
            caps.name("xpub").expect("regexp engine is broken").as_str(),
        )
        .map_err(|err| ComponentsParseError(err.to_string()))?;
        let terminal_path = caps
            .name("deriv")
            .expect("regexp engine is broken")
            .as_str();
        let terminal_path =
            DerivationPath::from_str(&format!("m/{}", terminal_path))
                .map_err(|err| ComponentsParseError(err.to_string()))?;
        let (prefix, terminal_path) = terminal_path.hardened_normal_split();
        if !prefix.as_ref().is_empty() {
            Err(ComponentsParseError(s!(
                "Terminal derivation path must not contain hardened keys"
            )))?;
        }
        let index_ranges = caps.name("range").and_then(|range| {
            let range = range.as_str();
            if range == "*" {
                return None;
            } else {
                Some(
                    range
                        .split(',')
                        .map(|item| {
                            let mut split = item.split('-');
                            let (start, end) =
                                match (split.next(), split.next()) {
                                    (Some(start), Some(end)) => (
                                        start
                                            .parse()
                                            .expect("regexp engine is broken"),
                                        end.parse()
                                            .expect("regexp engine is broken"),
                                    ),
                                    (Some(start), None) => {
                                        let idx: u32 = start
                                            .parse()
                                            .expect("regexp engine is broken");
                                        (idx, idx)
                                    }
                                    _ => unreachable!(),
                                };
                            DerivationRange::from_inner(RangeInclusive::new(
                                start, end,
                            ))
                        })
                        .collect(),
                )
            }
        });

        let (master_xpub, branch_path) = if let Some(caps) =
            branch.and_then(|branch| RE_DERIVATION.captures(branch))
        {
            let master_xpub = ExtendedPubKey::from_str(
                caps.name("xpub").expect("regexp engine is broken").as_str(),
            )
            .map_err(|err| ComponentsParseError(err.to_string()))?;
            let branch_path = caps
                .name("deriv")
                .expect("regexp engine is broken")
                .as_str();
            let branch_path =
                DerivationPath::from_str(&format!("m/{}", branch_path))
                    .map_err(|err| ComponentsParseError(err.to_string()))?;
            (master_xpub, branch_path)
        } else {
            (
                branch_xpub.clone(),
                DerivationPath::from(Vec::<ChildNumber>::new()),
            )
        };

        Ok(DerivationComponents {
            master_xpub,
            branch_path,
            branch_xpub,
            terminal_path,
            index_ranges,
        })
    }
}

impl MiniscriptKey for DerivationComponents {
    type Hash = Self;

    fn to_pubkeyhash(&self) -> Self::Hash {
        self.clone()
    }
}

/// Context information for deriving a public key from [`DerivationComponents`]
#[derive(Debug)]
pub struct DerivationComponentsCtx<'secp, C>
where
    C: 'secp + secp256k1::Verification,
{
    /// The underlying secp context
    pub secp_ctx: &'secp secp256k1::Secp256k1<C>,
    /// The child_number in case the descriptor is wildcard
    /// If the DescriptorPublicKey is not wildcard this field is not used.
    pub child_number: bip32::ChildNumber,
}

impl<'secp, C> From<DerivationComponentsCtx<'secp, C>>
    for DescriptorPublicKeyCtx<'secp, C>
where
    C: 'secp + secp256k1::Verification,
{
    fn from(dc: DerivationComponentsCtx<'secp, C>) -> Self {
        DescriptorPublicKeyCtx::new(dc.secp_ctx, dc.child_number)
    }
}

impl<'secp, C> Clone for DerivationComponentsCtx<'secp, C>
where
    C: 'secp + secp256k1::Verification,
{
    fn clone(&self) -> Self {
        Self {
            secp_ctx: &self.secp_ctx,
            child_number: self.child_number.clone(),
        }
    }
}

impl<'secp, C> Copy for DerivationComponentsCtx<'secp, C> where
    C: 'secp + secp256k1::Verification
{
}

impl<'secp, C> DerivationComponentsCtx<'secp, C>
where
    C: 'secp + secp256k1::Verification,
{
    /// Create a new context
    pub fn new(
        secp_ctx: &'secp secp256k1::Secp256k1<C>,
        child_number: bip32::ChildNumber,
    ) -> Self {
        Self {
            secp_ctx: secp_ctx,
            child_number: child_number,
        }
    }
}

impl<'secp, C> ToPublicKey<DerivationComponentsCtx<'secp, C>>
    for DerivationComponents
where
    C: 'secp + secp256k1::Verification,
{
    fn to_public_key(
        &self,
        to_pk_ctx: DerivationComponentsCtx<'secp, C>,
    ) -> PublicKey {
        let derivation_path = self
            .terminal_path
            .clone()
            .into_derivation_path()
            .expect("does not fail for vec/slices")
            .into_child(to_pk_ctx.child_number);
        self.branch_xpub
            .derive_pub(to_pk_ctx.secp_ctx, &derivation_path)
            .expect("unhardened derivation does not fail")
            .public_key
    }

    fn hash_to_hash160(
        hash: &Self::Hash,
        to_pk_ctx: DerivationComponentsCtx<'secp, C>,
    ) -> hash160::Hash {
        hash.to_public_key(to_pk_ctx).to_pubkeyhash()
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
