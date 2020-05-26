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

use bitcoin::hashes::core::fmt::Formatter;
use std::{convert::TryFrom, fmt, str::FromStr};

pub type MagicNumber = u32;

/// A set of recommended standard networks. Differs from bitcoin::Network in
/// ability to support non-standard and non-predefined networks
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[repr(u32)]
pub enum Network {
    Mainnet = 0xD9B4BEF9,
    Testnet = 0x0709110B,
    Regtest = 0xDAB5BFFA,
    Signet = 0xA553C67E,
    Other(MagicNumber),
}

impl Network {
    pub fn all_known() -> Vec<Network> {
        use Network::*;
        vec![Mainnet, Testnet, Regtest, Signet]
    }

    pub fn all_magic() -> Vec<MagicNumber> {
        Self::all_known().iter().map(Network::as_magic).collect()
    }

    pub fn from_magic(magic: MagicNumber) -> Self {
        match magic {
            m if m == Network::Mainnet.as_magic() => Network::Mainnet,
            m if m == Network::Testnet.as_magic() => Network::Testnet,
            m if m == Network::Regtest.as_magic() => Network::Regtest,
            m if m == Network::Signet.as_magic() => Network::Signet,
            m => Network::Other(m),
        }
    }

    pub fn as_magic(&self) -> MagicNumber {
        // FIXME: Something is going wrong here
        use std::mem;
        let m;
        unsafe {
            m = mem::transmute::<Self, u64>(self.clone());
        }
        m as u32
    }
}

impl From<MagicNumber> for Network {
    fn from(magic: MagicNumber) -> Self {
        Network::from_magic(magic)
    }
}

impl From<Network> for MagicNumber {
    fn from(network: Network) -> Self {
        network.as_magic()
    }
}

impl From<bitcoin::Network> for Network {
    fn from(bn: bitcoin::Network) -> Self {
        match bn {
            bitcoin::Network::Bitcoin => Network::Mainnet,
            bitcoin::Network::Testnet => Network::Testnet,
            bitcoin::Network::Regtest => Network::Regtest,
            bitcoin::Network::Signet => Network::Signet,
        }
    }
}

impl TryFrom<Network> for bitcoin::Network {
    type Error = ();
    fn try_from(bn: Network) -> Result<Self, Self::Error> {
        Ok(match bn {
            Network::Mainnet => bitcoin::Network::Bitcoin,
            Network::Testnet => bitcoin::Network::Testnet,
            Network::Regtest => bitcoin::Network::Regtest,
            Network::Signet => bitcoin::Network::Signet,
            _ => Err(())?,
        })
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Other(magic) => write!(f, "magic:{:x?}", magic),
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
            Network::Regtest => write!(f, "regtest"),
            Network::Signet => write!(f, "signet"),
        }
    }
}

impl fmt::Debug for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Network::Other(magic) => write!(f, "magic:{:x?}", magic),
            Network::Mainnet | Network::Testnet | Network::Regtest | Network::Signet => {
                write!(f, "{} (magic:{:x?})", self, self.as_magic())
            }
        }
    }
}

#[derive(Debug, Display)]
#[display_from(Debug)]
pub struct ParseError;

impl FromStr for Network {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_ascii_lowercase();
        bitcoin::Network::from_str(&s)
            .map(Network::from)
            .or_else(|_| {
                let s = s.strip_prefix("magic:").unwrap_or(&s);
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let magic = u32::from_str_radix(s, 16).map_err(|_| ParseError)?;
                Ok(Network::Other(magic))
            })
    }
}
