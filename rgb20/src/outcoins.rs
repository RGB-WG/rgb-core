// RGB20 Library: fungible digital assets for bitcoin & lightning
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

use regex::Regex;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::num::{ParseFloatError, ParseIntError};
use std::str::FromStr;

use bitcoin::blockdata::transaction::ParseOutPointError;
use bitcoin::hashes::hex::FromHex;
use bitcoin::{OutPoint, Txid};
use lnpbp::seals::{OutpointHash, OutpointReveal};
use rgb::{AtomicValue, SealDefinition};

#[derive(Clone, Copy, Debug, Display, Error, From)]
#[display(doc_comments)]
#[from(ParseFloatError)]
#[from(ParseIntError)]
#[from(ParseOutPointError)]
#[from(bitcoin::hashes::hex::Error)]
#[from(lnpbp::bech32::Error)]
/// Error parsing data
pub struct ParseError;

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize,),
    serde(crate = "serde_crate")
)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
pub struct SealCoins {
    pub coins: AtomicValue,
    pub vout: u32,
    pub txid: Option<Txid>,
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize,),
    serde(crate = "serde_crate")
)]
#[display("{coins}@{outpoint}")]
#[strict_encoding_crate(lnpbp::strict_encoding)]
pub struct OutpointCoins {
    pub coins: AtomicValue,
    pub outpoint: OutPoint,
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize,),
    serde(crate = "serde_crate")
)]
#[display("{coins}@{seal_confidential}")]
#[strict_encoding_crate(lnpbp::strict_encoding)]
pub struct ConsealCoins {
    pub coins: AtomicValue,
    pub seal_confidential: OutpointHash,
}

impl SealCoins {
    pub fn seal_definition(&self) -> SealDefinition {
        use bitcoin::secp256k1::rand::{self, RngCore};
        let mut rng = rand::thread_rng();
        let entropy = rng.next_u64(); // Not an amount blinding factor but outpoint blinding
        match self.txid {
            Some(txid) => SealDefinition::TxOutpoint(OutpointReveal {
                blinding: entropy,
                txid,
                vout: self.vout,
            }),
            None => SealDefinition::WitnessVout {
                vout: self.vout,
                blinding: entropy,
            },
        }
    }
}

impl OutpointCoins {
    pub fn seal_definition(&self) -> SealDefinition {
        use bitcoin::secp256k1::rand::{self, RngCore};
        let mut rng = rand::thread_rng();
        let entropy = rng.next_u64(); // Not an amount blinding factor but outpoint blinding
        SealDefinition::TxOutpoint(OutpointReveal {
            blinding: entropy,
            txid: self.outpoint.txid,
            vout: self.outpoint.vout,
        })
    }
}

impl Display for SealCoins {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@", self.coins)?;
        if let Some(txid) = self.txid {
            write!(f, "{}:", txid)?;
        }
        f.write_str(&self.vout.to_string())
    }
}

impl FromStr for SealCoins {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: Get rig of regex dependency
        let re = Regex::new(
            r"(?x)
                ^(?P<coins>[\d_'`]+) # float amount
                @
                ((?P<txid>[a-f\d]{64}) # Txid
                :)
                (?P<vout>\d+)$ # Vout
            ",
        )
        .expect("Regex parse failure");
        if let Some(m) = re.captures(&s.to_ascii_lowercase()) {
            match (m.name("coins"), m.name("txid"), m.name("vout")) {
                (Some(amount), Some(txid), Some(vout)) => Ok(Self {
                    coins: amount.as_str().parse()?,
                    vout: vout.as_str().parse()?,
                    txid: Some(Txid::from_hex(txid.as_str())?),
                }),
                (Some(amount), None, Some(vout)) => Ok(Self {
                    coins: amount.as_str().parse()?,
                    vout: vout.as_str().parse()?,
                    txid: None,
                }),
                _ => Err(ParseError),
            }
        } else {
            Err(ParseError)
        }
    }
}

impl FromStr for OutpointCoins {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split('@');
        match (iter.next(), iter.next(), iter.next()) {
            (Some(amount), Some(outpoint), None) => Ok(Self {
                coins: amount.parse()?,
                outpoint: outpoint.parse()?,
            }),
            (Some(_), Some(_), _) => Err(ParseError),
            _ => Err(ParseError),
        }
    }
}

impl FromStr for ConsealCoins {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let re = Regex::new(
            r"(?x)
                ^(?P<coins>[\d_'`]+) # float amount
                @
                ((?P<seal>[a-f\d]{64}))$ # Confidential seal: outpoint hash
            ",
        )
        .expect("Regex parse failure");
        if let Some(m) = re.captures(&s.to_ascii_lowercase()) {
            match (m.name("coins"), m.name("seal")) {
                (Some(amount), Some(seal)) => Ok(Self {
                    coins: amount.as_str().parse()?,
                    seal_confidential: OutpointHash::from_str(seal.as_str())?,
                }),
                _ => Err(ParseError),
            }
        } else {
            Err(ParseError)
        }
    }
}
