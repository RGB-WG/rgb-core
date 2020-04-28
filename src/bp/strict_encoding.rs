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

use super::{blind::OutpointHash, blind::OutpointReveal, Network, ShortId};
use crate::strict_encoding::{Error, StrictDecode, StrictEncode, WithBitcoinEncoding};
use bitcoin::{secp256k1, Txid};
use std::io;

impl WithBitcoinEncoding for Txid {}
impl WithBitcoinEncoding for OutpointHash {}

impl StrictEncode for secp256k1::PublicKey {
    type Error = Error;
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.serialize())?)
    }
}

impl StrictDecode for secp256k1::PublicKey {
    type Error = Error;
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::from_slice(&buf)
            .map_err(|_| Error::DataIntegrityError("invalid public key data".to_string()))?)
    }
}

impl StrictEncode for secp256k1::Signature {
    type Error = Error;
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.serialize_compact())?)
    }
}

impl StrictDecode for secp256k1::Signature {
    type Error = Error;
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::from_compact(&buf).map_err(|_| {
            Error::DataIntegrityError("Invalid secp256k1 signature data".to_string())
        })?)
    }
}

impl StrictEncode for Network {
    type Error = Error;
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        Ok(self.as_magic().strict_encode(e)?)
    }
}

impl StrictDecode for Network {
    type Error = Error;
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_magic(u32::strict_decode(d)?))
    }
}

impl StrictEncode for ShortId {
    type Error = Error;
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.into_u64().strict_encode(e)
    }
}

impl StrictDecode for ShortId {
    type Error = Error;
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from(u64::strict_decode(d)?))
    }
}

impl StrictEncode for OutpointReveal {
    type Error = Error;

    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
        Ok(strict_encode_list!(e; self.blinding, self.txid, self.vout))
    }
}

impl StrictDecode for OutpointReveal {
    type Error = Error;

    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self {
            blinding: u64::strict_decode(&mut d)?,
            txid: Txid::strict_decode(&mut d)?,
            vout: u16::strict_decode(&mut d)?,
        })
    }
}
