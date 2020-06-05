// LNP/BP Rust Library
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


use bitcoin::OutPoint;
use bitcoin::hash_types::Txid;
use crate::bp::{
    short_id::ShortId,
    blind::{OutpointReveal, OutpointHash}
};

#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum Error {
    VoutOverflow,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, Default)]
#[display_from(Debug)]
pub struct Type(pub u16);


#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum Seal {
    /// Seal contained within the witness transaction
    WitnessTxout(u16),
    /// Seal that is revealed
    RevealedTxout(OutpointReveal, Option<ShortId>),
    /// Seal that is not revealed yet
    BlindedTxout(OutpointHash)
}

impl Seal {
    pub fn witness(vout: u16) -> Self {
        Self::WitnessTxout(vout)
    }
    pub fn revealed(txid: Txid, vout: u16, blinding: u64) -> Self {
        Seal::RevealedTxout(OutpointReveal { blinding, txid, vout, }, None)
    }
    pub fn outpoint_reveal(revealed_outpoint: OutpointReveal, short_id: Option<ShortId>) -> Self {
        Seal::RevealedTxout(revealed_outpoint, short_id)
    }
    pub fn maybe_from_outpoint(outpoint: bitcoin::OutPoint, blinding: u64) -> Option<Self> {
        let vout = outpoint.vout;
        if vout > std::u16::MAX as u32 {
            return None
        }
        Some(Seal::RevealedTxout(OutpointReveal { blinding, txid: outpoint.txid, vout: vout as u16 }, None))
    }
    pub fn blinded(hash: OutpointHash) -> Self {
        Seal::BlindedTxout(hash)
    }

    pub fn maybe_as_outpoint(&self, revealed_outpoint: Option<OutPoint>, creating_txid: Option<Txid>, blinding_key: Option<u64>) -> Option<OutPoint> {
        match self {
            Seal::WitnessTxout(vout) if creating_txid.is_some() => Some(OutPoint { txid: creating_txid.unwrap(), vout: *vout as u32 }),
            Seal::RevealedTxout(revealed, _) => Some(OutPoint { txid: revealed.txid, vout: revealed.vout as u32 }),
            Seal::BlindedTxout(hash) if revealed_outpoint.is_some() && blinding_key.is_some() => {
                match Seal::maybe_from_outpoint(revealed_outpoint.unwrap(), blinding_key.unwrap()) {
                    Some(Seal::RevealedTxout(revealed, _)) if revealed.outpoint_hash() == *hash => Some(OutPoint { txid: revealed.txid, vout: revealed.vout as u32 }),
                    _ => None
                }
            },
            _ => None
        }
    }

    pub fn compare_to_outpoint(&self, outpoint: &OutPoint, creating_txid: Option<Txid>, blinding_key: Option<u64>) -> bool {
        self
            .maybe_as_outpoint(Some(outpoint.clone()), creating_txid, blinding_key)
            .map_or(false, |out| out == *outpoint)
    }
}
