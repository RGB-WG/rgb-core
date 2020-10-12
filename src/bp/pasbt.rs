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

//! PSBT extensions, including implementation of different
//! [`crate::bp::resolvers`] and enhancements related to key management

use bitcoin::util::psbt::{raw, Map, PartiallySignedTransaction};
use bitcoin::TxOut;

use super::resolvers::{Fee, FeeError, InputPreviousTxo, MatchError};
use crate::strict_encoding::{
    strict_decode, strict_encode, StrictDecode, StrictEncode,
};

fn proprietary_key(
    vendor: Vec<u8>,
    subtype: impl Into<u8>,
    key: Vec<u8>,
) -> raw::Key {
    let mut data = vendor;
    data.extend(&[subtype.into()]);
    data.extend(key);
    raw::Key {
        type_value: 0xFE,
        key: data,
    }
}

pub trait ProprietaryKeyMap {
    fn proprietary_key<T>(
        &self,
        vendor: Vec<u8>,
        subtype: impl Into<u8>,
        key: Vec<u8>,
    ) -> Option<T>
    where
        T: StrictDecode;

    fn insert_proprietary_key(
        &mut self,
        vendor: Vec<u8>,
        subtype: impl Into<u8>,
        key: Vec<u8>,
        value: &impl StrictEncode,
    ) -> bool;
}

impl<M> ProprietaryKeyMap for M
where
    M: Map,
{
    fn proprietary_key<T>(
        &self,
        vendor: Vec<u8>,
        subtype: impl Into<u8>,
        key: Vec<u8>,
    ) -> Option<T>
    where
        T: StrictDecode,
    {
        let key = proprietary_key(vendor, subtype, key);
        self.get_pairs().ok()?.iter().find_map(|pair| {
            if pair.key == key {
                strict_decode(&pair.value).ok()
            } else {
                None
            }
        })
    }

    fn insert_proprietary_key(
        &mut self,
        vendor: Vec<u8>,
        subtype: impl Into<u8>,
        key: Vec<u8>,
        value: &impl StrictEncode,
    ) -> bool {
        let key = proprietary_key(vendor, subtype, key);
        let value =
            strict_encode(value).expect("Memory encoders does not fail");
        self.insert_pair(raw::Pair { key, value })
            .map(|_| true)
            .unwrap_or(false)
    }
}

impl InputPreviousTxo for PartiallySignedTransaction {
    fn input_previous_txo(&self, index: usize) -> Result<&TxOut, MatchError> {
        if let (Some(input), Some(txin)) = (
            self.inputs.get(index),
            self.global.unsigned_tx.input.get(index),
        ) {
            let txid = txin.previous_output.txid;
            input
                .witness_utxo
                .as_ref()
                .ok_or(MatchError::NoInputTx(index))
                .or_else(|_| {
                    input
                        .non_witness_utxo
                        .as_ref()
                        .ok_or(MatchError::NoInputTx(index))
                        .and_then(|tx| {
                            if txid != tx.txid() {
                                Err(MatchError::NoTxidMatch(index, txid))
                            } else {
                                tx.output
                                    .get(txin.previous_output.vout as usize)
                                    .ok_or(MatchError::UnmatchingInputNumber(
                                        index,
                                    ))
                            }
                        })
                })
        } else {
            Err(MatchError::WrongInputNo(index))
        }
    }
}

impl Fee for PartiallySignedTransaction {
    fn fee(&self) -> Result<u64, FeeError> {
        let mut input_sum = 0;
        for index in 0..self.global.unsigned_tx.input.len() {
            input_sum += self.input_previous_txo(index)?.value;
        }

        let output_sum = self
            .global
            .unsigned_tx
            .output
            .iter()
            .map(|txout| txout.value)
            .sum();

        if input_sum < output_sum {
            Err(FeeError::InputsLessThanOutputs)
        } else {
            Ok(input_sum - output_sum)
        }
    }
}
