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

pub use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
pub use bitcoin::util::psbt::{raw, Error, Global, Input, Map, Output};

use bitcoin::TxOut;

use super::resolvers::{Fee, FeeError, InputPreviousTxo, MatchError};

impl InputPreviousTxo for Psbt {
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

impl Fee for Psbt {
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
