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

//! PSBT extensions

use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Txid;

use crate::strict_encoding::{StrictDecode, StrictEncode};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum FeeError {
    /// No `witness_utxo` and `non_witness_utxo` is provided for one of the
    /// input {_0}
    NoInputTx(Txid),

    /// Provided `non_witness_utxo` {_0} does not match transaction
    /// input {_0}
    NoTxidMatch(Txid),

    /// Sum of inputs is less than sum of outputs
    InputsLessThanOutputs,

    /// Number of transaction inputs does not match number of the provided PSBT
    /// input data
    UnmatchingInputNumber,
}

pub trait Fee {
    fn fee(&self) -> Result<u64, FeeError>;
}

impl Fee for PartiallySignedTransaction {
    fn fee(&self) -> Result<u64, FeeError> {
        let input_sum = self
            .inputs
            .iter()
            .zip(self.global.unsigned_tx.input.iter())
            .try_fold(0, |sum, (input, txin)| {
                let txid = txin.previous_output.txid;
                input
                    .witness_utxo
                    .as_ref()
                    .ok_or(FeeError::NoInputTx(txid))
                    .or_else(|_| {
                        input
                            .non_witness_utxo
                            .as_ref()
                            .ok_or(FeeError::NoInputTx(txid))
                            .and_then(|tx| {
                                if txid != tx.txid() {
                                    Err(FeeError::NoTxidMatch(txid))
                                } else {
                                    tx.output
                                        .get(txin.previous_output.vout as usize)
                                        .ok_or(FeeError::UnmatchingInputNumber)
                                }
                            })
                    })
                    .map(|txout| sum + txout.value)
            })?;

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
