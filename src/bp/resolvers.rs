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

//! Resolvers are traits allow accessing or computing information from a
//! bitcoin transaction graph (from blockchain, state channel, index, PSBT etc).

use bitcoin::{TxOut, Txid};

/// Errors happening when PSBT or other resolver information does not match the
/// structure of bitcoin transaction
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum MatchError {
    /// No `witness_utxo` and `non_witness_utxo` is provided for input {_0}
    NoInputTx(usize),

    /// Provided `non_witness_utxo` {_1} does not match transaction input {_0}
    NoTxidMatch(usize, Txid),

    /// Number of transaction inputs does not match number of the provided PSBT
    /// input data for input {_0}
    UnmatchingInputNumber(usize),

    /// Transaciton has less than {_0} inputs
    WrongInputNo(usize),
}

/// API for accessing previous transaction output data
pub trait InputPreviousTxo {
    /// Returns [`TxOut`] reference returned by resolver, if any, or reports
    /// specific matching error prevented from getting the output
    fn input_previous_txo(&self, index: usize) -> Result<&TxOut, MatchError>;
}

/// Errors happening during fee computation
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum FeeError {
    /// No input source information found because of wrong or incomplete PSBT
    /// structure
    #[from]
    MatchError(MatchError),

    /// Sum of inputs is less than sum of outputs
    InputsLessThanOutputs,
}

/// Fee computing resolver
pub trait Fee {
    /// Returns fee for a transaction, or returns error reporting resolver
    /// problem or wrong transaction structure
    fn fee(&self) -> Result<u64, FeeError>;
}
