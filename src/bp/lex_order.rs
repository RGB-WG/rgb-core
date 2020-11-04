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

//! Lexicographic sorting functions

use core::cmp::Ordering;

use bitcoin::{self, secp256k1};
use bitcoin::{
    util::psbt::PartiallySignedTransaction as Psbt, Transaction, TxIn, TxOut,
};

pub trait LexOrder {
    fn lex_order(&mut self);

    fn lex_ordered(mut self) -> Self
    where
        Self: Sized,
    {
        self.lex_order();
        self
    }
}

impl LexOrder for Vec<secp256k1::PublicKey> {
    fn lex_order(&mut self) {
        self.sort()
    }
}

impl LexOrder for Vec<bitcoin::PublicKey> {
    fn lex_order(&mut self) {
        self.sort()
    }
}

impl LexOrder for Vec<TxIn> {
    fn lex_order(&mut self) {
        self.sort_by_key(|txin| txin.previous_output)
    }
}

impl LexOrder for Vec<TxOut> {
    fn lex_order(&mut self) {
        self.sort_by(|left, right| txout_cmp(left, right))
    }
}

impl LexOrder for Transaction {
    fn lex_order(&mut self) {
        self.input.lex_order();
        self.output.lex_order();
    }
}

impl LexOrder for Psbt {
    fn lex_order(&mut self) {
        let tx = &mut self.global.unsigned_tx;
        let mut inputs = tx
            .input
            .clone()
            .into_iter()
            .zip(self.inputs.clone().into_iter())
            .collect::<Vec<(_, _)>>();
        inputs.sort_by_key(|(k, _)| k.previous_output);

        let mut outputs = tx
            .output
            .clone()
            .into_iter()
            .zip(self.outputs.clone().into_iter())
            .collect::<Vec<(_, _)>>();
        outputs.sort_by(|(a, _), (b, _)| txout_cmp(a, b));

        let (in_tx, in_map): (Vec<_>, Vec<_>) = inputs.into_iter().unzip();
        let (out_tx, out_map): (Vec<_>, Vec<_>) = outputs.into_iter().unzip();
        tx.input = in_tx;
        tx.output = out_tx;
        self.inputs = in_map;
        self.outputs = out_map;
    }
}

fn txout_cmp(left: &TxOut, right: &TxOut) -> Ordering {
    if left.value < right.value {
        Ordering::Less
    } else if left.value > right.value {
        Ordering::Greater
    } else {
        left.script_pubkey.cmp(&right.script_pubkey)
    }
}
