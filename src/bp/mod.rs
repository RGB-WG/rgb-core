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

#[allow(unused_variables)]
pub mod bip32;
pub mod blind;
pub mod chain;
pub mod dbc;
pub mod lex_order;
pub mod psbt;
pub mod resolvers;
pub mod scripts;
pub mod seals;
pub mod short_id;
mod slice32;
mod strict_encoding;
pub mod tagged_hash;

pub use bip32::{DerivationInfo, DerivationTemplate};
pub use chain::{Chain, P2pNetworkId};
pub use lex_order::LexOrder;
pub use psbt::Psbt;
pub use scripts::{
    GenerateScripts, LockScript, PubkeyParseError, PubkeyScript, RedeemScript,
    ScriptPubkeyContent, ScriptPubkeyFormat, ScriptPubkeyStructure,
    ScriptPubkeyTemplate, ScriptSet, Strategy, Witness, WitnessProgram,
    WitnessScript, WitnessVersion,
};
pub use seals::TxoutSeal;
pub use short_id::ShortId;
pub use slice32::Slice32;

// TODO: (v0.2) Move hash-lock types from LNP mod

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display(Debug)]
#[non_exhaustive]
pub enum Challenge {
    Signature(bitcoin::PublicKey),
    Multisig(u32, Vec<bitcoin::PublicKey>),
    Custom(LockScript),
}

#[cfg(test)]
pub mod test {
    use crate::SECP256K1;
    use bitcoin::secp256k1;

    pub fn gen_secp_pubkeys(n: usize) -> Vec<secp256k1::PublicKey> {
        let mut ret = Vec::with_capacity(n);
        let mut sk = [0; 32];

        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            ret.push(secp256k1::PublicKey::from_secret_key(
                &SECP256K1,
                &secp256k1::SecretKey::from_slice(&sk[..]).unwrap(),
            ));
        }
        ret
    }

    pub fn gen_bitcoin_pubkeys(
        n: usize,
        compressed: bool,
    ) -> Vec<bitcoin::PublicKey> {
        gen_secp_pubkeys(n)
            .into_iter()
            .map(|key| bitcoin::PublicKey { key, compressed })
            .collect()
    }
}
