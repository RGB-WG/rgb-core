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

use bitcoin::hashes::{sha256d, Hash};

#[macro_use]
pub mod tagged256;
pub mod blind;
pub mod dbc;
pub mod network;
pub mod scripts;
mod seals;
pub mod short_id;
mod strict_encoding;

pub use network::{MagicNumber, Network};
pub use scripts::*;
pub use seals::*;
pub use short_id::*;

hash_newtype!(HashLock, sha256d::Hash, 32, doc = "Hashed locks in HTLC");
hash_newtype!(
    HashPreimage,
    sha256d::Hash,
    32,
    doc = "Pre-images for hashed locks in HTLC"
);

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
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

    pub fn gen_bitcoin_pubkeys(n: usize, compressed: bool) -> Vec<bitcoin::PublicKey> {
        gen_secp_pubkeys(n)
            .into_iter()
            .map(|key| bitcoin::PublicKey { key, compressed })
            .collect()
    }
}
