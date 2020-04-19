// LNP/BP Rust Library
// Written in 202 by
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


use bitcoin::Txid;
use bitcoin::hashes::{Hash, sha256d};


/// Data required to generate or reveal the information about blinded
/// transaction outpoint
#[derive(Clone, PartialEq, PartialOrd, Debug, Display, Default)]
#[display_from(Debug)]
pub struct OutpointReveal {
    /// Blinding factor preventing rainbow table bruteforce attack based on
    /// the existing blockchain txid set
    pub blinding: u64,

    /// Txid that should be blinded
    pub txid: Txid,

    /// Tx output number that should be blinded
    pub vout: u16,
}


hash_newtype!(OutpointHash, sha256d::Hash, 32, doc="Blind version of transaction outpoint");
