// LNP/BP Rust Library
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


///! Common data types, structures and functions for LNPBPs

use bitcoin::Script;

/// Version used by `scriptPubKey` with SegWit support
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WitnessScriptVersion {
    LegacyP2SH,
    V0
}

/// Transaction `scriptPubKey` formats
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum OutputType {
    P2PK,
    P2PKH,
    P2WPH(WitnessScriptVersion),
    P2SH(WitnessScriptVersion),
    OpReturn,
    Empty,
    Invalid,
    OtherP2S(Script)
}
