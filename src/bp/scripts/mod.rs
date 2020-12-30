// LNP/BP Core Library implementing LNPBP specifications & standards
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

mod pubkey_parser;
pub mod script_pubkey;
pub mod tweak;
pub mod types;

//pub use error::Error;
pub use pubkey_parser::PubkeyParseError;
pub use script_pubkey::{
    Error, ScriptPubkeyContent, ScriptPubkeyFormat, ScriptPubkeyStructure,
    ScriptPubkeyTemplate,
};
pub use types::{
    GenerateScripts, LockScript, PubkeyScript, RedeemScript, ScriptSet,
    Strategy, Witness, WitnessProgram, WitnessScript, WitnessVersion,
};
