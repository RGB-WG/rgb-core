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

use bitcoin::secp256k1;
use miniscript::{Descriptor, Miniscript, Terminal};

use crate::bp::PubkeyScript;

impl PubkeyScript {
    pub fn with_ln_funding_v1(
        pubkey1: secp256k1::PublicKey,
        pubkey2: secp256k1::PublicKey,
    ) -> Self {
        // TODO: (v0.2) Make sure that miniscript does lexicographic ordering
        let lock = Terminal::Multi(
            2,
            vec![
                bitcoin::PublicKey {
                    compressed: true,
                    key: pubkey1,
                },
                bitcoin::PublicKey {
                    compressed: true,
                    key: pubkey2,
                },
            ],
        );
        let ms = Miniscript::from_ast(lock).expect(
            "miniscript library broken: parse of static miniscript failed",
        );
        Descriptor::Wsh(ms).script_pubkey().into()
    }
}
