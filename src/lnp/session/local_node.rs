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

use std::fmt::{self, Display, Formatter};

use bitcoin::secp256k1;
#[cfg(feature = "keygen")]
use bitcoin::secp256k1::rand::thread_rng;

use crate::SECP256K1;

/// Local node private keys
#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
#[lnpbp_crate(crate)]
pub struct LocalNode {
    private_key: secp256k1::SecretKey,
    ephemeral_private_key: secp256k1::SecretKey,
}

impl LocalNode {
    /// Constructs new set of private key by using random number generator
    #[cfg(feature = "keygen")]
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let private_key = secp256k1::SecretKey::new(&mut rng);
        let ephemeral_private_key = secp256k1::SecretKey::new(&mut rng);
        Self {
            private_key,
            ephemeral_private_key,
        }
    }

    pub fn from_keys(
        node_key: secp256k1::SecretKey,
        ephemeral_key: secp256k1::SecretKey,
    ) -> Self {
        Self {
            private_key: node_key,
            ephemeral_private_key: ephemeral_key,
        }
    }

    pub fn node_id(&self) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_secret_key(&SECP256K1, &self.private_key)
    }

    pub fn sign(&self, message: &secp256k1::Message) -> secp256k1::Signature {
        SECP256K1.sign(message, &self.private_key)
    }
}

impl Display for LocalNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "LocalNode({:#})", self.node_id())
        } else {
            write!(f, "{}", self.node_id())
        }
    }
}
