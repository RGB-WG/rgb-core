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

use bitcoin::hash_types::PubkeyHash;
use bitcoin::secp256k1;
use core::cell::RefCell;

use super::pubkey::PubkeyCommitment;
use super::Error;
use crate::bp::scripts::LockScript;
use crate::primitives::commit_verify::CommitEmbedVerify;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
pub struct LockscriptContainer {
    pub script: LockScript,
    pub pubkey: secp256k1::PublicKey,
}

wrapper!(
    LockscriptCommitment,
    LockScript,
    doc = "LockScript contanining public keys which sum is commit to some message according to LNPBP-2",
    derive = [PartialEq, Eq, Hash]
);

impl<MSG> CommitEmbedVerify<MSG> for LockscriptCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = LockscriptContainer;
    type Error = Error;

    fn commit_embed(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        let original_hash = bitcoin::PublicKey {
            compressed: false,
            key: container.pubkey,
        }
        .pubkey_hash();
        let tweaked_pk = PubkeyCommitment::commit_embed(container.pubkey, msg)?;
        let tweaked_hash = bitcoin::PublicKey {
            compressed: false,
            key: *tweaked_pk,
        }
        .pubkey_hash();
        let found = RefCell::new(0);
        let lockscript = container.script.replace_pubkeys_and_hashes(
            |pubkey: secp256k1::PublicKey| match pubkey == container.pubkey {
                true => {
                    *found.borrow_mut() += 1;
                    Some(*tweaked_pk)
                }
                false => Some(pubkey),
            },
            |hash: PubkeyHash| match hash == original_hash {
                true => {
                    *found.borrow_mut() += 1;
                    Some(tweaked_hash)
                }
                false => Some(hash),
            },
        )?;
        if *found.borrow() == 0 {
            Err(Error::LockscriptKeyNotFound)
        } else {
            Ok(Self(lockscript))
        }
    }
}
