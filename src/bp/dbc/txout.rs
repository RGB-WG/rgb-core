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

use bitcoin::TxOut;

use super::{Container, Error, Proof, ScriptPubkeyContainer};
use crate::bp::scripts::PubkeyScript;
use crate::commit_verify::CommitEmbedVerify;

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct TxoutContainer {
    pub value: u64,
    pub script_container: ScriptPubkeyContainer,
}

impl Container for TxoutContainer {
    type Supplement = u64;
    type Commitment = TxOut;

    fn restore(
        proof: &Proof,
        supplement: &Self::Supplement,
        commitment: &Self::Commitment,
    ) -> Result<Self, Error> {
        Ok(Self {
            value: *supplement,
            script_container: ScriptPubkeyContainer::restore(
                proof,
                &None,
                &commitment.script_pubkey.clone().into(),
            )?,
        })
    }

    fn to_proof(&self) -> Proof {
        self.script_container.to_proof()
    }
}
impl<MSG> CommitEmbedVerify<MSG> for TxOut
where
    MSG: AsRef<[u8]>,
{
    type Container = TxoutContainer;
    type Error = Error;

    fn commit_embed(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        Ok(TxOut {
            value: container.value,
            script_pubkey: (*PubkeyScript::commit_embed(container.script_container, msg)?).clone(),
        })
    }
}
