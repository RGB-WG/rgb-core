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

use super::{Container, Error, Proof, ScriptPubkeyCommitment, ScriptPubkeyContainer};
use crate::commit_verify::CommitEmbedVerify;

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct TxoutContainer {
    pub value: u64,
    pub script_container: ScriptPubkeyContainer,
}

impl Container for TxoutContainer {
    fn to_proof(&self) -> Proof {
        self.script_container.to_proof()
    }
}

wrapper!(
    TxoutCommitment,
    ScriptPubkeyCommitment,
    doc = "",
    derive = [PartialEq, Eq, Hash]
);

impl<MSG> CommitEmbedVerify<MSG> for TxoutCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = TxoutContainer;
    type Error = Error;

    fn commit_embed(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        Ok(Self(ScriptPubkeyCommitment::commit_embed(
            container.script_container,
            msg,
        )?))
    }
}
