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

use bitcoin::hashes::Hash;
use super::committable::*;
use crate::{AsBytes, Wrapper};

#[allow(type_alias_bounds)]
type DigestCommitment<HT: Hash> = Wrapper<HT>;


impl<HT, MSG> CommitmentVerify<MSG> for DigestCommitment<HT> where
    HT: Hash,
    MSG: AsBytes + Committable<Self>,
    Self: StandaloneCommitment<MSG>
{
    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <DigestCommitment<HT> as StandaloneCommitment<MSG>>::reveal_verify(&self, msg)
    }
}

/*
impl<HT, MSG> StandaloneCommitment<MSG> for DigestCommitment<HT> where
    HT: Hash,
    MSG: AsBytes + Committable<Self>
{
    #[inline]
    fn from(msg: &MSG) -> DigestCommitment<HT> {
        DigestCommitment::from(<HT as Hash>::hash(&msg[..]))
    }
}
*/