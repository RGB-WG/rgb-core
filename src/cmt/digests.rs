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

#[derive(Clone, PartialEq, Eq)]
pub struct DigestCommitment<HT: Hash>(HT);

impl<HT> Wrapper<HT> for DigestCommitment<HT> where
    HT: Hash
{
    #[inline]
    fn inner_ref(&self) -> &HT { &self.0 }
}

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

impl<HT, MSG> StandaloneCommitment<MSG> for DigestCommitment<HT> where
    HT: Hash,
    MSG: AsBytes + Committable<Self>
{
    #[inline]
    fn from(msg: &MSG) -> DigestCommitment<HT> {
        DigestCommitment(<HT as Hash>::hash(&msg[..]))
    }
}
