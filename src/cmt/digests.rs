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

use std::marker::PhantomData;
use bitcoin::hashes::Hash;
use super::committable::*;
use crate::{AsSlice, Wrapper};


#[derive(Clone, Copy, Eq, PartialEq)]
struct _DigestCommitment<HT: Hash>(PhantomData<HT>);
#[allow(private_in_public, type_alias_bounds)]
pub type DigestCommitment<HT: Hash> = Wrapper<HT, _DigestCommitment<HT>>;


impl<HT, MSG> CommitmentVerify<MSG> for DigestCommitment<HT> where
    HT: Hash,
    MSG: AsSlice + Committable<Self>
{
    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <DigestCommitment<HT> as StandaloneCommitment<MSG>>::reveal_verify(&self, msg)
    }
}

impl<HT, MSG> StandaloneCommitment<MSG> for DigestCommitment<HT> where
    HT: Hash,
    MSG: AsSlice + Committable<Self>
{
    #[inline]
    fn commit_to(msg: &MSG) -> DigestCommitment<HT> {
        From::from(<HT as Hash>::hash(&msg.as_slice()))
    }
}


impl<T, HT> Verifiable<DigestCommitment<HT>> for T where HT: Hash, T: AsSlice { }

impl<T, HT> Committable<DigestCommitment<HT>> for T where HT: Hash, T: AsSlice { }


#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::hashes::{*, hex::ToHex};


    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct Message<'a>(&'a str);
    impl AsSlice for Message<'_> {
        fn as_slice(&self) -> &[u8] {
            &self.0.as_bytes()
        }
    }

    #[test]
    fn test_sha256_commitment() {
        let msg = Message("Message to commit to");
        let digest = sha256::Hash::hash(&msg.as_slice());
        assert_eq!(digest.to_hex(), "868258ba45e46ac4ba141fe0eb6cd6251b4d0ee2c23e69cd99322505324672e4");

        let commitment: DigestCommitment<sha256::Hash> = msg.commit();
        assert_eq!(digest, commitment.clone().into_inner());
        assert_eq!(msg.verify(&commitment), true);
    }
}