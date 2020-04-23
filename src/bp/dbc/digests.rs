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

use crate::primitives::commit_verify::CommitVerify;
use bitcoin::hashes::Hash;

impl<HT, MSG> CommitVerify<MSG> for HT
where
    HT: Hash,
    MSG: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &MSG) -> HT {
        From::from(<HT as Hash>::hash(msg.as_ref()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::hashes::{hex::ToHex, *};

    #[test]
    fn test_sha256_commitment() {
        let msg = "Message to commit to";
        let digest = sha256::Hash::hash(msg.as_ref());
        assert_eq!(
            digest.to_hex(),
            "868258ba45e46ac4ba141fe0eb6cd6251b4d0ee2c23e69cd99322505324672e4"
        );

        let commitment = sha256::Hash::commit(&msg);
        assert_eq!(digest, commitment);
        assert_eq!(commitment.verify(&msg), true);
    }
}
