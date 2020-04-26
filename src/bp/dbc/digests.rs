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

use crate::commit_verify::CommitVerify;
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
    use crate::commit_verify::test::*;
    use bitcoin::hashes::*;

    #[test]
    fn test_sha256_commitment() {
        commit_verify_suite::<Vec<u8>, sha256::Hash>(gen_messages());
    }

    #[test]
    fn test_sha256d_commitment() {
        commit_verify_suite::<Vec<u8>, sha256d::Hash>(gen_messages());
    }

    #[test]
    fn test_ripemd160_commitment() {
        commit_verify_suite::<Vec<u8>, ripemd160::Hash>(gen_messages());
    }

    #[test]
    fn test_hash160_commitment() {
        commit_verify_suite::<Vec<u8>, hash160::Hash>(gen_messages());
    }

    #[test]
    fn test_sha1_commitment() {
        commit_verify_suite::<Vec<u8>, sha1::Hash>(gen_messages());
    }

    #[test]
    fn test_sha512_commitment() {
        commit_verify_suite::<Vec<u8>, sha512::Hash>(gen_messages());
    }

    #[test]
    fn test_siphash24_commitment() {
        commit_verify_suite::<Vec<u8>, siphash24::Hash>(gen_messages());
    }
}
