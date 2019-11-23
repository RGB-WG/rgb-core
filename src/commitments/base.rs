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

pub trait CommittableMessage {}
pub trait CommitmentContainer {}
pub trait CommitmentProofs {}
pub trait CommitmentEngine<MSG: CommittableMessage, CT: CommitmentContainer, PRF: CommitmentProofs> {
    fn commit(&self, message: &MSG, container: &mut CT) -> PRF;
    fn verify(&self, message: &MSG, container: &CT, proofs: &PRF) -> bool;
}
