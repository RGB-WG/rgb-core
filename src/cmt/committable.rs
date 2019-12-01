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

pub trait CommitmentVerify<MSG> where
    MSG: Verifiable<Self>,
    Self: Sized
{
    fn reveal_verify(&self, msg: &MSG) -> bool;
}

pub trait StandaloneCommitment<MSG>: CommitmentVerify<MSG> where
    MSG: Committable<Self>,
    Self: Eq + Sized
{
    fn from(msg: &MSG) -> Self;

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool { Self::from(msg) == *self }
}

pub trait EmbeddedCommitment<MSG>: CommitmentVerify<MSG> where
    MSG: EmbedCommittable<Self>,
    Self: Sized + Eq
{
    type Container;
    type Error;

    fn get_original_container(&self) -> &Self::Container;
    fn from(container: &Self::Container, msg: &MSG) -> Result<Self, Self::Error>;

    fn reveal_verify(&self, msg: &MSG) -> bool {
        match Self::from(self.get_original_container(), msg) {
            Ok(commitment) => commitment == *self,
            Err(_) => false
        }
    }
}


pub trait Verifiable<CMT: CommitmentVerify<Self>> where
    Self: Sized
{
    #[inline]
    fn verify(&self, commitment: &CMT) -> bool { commitment.reveal_verify(&self) }
}

pub trait Committable<CMT>: Verifiable<CMT> where
    CMT: StandaloneCommitment<Self>
{
    #[inline]
    fn commit(&self) -> CMT { CMT::from(&self) }
}

pub trait EmbedCommittable<CMT>: Verifiable<CMT> where
    CMT: EmbeddedCommitment<Self>
{
    #[inline]
    fn commit_embed(&self, container: &CMT::Container) -> Result<CMT, CMT::Error> {
        CMT::from(container, &self)
    }
}
