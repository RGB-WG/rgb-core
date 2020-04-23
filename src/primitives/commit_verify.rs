// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
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

pub trait CommitVerify<MSG>
where
    MSG: AsRef<[u8]>,
    Self: Eq + Sized,
{
    fn commit(msg: &MSG) -> Self;

    #[inline]
    fn verify(&self, msg: &MSG) -> bool {
        Self::commit(msg) == *self
    }
}

pub trait EmbedCommitVerify<MSG>
where
    MSG: AsRef<[u8]>,
    Self: Sized + Eq,
{
    type Container;
    type Error;

    fn container(&self) -> Self::Container;
    fn embed_commit(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error>;

    #[inline]
    fn verify(&self, msg: &MSG) -> bool {
        match Self::embed_commit(self.container(), msg) {
            Ok(commitment) => commitment == *self,
            Err(_) => false,
        }
    }
}
