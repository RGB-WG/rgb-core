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

//! Base commit-verify scheme interface with extension allowing to create
//! embedded commitments (commit-embed-verify), required for detarministic
//! bitcoin commitments (LNPBP1-3 standards).

/// Trait for commit-verify scheme. A message for the commitment may be any
/// structure that can be represented as a byte array (i.e. implements
/// `AsRef<[u8]>`).
pub trait CommitVerify<MSG>
where
    MSG: AsRef<[u8]>,
    Self: Eq + Sized,
{
    /// Creates a commitment to a byte representation of a given message
    fn commit(msg: &MSG) -> Self;

    /// Verifies commitment against the message; default implementation just
    /// repeats the commitment to the message and check it against the `self`.
    #[inline]
    fn verify(&self, msg: &MSG) -> bool {
        Self::commit(msg) == *self
    }
}

/// Trait for commit-verify scheme when a commitment has to be embedded into
/// some data structure existing before the commitment process. Operates in the
/// form of `EmbedCommit: (Container, Message) -> Commitment` and
/// `Verify: (Commitment, Message) -> bool`; the commitment MUST contain
/// all the data required for reproducing the original container.
///
/// This trait is heavily used in **deterministic bitcoin commitments**
/// [crate::dbc] module implementations
pub trait CommitEmbedVerify<MSG>
where
    MSG: AsRef<[u8]>,
    Self: Sized + Eq,
{
    /// External container type that will be used to host commitment to a message
    type Container;
    /// Error type that may be reported during [commit_embed] procedure
    type Error;

    /// Creates a commitment and embeds it into the provided container returning
    /// `Self` containing both message commitment and all additional data required
    /// to reconstruct the original container
    fn commit_embed(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error>;

    /// Verifies commitment against the message; default implementation just
    /// reconstructs the original container with [container] function,
    /// repeats the commitment to the message and check it against the `self`.
    #[inline]
    fn verify(&self, container: Self::Container, msg: &MSG) -> bool {
        match Self::commit_embed(container, msg) {
            Ok(commitment) => commitment == *self,
            Err(_) => false,
        }
    }
}
