// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use bitcoin::hashes::{sha256, sha256t};
use commit_verify::{
    commit_encode, CommitConceal, CommitVerify, ConsensusCommit, PrehashedProtocol, TaggedHash,
};
use stens::AsciiString;
use strict_encoding::{strict_serialize, StrictEncode};

use crate::{ConfidentialState, RevealedState};

// "rgb:container:id"
static MIDSTATE_CONTAINER_ID: [u8; 32] = [
    12, 61, 136, 60, 191, 129, 135, 229, 141, 35, 41, 161, 203, 125, 0, 101, 109, 136, 50, 236, 7,
    101, 59, 39, 148, 207, 63, 236, 255, 48, 24, 171,
];
// "rgb:container:confidential"
static MIDSTATE_CONFIDENTIAL_CONTAINER: [u8; 32] = [
    91, 91, 44, 25, 205, 155, 231, 106, 244, 163, 175, 204, 49, 17, 129, 52, 227, 151, 9, 5, 246,
    42, 1, 226, 126, 43, 141, 177, 84, 100, 61, 108,
];

/// Tag used for [`ContainerId`] hash type
pub struct ContainerIdTag;

impl sha256t::Tag for ContainerIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_CONTAINER_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Unique data container identifier
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From)]
#[derive(StrictEncode, StrictDecode)]
#[wrapper(Debug, Display)]
pub struct ContainerId(sha256t::Hash<ContainerIdTag>);

impl<Msg> CommitVerify<Msg, PrehashedProtocol> for ContainerId
where Msg: AsRef<[u8]>
{
    #[inline]
    fn commit(msg: &Msg) -> ContainerId { ContainerId::hash(msg) }
}

/// Tag used for [`ContainerId`] hash type
pub struct ConfidentialContainerTag;

impl sha256t::Tag for ConfidentialContainerTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_CONFIDENTIAL_CONTAINER);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Confidential representation of data container information
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From, AsAny)]
#[derive(StrictEncode, StrictDecode)]
#[wrapper(Debug, Display)]
pub struct Confidential(sha256t::Hash<ConfidentialContainerTag>);

impl commit_encode::Strategy for Confidential {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl ConsensusCommit for Confidential {
    type Commitment = ContainerId;
}

impl ConfidentialState for Confidential {}

impl Confidential {
    pub fn container_id(&self) -> ContainerId { self.consensus_commit() }
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, AsAny, Display)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display("{id}~{mime}")]
pub struct Revealed {
    pub id: ContainerId,
    pub mime: AsciiString,
    pub salt: u64,
}

impl CommitConceal for Revealed {
    type ConcealedCommitment = Confidential;

    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        Confidential::hash(
            &strict_serialize(self).expect("Encoding of predefined data types must not fail"),
        )
    }
}
impl commit_encode::Strategy for Revealed {
    type Strategy = commit_encode::strategies::UsingConceal;
}

impl RevealedState for Revealed {}

#[cfg(test)]
mod test {
    use amplify::Wrapper;
    use commit_verify::tagged_hash;

    use super::*;

    #[test]
    fn test_container_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:container:id");
        assert_eq!(midstate.into_inner().into_inner(), MIDSTATE_CONTAINER_ID);
    }

    #[test]
    fn test_confidential_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:container:confidential");
        assert_eq!(
            midstate.into_inner().into_inner(),
            MIDSTATE_CONFIDENTIAL_CONTAINER
        );
    }
}
