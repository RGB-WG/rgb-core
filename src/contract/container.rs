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

use std::io::Write;

use bitcoin_hashes::{sha256, sha256t};
use commit_verify::{
    commit_encode, CommitConceal, CommitEncode, CommitVerify, ConsensusCommit, PrehashedProtocol,
    TaggedHash,
};
use stens::AsciiString;
use strict_encoding::{strict_serialize, StrictEncode};

use crate::{ConfidentialState, RevealedState};

// TODO: Update the value
// "rgb:container:id"
static MIDSTATE_CONTAINER_ID: [u8; 32] = [
    148, 72, 59, 59, 150, 173, 163, 140, 159, 237, 69, 118, 104, 132, 194, 110, 250, 108, 1, 140,
    74, 248, 152, 205, 70, 32, 184, 87, 20, 102, 127, 20,
];
// TODO: Update the value
// "rgb:container:confidential"
static MIDSTATE_CONFIDENTIAL_CONTAINER: [u8; 32] = [
    148, 72, 59, 59, 150, 173, 163, 140, 159, 237, 69, 118, 104, 132, 194, 110, 250, 108, 1, 140,
    74, 248, 152, 205, 70, 32, 184, 87, 20, 102, 127, 20,
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

impl CommitEncode for Confidential {
    fn commit_encode<E: Write>(&self, e: E) -> usize {
        let _ = ContainerId::commit(&self.0).strict_encode(e);
        32
    }
}

impl ConsensusCommit for Confidential {
    type Commitment = ContainerId;
}

impl ConfidentialState for Confidential {}

impl Confidential {
    pub fn container_id(&self) -> ContainerId { self.consensus_commit() }
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, AsAny)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
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
