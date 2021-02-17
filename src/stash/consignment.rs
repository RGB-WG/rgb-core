// LNP/BP Rust Library
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

use std::collections::BTreeSet;
use std::str::FromStr;

use bitcoin::hashes::{sha256, sha256t};
use bitcoin::Txid;
use lnpbp::bech32::{self, FromBech32Str, ToBech32String};
use lnpbp::client_side_validation::{
    commit_strategy, commit_verify::CommitVerify, CommitEncodeWithStrategy,
    ConsensusCommit,
};
use lnpbp::seals::OutpointReveal;
use lnpbp::TaggedHash;

use crate::{
    validation, Anchor, Extension, Genesis, Node, NodeId, Schema, SealEndpoint,
    Transition, Validator,
};

pub type ConsignmentEndpoints = Vec<(NodeId, SealEndpoint)>;
pub type TransitionData = Vec<(Anchor, Transition)>;
pub type ExtensionData = Vec<Extension>;

pub const RGB_CONSIGNMENT_VERSION: u16 = 0;

static MIDSTATE_CONSIGNMENT_ID: [u8; 32] = [
    8, 36, 37, 167, 51, 70, 76, 241, 171, 132, 169, 56, 76, 108, 174, 226, 197,
    98, 75, 254, 29, 125, 170, 233, 184, 121, 13, 183, 90, 51, 134, 6,
];

/// Tag used for [`NodeId`] and [`ContractId`] hash types
pub struct ConsignmentIdTag;

impl sha256t::Tag for ConsignmentIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_CONSIGNMENT_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Unique consignment identifier equivalent to the commitment hash
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Wrapper,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[wrapper(Debug, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[display(ConsignmentId::to_bech32_string)]
pub struct ConsignmentId(sha256t::Hash<ConsignmentIdTag>);

impl<MSG> CommitVerify<MSG> for ConsignmentId
where
    MSG: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &MSG) -> ConsignmentId {
        ConsignmentId::hash(msg)
    }
}

impl CommitEncodeWithStrategy for ConsignmentId {
    type Strategy = commit_strategy::UsingStrict;
}

impl bech32::Strategy for ConsignmentId {
    const HRP: &'static str = "id";
    type Strategy = bech32::strategies::UsingStrictEncoding;
}

impl FromStr for ConsignmentId {
    type Err = bech32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ConsignmentId::from_bech32_str(s)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, StrictEncode, StrictDecode)]
#[display(Consignment::to_bech32_string)]
pub struct Consignment {
    version: u16,
    pub genesis: Genesis,
    pub endpoints: ConsignmentEndpoints,
    pub state_transitions: TransitionData,
    pub state_extensions: ExtensionData,
}

impl lightning_encoding::Strategy for Consignment {
    type Strategy = lightning_encoding::strategies::AsStrict;
}

impl CommitEncodeWithStrategy for Consignment {
    type Strategy = commit_strategy::UsingStrict;
}

impl ConsensusCommit for Consignment {
    type Commitment = ConsignmentId;
}

impl bech32::Strategy for Consignment {
    const HRP: &'static str = "consignment";
    type Strategy = bech32::strategies::CompressedStrictEncoding;
}

impl FromStr for Consignment {
    type Err = bech32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Consignment::from_bech32_str(s)
    }
}

impl Consignment {
    #[inline]
    pub fn with(
        genesis: Genesis,
        endpoints: ConsignmentEndpoints,
        state_transitions: TransitionData,
        state_extensions: ExtensionData,
    ) -> Consignment {
        Self {
            version: RGB_CONSIGNMENT_VERSION,
            genesis,
            endpoints,
            state_extensions,
            state_transitions,
        }
    }

    #[inline]
    pub fn id(&self) -> ConsignmentId {
        self.clone().consensus_commit()
    }

    #[inline]
    pub fn txids(&self) -> BTreeSet<Txid> {
        self.state_transitions
            .iter()
            .map(|(anchor, _)| anchor.txid)
            .collect()
    }

    #[inline]
    pub fn node_ids(&self) -> BTreeSet<NodeId> {
        let mut set = bset![self.genesis.node_id()];
        set.extend(
            self.state_transitions
                .iter()
                .map(|(_, node)| node.node_id()),
        );
        set.extend(self.state_extensions.iter().map(Extension::node_id));
        set
    }

    pub fn validate<R: validation::TxResolver>(
        &self,
        schema: &Schema,
        resolver: R,
    ) -> validation::Status {
        Validator::validate(schema, self, resolver)
    }

    /// Reveals previously known seal information (replacing blind UTXOs with
    /// unblind ones). Function is used when a peer receives consignment
    /// containing concealed seals for the outputs owned by the peer
    pub fn reveal_seals<'a>(
        &mut self,
        known_seals: impl Iterator<Item = &'a OutpointReveal> + Clone,
    ) -> usize {
        let counter = 0;
        for (_, transition) in &mut self.state_transitions {
            transition.owned_rights_mut().into_iter().fold(
                counter,
                |counter, (_, assignment)| {
                    counter + assignment.reveal_seals(known_seals.clone())
                },
            );
        }
        for extension in &mut self.state_extensions {
            extension.owned_rights_mut().into_iter().fold(
                counter,
                |counter, (_, assignment)| {
                    counter + assignment.reveal_seals(known_seals.clone())
                },
            );
        }
        counter
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::schema::test::schema;
    use crate::validation::TxResolver;
    use lnpbp::strict_encoding::StrictDecode;
    use lnpbp::tagged_hash;

    static CONSIGNMENT: [u8; 1549] = include!("../../test/consignment.in");

    pub(crate) fn consignment() -> Consignment {
        Consignment::strict_decode(&CONSIGNMENT[..]).unwrap()
    }

    struct TestResolver;

    impl TxResolver for TestResolver {
        fn resolve(
            &self,
            txid: &Txid,
        ) -> Result<
            Option<(bitcoin::Transaction, u64)>,
            validation::TxResolverError,
        > {
            eprintln!("Validating txid {}", txid);
            Err(validation::TxResolverError)
        }
    }

    #[test]
    fn test_consignment_validation() {
        let consignment = consignment();
        let schema = schema();
        let status = consignment.validate(&schema, TestResolver);
        println!("{}", status);
    }

    #[test]
    fn test_consignment_id_midstate() {
        // TODO: Do the actual consignment verification testing
        let midstate = tagged_hash::Midstate::with(b"rgb:consignment");
        assert_eq!(**midstate, MIDSTATE_CONSIGNMENT_ID);
    }

    #[test]
    fn test_consignment_bech32() {
        let consignment = consignment();

        let bech32id =
            "id10esx6u6e7yfmh86ngytsma5nk0pkxhuaa3yuqzgrcwnz2vknvduqt78j6u";
        let id = consignment.id();
        assert_eq!(bech32id, id.to_string());
        assert_eq!(ConsignmentId::from_str(bech32id).unwrap(), id);

        let bech32cs = include!("../../test/consignment1bech.in");

        assert_eq!(bech32cs, consignment.to_string());
        assert_eq!(Consignment::from_str(bech32cs).unwrap(), consignment);
    }
}
