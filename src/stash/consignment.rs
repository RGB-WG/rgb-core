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
    commit_strategy, commit_verify::CommitVerify, CommitConceal,
    CommitEncodeWithStrategy, ConsensusCommit,
};
use lnpbp::seals::OutpointReveal;
use lnpbp::TaggedHash;
use wallet::resolvers::TxResolver;

use crate::contract::ConcealSeals;
use crate::{
    validation, Anchor, ConcealState, ContractId, Extension, Genesis, Node,
    NodeId, Schema, SealEndpoint, Transition, Validator,
};

pub type ConsignmentEndpoints = Vec<(NodeId, SealEndpoint)>;
// TODO #59: Current strict encoding procedure limits transition history to
//      u16::MAX which is insufficient. Upgrade it to use larger array size
pub type TransitionData = Vec<(Anchor, Transition)>;
// TODO #59: Current strict encoding procedure limits extension history to
//      u16::MAX which is insufficient. Upgrade it to use larger array size
pub type ExtensionData = Vec<Extension>;

pub const RGB_CONSIGNMENT_VERSION: u16 = 0;

static MIDSTATE_CONSIGNMENT_ID: [u8; 32] = [
    8, 36, 37, 167, 51, 70, 76, 241, 171, 132, 169, 56, 76, 108, 174, 226, 197,
    98, 75, 254, 29, 125, 170, 233, 184, 121, 13, 183, 90, 51, 134, 6,
];

/// Tag used for [`ConsignmentId`] hash types
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

#[cfg_attr(
    all(feature = "cli", feature = "serde"),
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
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

// TODO #60: Implement different conceal procedures for the consignment

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
    pub fn version(&self) -> u16 {
        self.version
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

    pub fn validate<R: TxResolver>(
        &self,
        schema: &Schema,
        resolver: R,
    ) -> validation::Status {
        Validator::validate(schema, self, resolver)
    }

    pub fn finalize(
        &mut self,
        expose: &BTreeSet<SealEndpoint>,
        contract_id: ContractId,
    ) -> usize {
        let concealed_endpoints =
            expose.iter().map(SealEndpoint::commit_conceal).collect();

        let mut removed_endpoints = vec![];
        self.endpoints = self
            .endpoints
            .clone()
            .into_iter()
            .filter(|(_, endpoint)| {
                if expose.contains(endpoint) {
                    true
                } else {
                    removed_endpoints.push(*endpoint);
                    false
                }
            })
            .collect();
        let seals_to_conceal = removed_endpoints
            .iter()
            .map(SealEndpoint::commit_conceal)
            .collect();

        let mut count = self.state_transitions.iter_mut().fold(
            0usize,
            |count, (anchor, transition)| {
                count
                    + anchor.conceal_except(contract_id)
                    + transition.conceal_state_except(&concealed_endpoints)
                    + transition.conceal_seals(&seals_to_conceal)
            },
        );

        count =
            self.state_extensions
                .iter_mut()
                .fold(count, |count, extension| {
                    count + extension.conceal_state_except(&concealed_endpoints)
                });

        count
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
            transition.owned_rights_mut().iter_mut().fold(
                counter,
                |counter, (_, assignment)| {
                    counter + assignment.reveal_seals(known_seals.clone())
                },
            );
        }
        for extension in &mut self.state_extensions {
            extension.owned_rights_mut().iter_mut().fold(
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
    use lnpbp::strict_encoding::StrictDecode;
    use lnpbp::tagged_hash;
    use wallet::resolvers::{TxResolver, TxResolverError};

    static CONSIGNMENT: [u8; 1496] = include!("../../test/consignment.in");

    pub(crate) fn consignment() -> Consignment {
        Consignment::strict_decode(&CONSIGNMENT[..]).unwrap()
    }

    struct TestResolver;

    impl TxResolver for TestResolver {
        fn resolve(
            &self,
            txid: &Txid,
        ) -> Result<Option<(bitcoin::Transaction, u64)>, TxResolverError>
        {
            eprintln!("Validating txid {}", txid);
            Err(TxResolverError)
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
        // TODO #61: Do the actual consignment verification testing
        let midstate = tagged_hash::Midstate::with(b"rgb:consignment");
        assert_eq!(**midstate, MIDSTATE_CONSIGNMENT_ID);
    }

    #[test]
    fn test_consignment_bech32() {
        let consignment = consignment();

        let bech32id =
            "id1mqqhssqzjqz5whcdkmwxj3ugv8ekmmyna2vfkjee204p4eu644psqqhg2c";
        let id = consignment.id();
        assert_eq!(bech32id, id.to_string());
        assert_eq!(ConsignmentId::from_str(bech32id).unwrap(), id);

        let bech32cs = include!("../../test/consignment1bech.in");

        assert_eq!(bech32cs, consignment.to_string());
        assert_eq!(Consignment::from_str(bech32cs).unwrap(), consignment);
    }
}
