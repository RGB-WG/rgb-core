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

use bitcoin::Txid;

use lnpbp::bp;
use lnpbp::bp::blind::OutpointReveal;

use crate::{
    validation, Anchor, Extension, Genesis, Node, NodeId, Schema, Transition,
    Validator,
};

pub type ConsignmentEndpoints = Vec<(NodeId, bp::blind::OutpointHash)>;
pub type TransitionData = Vec<(Anchor, Transition)>;
pub type ExtensionData = Vec<Extension>;

pub const RGB_CONSIGNMENT_VERSION: u16 = 0;

#[derive(Clone, PartialEq, Eq, Debug, Display, StrictEncode, StrictDecode)]
#[display(Debug)]
pub struct Consignment {
    version: u16,
    pub genesis: Genesis,
    pub endpoints: ConsignmentEndpoints,
    pub state_transitions: TransitionData,
    pub state_extensions: ExtensionData,
}

impl Consignment {
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

    static CONSIGNMENT: [u8; 1555] = include!("../../../test/consignment.in");

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
}
