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


#![allow(unused_imports)]

use std::collections::HashSet;

use bitcoin::{Txid, Transaction, OutPoint};

use petgraph::{Directed, Direction, stable_graph::StableGraph};
use petgraph::visit::EdgeRef;
use petgraph::graph::{NodeIndex, DefaultIx};

use crate::common::Wrapper;

use super::{Transition, Metadata, State};
use super::data::amount::Commitment;
use super::state::{Partial, Bound};
use super::seal;

/// Fetch a raw Bitcoin transaction given its identifier
pub trait TxFetch {
    type Error;

    fn fetch_from_txid(&mut self, txid: &Txid) -> Result<Option<Transaction>, Self::Error>;
}

#[derive(Debug, Clone)]
pub enum GraphError {
    InvalidOpenSeal(NodeIndex<DefaultIx>),
}

#[derive(Debug, Clone)]
pub enum HistoryGraphNode {
    Open(seal::Seal),
    Transition(Transition, Txid),
    Genesis(Transition),
}

#[derive(Debug, Clone)]
pub struct HistoryGraph {
    graph: StableGraph<HistoryGraphNode, (), Directed>,
    open: Vec<(Option<Txid>, NodeIndex<DefaultIx>)>,
}

impl HistoryGraph {
    fn add_open_seals(&mut self, from_transition: &Transition, from_txid: Option<Txid>, from_node: NodeIndex<DefaultIx>) {
        for state in from_transition.state.iter() {
            if let Partial::State(Bound { seal, .. }) = state {
                let open_seal_node = self.graph.add_node(HistoryGraphNode::Open(seal.clone()));
                self.graph.add_edge(from_node, open_seal_node, ());

                self.open.push((from_txid.clone(), open_seal_node));
            }
        }
    }

    pub fn new(genesis: Transition) -> Self {
        let mut graph = StableGraph::new();
        let genesis_node = graph.add_node(HistoryGraphNode::Genesis(genesis.clone()));

        let mut graph = HistoryGraph {
            graph,
            open: vec![],
        };
        graph.add_open_seals(&genesis, None, genesis_node);

        graph
    }

    pub fn apply_transition(&mut self, transition: Transition, txid: Txid, closes: Vec<OutPoint>) -> Result<(), GraphError> {
        let closing_indexes = self
            .open
            .iter()
            .try_fold(HashSet::new(), |mut to_close, (prev_txid, node_index)| {
                if let Some(HistoryGraphNode::Open(node_seal)) = self.graph.node_weight(*node_index) {
                    if closes.iter().any(|outpoint| node_seal.compare_to_outpoint(outpoint, *prev_txid, None)) { // TODO: add support for blinding key in transitions
                        to_close.insert(*node_index);
                    }

                    Ok(to_close)
                } else {
                    Err(GraphError::InvalidOpenSeal(*node_index))
                }
            })?;

        // remove all the seals we are closing from the `open` vec
        self.open.retain(|(_, node_index)| !closing_indexes.contains(node_index));

        let new_node = self.graph.add_node(HistoryGraphNode::Transition(transition.clone(), txid));
        self.add_open_seals(&transition, Some(txid), new_node);

        for to_close in closing_indexes {
            println!("to_close {:?}", to_close);

            // copy the edges that went into the seal we are closing
            let from_edges = self
                .graph
                .edges_directed(to_close, Direction::Incoming)
                .map(|edge| edge.source())
                .collect::<Vec<_>>();

            for from in from_edges {
                println!("add edge from {:?}", from);
                self.graph.add_edge(from, new_node, ());
            }

            // and then remove the node
            self.graph.remove_node(to_close);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::rgb::data;

    #[test]
    fn test_graph() {
        let genesis = Transition {
            id: 0,
            meta: Metadata::from_inner(vec![]),
            state: State::from_inner(vec![Partial::State(Bound {
                id: seal::Type(0),
                seal: seal::Seal::revealed(Default::default(), 5, 0),
                val: data::Data::None,
            })]),
            script: None
        };

        let mut graph = HistoryGraph::new(genesis);
        println!("{:#?}", graph);

        let next_trans = Transition {
            id: 1,
            meta: Metadata::from_inner(vec![]),
            state: State::from_inner(vec![Partial::State(Bound {
                id: seal::Type(0),
                seal: seal::Seal::revealed(Default::default(), 42, 0),
                val: data::Data::None,
            })]),
            script: None,
        };

        graph.apply_transition(next_trans, Default::default(), vec![OutPoint{txid: Default::default(), vout: 5}]);
        println!("{:#?}", graph);
    }
}
