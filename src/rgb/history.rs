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

use std::collections::{HashSet, HashMap};

use bitcoin::{Txid, Transaction, OutPoint};

use petgraph::{Directed, Direction, stable_graph::StableGraph};
use petgraph::visit::{Bfs, EdgeRef, Reversed};
use petgraph::graph::{NodeIndex, DefaultIx};

use crate::common::Wrapper;

use super::{Transition, Metadata, State};
use super::data::amount::Commitment;
use super::state::{Partial, Bound};
use super::seal;

#[derive(Debug, Clone)]
pub enum GraphError {
    InvalidOpenSeal(NodeIndex<DefaultIx>),
    OpenSealAsParent,
    IncompatibleOpenSeals,
}

#[derive(Debug, Clone)]
pub enum HistoryGraphNode {
    Open(Option<Txid>, usize, seal::Seal),
    Transition(Transition, Txid),
    Genesis(Transition),
}

#[derive(Debug, Clone)]
pub struct HistoryGraph {
    graph: StableGraph<HistoryGraphNode, (), Directed>,
    open: HashSet<NodeIndex<DefaultIx>>,
    genesis: NodeIndex<DefaultIx>,
}

impl HistoryGraph {
    /// Internal method to add all the open seals created in a transition
    fn add_open_seals(&mut self, from_transition: &Transition, from_txid: Option<Txid>, to_node: NodeIndex<DefaultIx>) {
        for (index, state) in from_transition.state.iter().enumerate() {
            if let Partial::State(Bound { seal, .. }) = state {
                let open_seal_node = self.graph.add_node(HistoryGraphNode::Open(from_txid, index, seal.clone()));
                self.graph.add_edge(open_seal_node, to_node, ());

                self.open.insert(open_seal_node);
            }
        }
    }

    /// Internal method to find the node indexes among the required open seals
    fn find_open_seals(&self, outpoints: Vec<OutPoint>) -> Result<HashSet<NodeIndex<DefaultIx>>, GraphError> {
        self
            .open
            .iter()
            .try_fold(HashSet::new(), |mut to_close, node_index| {
                if let Some(HistoryGraphNode::Open(prev_txid, _, node_seal)) = self.graph.node_weight(*node_index) {
                    if outpoints.iter().any(|outpoint| node_seal.compare_to_outpoint(outpoint, *prev_txid, None)) { // TODO: add support for blinding key in transitions
                        to_close.insert(*node_index);
                    }

                    Ok(to_close)
                } else {
                    Err(GraphError::InvalidOpenSeal(*node_index))
                }
            })
    }

    /// Creates a new graph starting from the genesis transition. The graph will contain the
    /// genesis itself plus all of its bound seals
    pub fn new(genesis: Transition) -> Self {
        let mut graph = StableGraph::new();
        let genesis_node = graph.add_node(HistoryGraphNode::Genesis(genesis.clone()));

        let mut graph = HistoryGraph {
            graph,
            genesis: genesis_node,
            open: HashSet::new(),
        };
        graph.add_open_seals(&genesis, None, graph.genesis);

        graph
    }

    /// Applies a transition to the graph, removing the closed seals and adding the newly created
    /// ones
    pub fn apply_transition(&mut self, transition: Transition, txid: Txid, closes: Vec<OutPoint>) -> Result<(), GraphError> {
        // TODO: test with the same seal duplicated a few times

        let closing_indexes = self.find_open_seals(closes)?;

        // remove all the seals we are closing from the `open` vec
        self.open.retain(|node_index| !closing_indexes.contains(node_index));

        let new_node = self.graph.add_node(HistoryGraphNode::Transition(transition.clone(), txid));
        self.add_open_seals(&transition, Some(txid), new_node);

        for to_close in closing_indexes {
            // copy the edges connected to the node we are removing
            let to_edges = self
                .graph
                .edges_directed(to_close, Direction::Outgoing)
                .map(|edge| edge.target())
                .collect::<Vec<_>>();

            for to in to_edges {
                self.graph.add_edge(new_node, to, ());
            }

            // and then remove the node
            self.graph.remove_node(to_close);
        }

        Ok(())
    }

    /// Strips the part of the history that is not required to validate the requested open seals
    pub fn strip_history(&mut self, keep: Vec<OutPoint>) -> Result<(), GraphError> {
        let mut keep_nodes = HashSet::new();

        for start in self.find_open_seals(keep)? {
            let mut bfs = Bfs::new(&self.graph, start);
            while let Some(nx) = bfs.next(&self.graph) {
                keep_nodes.insert(nx);
            }
        }

        self.graph.retain_nodes(|_, node| keep_nodes.contains(&node));
        self.open.retain(|node| keep_nodes.contains(&node));

        Ok(())
    }

    pub fn merge_history(&mut self, other: Self) -> Result<(), GraphError> {
        // TODO: make sure the genesis is ==
        // TODO: instead of comparing open seals with ==, should we somehow
        //       interpret them and see if they are equivalent
        

        let mut transition_index = HashMap::new();
        let mut open_index = HashMap::new();

        // iterate `self.graph` from the genesis going forward (that's why edges are reversed), and
        // create an index of every transition or open seal we see
        let reversed_graph = Reversed(&self.graph);
        let mut bfs = Bfs::new(&reversed_graph, self.genesis);
        while let Some(nx) = bfs.next(&reversed_graph) {
            match self.graph.node_weight(nx).expect("Corrupted graph: missing node during BFS") {
                HistoryGraphNode::Genesis(_) => continue,
                HistoryGraphNode::Transition(_, txid) => { transition_index.insert(txid.clone(), nx); },
                HistoryGraphNode::Open(prev_txid, index, seal) => { open_index.insert((prev_txid.clone(), index.clone()), (nx, seal.clone())); },
            }
        }

        // Iterate `other.graph` from the genesis again. whenever we find a node that's missing in
        // `self.graph`, we add it and copy all the edges.
        //
        // Since we do a BFS, it's guaranteed that if we find a missing node, all of its "parent"
        // nodes will already be present.
        let reversed_other = Reversed(&other.graph);
        let mut bfs = Bfs::new(&reversed_other, other.genesis);
        while let Some(nx) = bfs.next(&reversed_other) {
            let mut add_to_self = |node: HistoryGraphNode, index_in_other: NodeIndex<DefaultIx>| -> Result<NodeIndex<DefaultIx>, GraphError> {
                // add the node to ourselves
                let new_node = self.graph.add_node(node);

                // iterate over all the neighbors in the `Outgoing` direction, so towards the
                // genesis. i.e., its parent nodes.
                for prev_node in other.graph.neighbors_directed(index_in_other, Direction::Outgoing) {
                    match other.graph.node_weight(prev_node).expect("Corrupted graph: missing node during BFS") {
                        HistoryGraphNode::Genesis(_) => { self.graph.add_edge(new_node, self.genesis, ()); },
                        HistoryGraphNode::Transition(_, prev_txid) => {
                            let corresponding_index = transition_index.get(prev_txid).expect(&format!("Corrupted graph: missing txid in `transition_index`: {:?}", prev_txid));
                            self.graph.add_edge(new_node, *corresponding_index, ());
                        },
                        HistoryGraphNode::Open(_, _, _) => return Err(GraphError::OpenSealAsParent),
                    }
                }

                Ok(new_node)
            };

            match other.graph.node_weight(nx).expect("Corrupted graph: missing node during BFS") {
                HistoryGraphNode::Genesis(_) => continue,
                HistoryGraphNode::Transition(transition, txid) => {
                    if transition_index.contains_key(txid) {
                        continue;
                    }

                    let new_node = add_to_self(HistoryGraphNode::Transition(transition.clone(), *txid), nx)?;

                    // add it to the index now that it's in `self.graph`
                    transition_index.insert(*txid, new_node);
                },
                HistoryGraphNode::Open(prev_txid, index, seal) => {
                    let key = (*prev_txid, *index);

                    if let Some((_, known_seal)) = open_index.get(&key) {
                        // compare seals. TODO here vvvv
                        if known_seal != seal {
                            return Err(GraphError::IncompatibleOpenSeals);
                        }

                        continue;
                    }


                    let new_node = add_to_self(HistoryGraphNode::Open(*prev_txid, *index, seal.clone()), nx)?;
                    // add to the list of open seals
                    self.open.insert(new_node);

                    // add it to the index now that it's in `self.graph`
                    open_index.insert(key, (new_node, seal.clone()));
                },
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::rgb::data;

    #[test]
    fn test_graph_apply_transition() {
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

        graph.apply_transition(next_trans, Default::default(), vec![OutPoint { txid: Default::default(), vout: 5 }]);
        println!("{:#?}", graph);
    }

    #[test]
    fn test_graph_strip_history() {
        let state = State::from_inner(
            vec![
                Partial::State(Bound {
                    id: seal::Type(0),
                    seal: seal::Seal::revealed(Default::default(), 0, 0),
                    val: data::Data::None,
                }),
                Partial::State(Bound {
                    id: seal::Type(0),
                    seal: seal::Seal::revealed(Default::default(), 1, 0),
                    val: data::Data::None,
                }),
                Partial::State(Bound {
                    id: seal::Type(0),
                    seal: seal::Seal::revealed(Default::default(), 2, 0),
                    val: data::Data::None,
                }),
            ]
        );
        let genesis = Transition {
            id: 0,
            meta: Metadata::from_inner(vec![]),
            state,
            script: None
        };

        let mut graph = HistoryGraph::new(genesis);
        println!("{:#?}", graph);

        graph.strip_history(vec![OutPoint { txid: Default::default(), vout: 0 }]);

        println!("{:#?}", graph);
    }

    #[test]
    fn test_graph_merge_history() {
        let seal_genesis = seal::Seal::revealed(Default::default(), 42, 0);
        let genesis = Transition {
            id: 0,
            meta: Metadata::from_inner(vec![]),
            state: State::from_inner(vec![Partial::State(Bound {
                id: seal::Type(0),
                seal: seal_genesis.clone(),
                val: data::Data::None,
            })]),
            script: None
        };

        let mut graph = HistoryGraph::new(genesis);

        let seal_0 = seal::Seal::revealed(Default::default(), 0, 0);
        let seal_1 = seal::Seal::revealed(Default::default(), 1, 0);
        let state = State::from_inner(
            vec![
                Partial::State(Bound {
                    id: seal::Type(0),
                    seal: seal_0.clone(),
                    val: data::Data::None,
                }),
                Partial::State(Bound {
                    id: seal::Type(0),
                    seal: seal_1.clone(),
                    val: data::Data::None,
                }),
            ]
        );
        let next_trans = Transition {
            id: 1,
            meta: Metadata::from_inner(vec![]),
            state,
            script: None,
        };
        graph.apply_transition(next_trans, Txid::default(), vec![seal_genesis.maybe_as_outpoint(None, None, None).unwrap()]);

        println!("initial graph {:#?}", graph);

        let mut history_0 = graph.clone();
        history_0.strip_history(vec![seal_0.maybe_as_outpoint(None, None, None).unwrap()]);

        println!("{:#?}", history_0);

        let mut history_1 = graph.clone();
        history_1.strip_history(vec![seal_1.maybe_as_outpoint(None, None, None).unwrap()]);

        history_0.merge_history(history_1);

        println!("{:#?}", history_0);
    }
}
