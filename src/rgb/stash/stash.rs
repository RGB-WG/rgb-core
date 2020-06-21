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

//use bitcoin::Transaction;
//use std::collections::HashSet;

use crate::rgb::{Anchor, Consignment, ContractId, Node, SealDefinition, Transition};

#[derive(Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display_from(Debug)]
pub enum Error {}

pub trait Stash {
    fn consign(
        &self,
        contract_id: ContractId,
        transition: Transition,
        anchor: Anchor,
        endpoints: Vec<SealDefinition>,
    ) -> Result<Consignment, Error>;

    fn merge(&mut self, consignment: Consignment) -> Result<Vec<Box<dyn Node>>, Error>;
}

/*
/// Top-level structure used by client wallets to manage all known RGB smart
/// contracts and related data
pub struct Stash {
    /// A contract is a genesis + the whole known history graph under specific
    /// genesis
    pub contracts: Vec<Contract>,

    /// We have to keep anchors at this level, since they may link many
    /// state transitions under multiple contracts at the same time (via
    /// LNPBP-4 multimessage commitments)
    pub anchors: Vec<Anchor>,
}

/// With `Stash` we define a simple and uniform interface for all low-level
/// operations that are possible for smart contract management
impl Stash {
    /// When we have received data from other peer (which usually relate to our
    /// newly owned state, like assets) we do `merge` with the [Consignment], and
    /// it gets into the known data.
    pub fn merge(&mut self, _consignment: Consignment) {
        unimplemented!()
    }

    /// Now, when we need to send over to somebody else an update (like we have
    /// transferred him some state, for instance an asset) for each transfer we
    /// ask [Stash] to create a new [Consignment] for the given set of seals
    /// under some specific [Genesis] (contract creation genesis)
    pub fn consign(&self, _seals: Vec<SealDefinition>, _under: Genesis) -> Consignment {
        unimplemented!()
    }

    /// If we need to forget about the state which is not owned by us anymore
    /// (we have done the transfer and would like to prune this specific info
    /// we call this function
    pub fn forget(&mut self, _consignment: Consignment) {
        unimplemented!()
    }

    /// Clears all data that are not related to the contract state owned by
    /// us in this moment — under all known contracts
    pub fn prune(&mut self) {
        unimplemented!()
    }

    /// When we need to organize a transfer of some state we use this function.
    /// The difference with [consign] is that this function *creates new
    /// state transition data and anchors*, when [consign] allows to export a
    /// [Consignment] for already existing state transitions and anchors.
    /// The workflow is the following:
    /// 1. Use [transit] function to create an instance of [CoordinatedTransition]
    ///    for the selected seals
    /// 2. Use [Coordinator] (wallet-provided instance via trait interface)
    ///    to coordinate different contracts which are related to the given
    ///    set of seals (see [CoordinatedTransition] implementation below.
    /// 3. When you are happy with the new state assignments (i.e. new set of
    ///    seals that will hold the state) call [CoordinatedTransition::finalize].
    ///    This will generate required bitcoin transaction(s) that will close
    ///    given set of seals and commit to a newly defined seals. For building
    ///    transaction structure [CoordinatedTransition::finalize] will use
    ///    [TxResolver] (providing blockchain information or LN channel
    ///    transaction graph) and [TxConductor] for fine-tuning individual
    ///    parameters of the transaction. This will generate
    ///    [CoordinatedUpdate] containing information on all generated
    ///    state transitions, anchors and transaction(s).
    /// 4. Call [apply] (next method on [Stash] with the [CoordinatedUpdate];
    ///    this will change the state of the Stash itself and publish all
    ///    transactions with [TxResolver] (will work with both on-chain and LN
    ///    part); after this a new state ownership structure will come in place.
    ///    The function will produce a [Consignment] which may be discarded;
    ///    since it will take complete information about all state changes and
    ///    not only those changes which are related to the state you'd like
    ///    to share (for instance, if you are transferring some asset and leaving
    ///    change for yourself + moving other assets under your control which
    ///    were allocated to the same transaction outputs, this `Consignment`
    ///    will hold information on both transfer and change).
    /// 5. Use [consign] function to create a version of the `Consignment`
    ///    that will hold only information that is related to the state you'd
    ///    like to send to some other party; serialize it and send it over
    ///    the wire protocol.
    pub fn transit(&self, _seals: Vec<SealDefinition>) -> CoordinatedTransition {
        unimplemented!()
    }
    pub fn apply(
        &mut self,
        _update: CoordinatedUpdate,
        _resolver: &impl TxResolver,
    ) -> Consignment {
        unimplemented!()
    }
}

pub struct CoordinatedTransition {
    pub transitions: HashSet<ContractId, Transition>,
    pub multi_commits: HashSet<SealDefinition, MultimsgCommitment>,
}

impl CoordinatedTransition {
    pub fn coordinate(&mut self, _coordinator: &impl Coordinator) {
        unimplemented!()
    }
    pub fn finalize(
        self,
        _resolver: &impl TxResolver,
        _conductor: &impl TxConductor,
    ) -> CoordinatedUpdate {
        unimplemented!()
    }
}

pub struct CoordinatedUpdate {
    pub transitions: Vec<Transition>,
    pub anchor: Anchor,
    pub inner_witness: Transaction,
}
 */
