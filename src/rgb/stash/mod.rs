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
    pub fn merge(&mut self, consignment: Consignment) {}

    /// Now, when we need to send over to somebody else an update (like we have
    /// transferred him some state, for instance an asset) for each transfer we
    /// ask [Stash] to create a new [Consignment] for the given set of seals
    /// under some specific [Genesis] (contract creation genesis)
    pub fn consign(&self, seals: Vec<SealDefinition>, under: Genesis) -> Consignment {}

    /// If we need to forget about the state which is not owned by us anymore
    /// (we have done the transfer and would like to prune this specific info
    /// we call this function
    pub fn forget(&mut self, consignment: Consigment) {}

    /// Clears all data that are not related to the contract state owned by
    /// us in this moment — under all known contracts
    pub fn prune(&mut self) {}

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
    /// 3. When you are happy with the new state assignmnets (i.e. new set of
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
    pub fn transit(&self, seals: Vec<SealDefinition>) -> CoordinatedTransition {}
    pub fn apply(&mut self, update: CoordinatedUpdate, resolver: &TxResolver) -> Consignment {}
}

pub struct CoordinatedTransition {
    pub transitions: HashSet<ContractId, Transition<Revealed>>,
    pub multi_commits: HashSet<SealDefinition, MultiCommit>,
}

impl CoordinatedTransition {
    pub fn coordinate(&mut self, coordinator: &Coordinator) {}
    pub fn finalize(self, resolver: &TxResolver, conductor: &TxConductor) -> CoordinatedUpdate {}
}

pub struct CoordinatedUpdate {
    pub transitions: Vec<Transition<Disclosed>>,
    pub anchor: Anchor,
    pub inner_witness: Transaction,
}

/// The structure for a specific contract. Contract always have a part of the
/// information that is fully known (we use term *revealed*), i.e. the
/// information related to the state you have issued and the transfers you have
/// created, and partially-known (*partial*), like the one behind zero knowledge
/// proofs, merkle trees and blinded seals; this is an information you received
/// with *consignments* from other parties or that have resulted from the
/// [Stash::forget] and [Stash::prune] operations on your previously-owned
/// (but now transferred) state. To efficiently operate with privacy management
/// the revealed and partial state transitions are kept separate. We re-use
/// the same Transition data structures for both, but use generic polymorphism
/// with associated types to clearly distinguish transitions with partial and
/// revealed data underneath.
pub struct Contract {
    pub genesis: Genesis,
    pub revealed: Vec<Transition<Revealed>>,
    pub partial: Vec<Transition<Partial>>,
}

pub trait Revealable {
    type Amount: Homomorphic;
    type State: StateVisibility;
    type Seal: SealVisibility;
}

pub struct Revealed;
impl Revealable for Disclosed {
    type Amount = RevealedAmount;
    type State = RevealedState;
    type Seal = RevealedSeal;
}

pub struct Partial;
impl Revealable for Partial {
    type Amount = Amount;
    type State = State;
    type Seal = Seal;
}
