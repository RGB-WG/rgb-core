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

pub struct Stash {
    pub contracts: Vec<Contract>,
    pub anchors: Vec<Anchor>,
}

impl Stash {
    pub fn merge(&mut self, consignment: Consignment) {}
    pub fn consign(&self, seals: Vec<SealDefinition>) -> Consignment {}
    pub fn forget(&mut self, seals: Vec<SealDefinition>) -> Consigment {}
    pub fn prune(&mut self) {}
    pub fn transit(&self, seals: Vec<SealDefinition>) -> CoordinatedTransition {}
    pub fn apply(&mut self, transit: FinalizedTrasition) -> Consignment {}
}

pub struct CoordinatedTransition {
    pub transitions: HashSet<ContractId, Transition<Revealed>>,
    pub multi_commits: HashSet<SealDefinition, MultiCommit>,
}

impl CoordinatedTransition {
    pub fn coordinate(&mut self, coordinator: &Coordinator) {}
    pub fn finalize(self, resolver: &TxResolver) -> FinalizedTrasition {}
}

pub struct FinalizedTransition {
    pub transitions: Vec<Transition<Disclosed>>,
    pub anchors: Vec<Anchor>,
    pub transactionx: Vec<Transaction>,
}

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
