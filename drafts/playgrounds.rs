pub mod serialize {
    pub mod commitment {
        pub struct Transition<const N: u32, const M: u16> {
            pub seals_root: MerkleRoot<SealHash, N>,
            pub state_root: MerkleRoot<StateHash, N>,
            pub meta_root:  MerkleRoot<MetaHash, M>,
            pub script: ScriptHash,
        }
        impl<N, M> Transition {
            pub const SEALS: u32 = N;
            pub const META: u16 = M;
        }
    }

    pub mod network {
        pub struct Transition {
            pub known_seal_state: Vec<self::SealState>,
            pub merkle_nodes: Vec<self::MerkleNode>,
            pub meta: Vec<self::MetaRecord>,
            pub script: Option<self::SimplicityScript>,
        }

        pub struct SealState<const LEN: u32> {
            pub no: u32,
            pub txid: Txid,
            pub vout: u32,
            pub entropy: u32,
                len: u16,
            pub format: u16,
            pub data: [u8; LEN as usize],
        }

        impl<LEN> SealState {
            pub const LEN: u32 = LEN;
        }
    }
}

pub mod runtime {
    //! ```rust
    //! use lnpbp::drafts::runtime::*;
    //!
    //! let seal_set = SealSet::from(vec![
    //!     transition1.state_for(0)?,
    //!     transition2.state_for(1)?,
    //! ])?;
    //! let seal_set2 = SealSet::from(vec![]);
    //! let new_transition = seal_set.create_transition(vec![
    //!     State::new(Seal::Hidden(txid1, vout1, entropy), StateData::Amount(1000)),
    //!     State::new(dest, StateData::Amount(10))
    //! ], vec![] /* Meta */, None /* Script */)?;
    //! let new_transition2 = seal_set2.create_transition(vec![], vec![], None);
    //! let multitransition = Multitransition::new(vec![new_transition, new_transition2]);
    //! let tx = multitransition.construct_transaction(
    //!     vec![] /* Additional inputs */,
    //!     vec![] /* Additional outputs */,
    //!     None /* Preferences for the fee */
    //! );
    //! ```

    use std::io;
    use bitcoin::{Txid, TxIn, TxOut, Transaction, OutPoint};

    pub enum Error {

    }

    pub enum StateData {
        Amount(u256),
    }

    pub enum Seal {
        Hidden(Txid, u32, u32),
        Explicit(Txid, u32),
    }

    pub struct State {
        pub seal: Seal,
        pub data: StateData,
    }

    pub enum MetaRecord {
        String(String)
    }

    pub struct StateSet(Set<State>);
    impl StateSet {
        pub fn from(states: Set<State>) -> Result<StateSet, Error> { unimplemented!() }
        pub fn create_transition(
            self, outs: Vec<State>, meta: Vec<MetaRecord>, script: Option<SimplicityScript>
        ) -> Transition {
            unimplemented!()
        }
    }

    pub struct FeePolicy {
        pub vout: u32,
    }

    pub trait TransactionConstructor {
        fn construct_transaction(
            self, ins: Vec<TxIn>, outs: Vec<TxOut>, fee_policy: Option<FeePolicy>
        ) -> Transaction;
    }

    pub struct Multitransition(Vec<Transition>);
    impl Multitransition {
        pub fn new(src: Vec<Transition>) -> Result<Multitransition, Error> { unimplemented!() }
    }
    impl TransactionConstructor for Multitransition {
        fn construct_transaction(
            self, ins: Vec<TxIn>, outs: Vec<TxOut>, fee: Option<FeePolicy>
        ) -> Transaction {
            unimplemented!()
        }
    }

    pub struct Transition {
        pub commitment_source: super::serialize::commitment::Transition,
        pub known_inputs: Vec<State>,
        pub known_state: Vec<State>,
        pub meta: Vec<MetaRecord>,
        pub script: Option<SimplicityScript>,
    }
    impl Transition {
        pub fn state_for(&self, no: u32) -> Result<State, Error> { unimplemented!() }
    }
    impl TransactionConstructor for Transition {
        fn construct_transaction(
            self, ins: Vec<TxIn>, outs: Vec<TxOut>, fee: Option<FeePolicy>
        ) -> Transaction {
            unimplemented!()
        }
    }

    pub trait StorageSerialize {
        fn storage_serialize(&self, stream: &io::Stream) -> Result<(), io::Error>;
        fn storage_deserialize(stream: &io::Stream) -> Self;
    }

    pub trait NetworkSerialize {
        fn network_serialize(&self, stream: &io::Stream) -> Result<(), io::Error>;
        fn network_deserialize(stream: &io::Stream) -> Self;
    }

    impl StorageSerialize for Transition { /* ... */ }
    impl NetworkSerialize for Transition { /* ... */ }
}
