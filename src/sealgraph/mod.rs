use bitcoin_hashes::sha256;

pub trait Digestable {
    fn get_digest(&self) -> Digest<Self>;
}

pub struct MerkleDigest<T: Digestable>(pub sha256::Hash);
pub struct Digest<T>(pub sha256::Hash);

/// Merkle root for all state transactions that the seal will be closed over
pub struct ProtocolMessage (pub MerkleDigest<StateTx>);

impl Digestable for ProtocolMessage {
    fn get_digest(&self) -> Digest<Self> {
        Digest((self.0).0)
    }
}

impl ProtocolMessage {
    fn from_state(state_tx: Vec<StateTx>) -> Self {
        unimplemented!()
    }
}

pub struct StateTx {
    pub states: Vec<StateSet<dyn BindableState>>,

    /// Commitment to the `StateMetadata`
    pub metadata_digest: Digest<StateMetadata>,
}

pub struct StateSet<T> {
    /// Root of the Merkle Tree build from TxoutBinding's
    pub bindings_mr: MerkleDigest<TxoutBinding>,

    /// Commitment to the `BoundState`
    pub state_digest: Digest<BoundState<T>>,
}

pub struct TxoutBinding {
    pub txid: Txid,
    pub vout: u16,
}

pub struct BoundState<T: BindableState> (pub Vec<dyn T>);

pub trait BindableState: Digestable {}

pub struct StateMetadata (pub Vec<dyn MetaEntry>);

pub trait MetaEntry {}
