// TODO: These have to be in `single_use_seals` crate

use commit_verify::mpc;
use single_use_seals::SealWitness;
use strict_types::{StrictDecode, StrictDumb, StrictEncode};

use crate::vm::WitnessOrd;

pub trait WitnessId: Copy + Ord {}
pub trait PubWitness: StrictEncode + StrictDecode {
    type WitnessId: WitnessId;
    type Client: ClientWitness;
    type Seal;
    fn witness_id(&self) -> Self::WitnessId;
}
pub trait ClientWitness: StrictEncode + StrictDecode {}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Witness<W: PubWitness> {
    pub public: W,
    pub anchor: Anchor<W::Client>,
}

impl<W: PubWitness> Witness<W> {
    pub fn order(&self) -> WitnessOrd { todo!() }
}

impl<W: PubWitness> SealWitness<W::Seal> for Witness<W> {
    type Message = ();
    type Error = ();

    fn verify_seal(&self, seal: &W::Seal, msg: &Self::Message) -> Result<(), Self::Error> {
        todo!()
    }

    fn verify_many_seals<'seal>(
        &self,
        seals: impl IntoIterator<Item = &'seal W::Seal>,
        msg: &Self::Message,
    ) -> Result<(), Self::Error>
    where
        W::Seal: 'seal,
    {
        todo!()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_BPCORE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Anchor<Pw: PubWitness, M: mpc::Proof = mpc::MerkleProof> {
    /// Structured multi-protocol commitment proof.
    pub mpc_proof: M,

    /// Seal client witness.
    pub client_witness: Pw,
}
