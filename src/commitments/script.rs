use bitcoin::{PublicKey, Script};
use crate::commitments::{base::*, secp256k1::*};

impl CommitTarget for Script {}

pub struct ScriptCommitment {
    pub tweaks: Vec<TweakCommitment>,
    pub script: Script,
}

impl CommitmentScheme<Script> for ScriptCommitment {
    fn commit(&self) -> Script {
        unimplemented!()
    }

    fn verify(&self, script: Script) -> bool {
        unimplemented!()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScriptEngine(Script);

impl<'a> CommitmentEngine<Script, TweakSource<'a>, ScriptCommitment> for ScriptEngine {
    fn construct(&self, src: &TweakSource<'a>) -> ScriptCommitment {
        unimplemented!()
    }
}
