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


use std::collections::HashMap;
use num_integer::Integer;

use bitcoin::hashes::{sha256, sha256t};

use super::{
    ConsensusCommit,
    serialize
};


pub struct ValidationError {

}

pub enum StateFormat {
    NoState,
    Amount,
    Data
}

pub enum Bits {
    Bit8,
    Bit16,
    Bit32,
    Bit64,
    Bit128,
    Bit256,
}

pub enum DigestAlgorithm {
    Sha256,
    Bitcoin256,
    Ripmd160,
    Bitcoin160,
    Tagged256,
}

pub enum SignatureAlgorithm {
    EcdsaDer,
    SchnorrBip,
}

pub enum ECPointSerialization {
    Uncompressed,
    Compressed,
    SchnorrBip
}

pub enum FieldFormat {
    Unsigned { bits: Bits, min: Option<u64>, max: Option<u64> },
    Integer { bits: Bits, min: Option<i64>, max: Option<i64> },
    Float { bits: Bits, min: Option<f64>, max: Option<f64> },
    Enum { values: Vec<u8> },
    String(u16),
    Bytes(u16),
    Digest(u16, DigestAlgorithm),
    ECPoint(ECPointSerialization),
    Signature(SignatureAlgorithm),
}

pub enum Occurences<MAX: Integer> {
    Once,
    NoneOrOnce,
    OnceOrUpTo(Option<MAX>),
    NoneOrUpTo(Option<MAX>),
}

pub struct Field(pub FieldFormat, pub Occurences<u8>);

pub enum ScriptRequirements {
    ScriptsDenied,
    GenesisOnly,
    Allowed
}

pub struct Transition {
    pub closes: Option<HashMap<usize, Occurences<u32>>>,
    pub fields: Vec<Field>,
    pub binds: HashMap<usize, Occurences<u32>>,
    pub scripts: ScriptRequirements,
}

pub struct Schema {
    pub seals: HashMap<usize, StateFormat>,
    pub transitions: Vec<Transition>,
}

impl Schema {
    pub fn validate(&self, ts: super::transition::Transition) -> Result<(), ValidationError> {
        unimplemented!()
    }
}

impl serialize::Commitment for Schema {
    fn commitment_serialize(&self) -> Vec<u8> {
        unimplemented!()
        /*
        let buf = self.seals.commitment_serialize();
        buf.extend(self.transitions.commitment_serialize())
        */
    }
}

impl serialize::Commitment for Transition {
    fn commitment_serialize(&self) -> Vec<u8> {
        unimplemented!()
        /*
        let buf = self.closes.commitment_serialize();
        buf.extend(self.fields.commitment_serialize());
        buf.extend(self.binds.commitment_serialize());
        buf.extend(self.scripts.commitment_serialize())
        */
    }
}

static MIDSTATE_SHEMAID: [u8; 32] = [
    25, 205, 224, 91, 171, 217, 131, 31, 140, 104, 5, 155, 127, 82, 14, 81, 58, 245, 79, 165, 114,
    243, 110, 60, 133, 174, 103, 187, 103, 230, 9, 106
];

tagged_hash!(SchemaId, SchemaIdTag, SchemaId, MIDSTATE_SHEMAID);

impl ConsensusCommit for Schema {
    type CommitmentHash = SchemaId;
}
