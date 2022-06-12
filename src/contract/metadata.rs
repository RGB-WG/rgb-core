// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Convenience metadata accessor methods for Genesis and state transitions.

use std::collections::{BTreeMap, BTreeSet};

use amplify::num::apfloat::ieee;
use amplify::num::{i1024, i256, i512, u1024, u256, u512};
use amplify::Wrapper;
use commit_verify::merkle::MerkleNode;
use commit_verify::{
    commit_encode, ConsensusCommit, ConsensusMerkleCommit, MerkleSource, ToMerkleSource,
};
use half::bf16;
use stens::AsciiString;

use super::data;
use crate::schema;

// TODO #47: Use of BTreeSet for metadata values breaks their arbitrary order
//       which may be used to correlate metadata with indexes of other
//       metadata or state. Consider converting into `Vec` type like it was
//       accomplished for the state data
type MetadataInner = BTreeMap<schema::FieldType, BTreeSet<data::Revealed>>;

/// Transition & genesis metadata fields
#[derive(Wrapper, Clone, PartialEq, Eq, Default, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(StrictEncode, StrictDecode)]
pub struct Metadata(MetadataInner);

impl IntoIterator for Metadata {
    type Item = <MetadataInner as IntoIterator>::Item;
    type IntoIter = <MetadataInner as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, StrictEncode, StrictDecode)]
pub struct MetadataLeaf(pub schema::FieldType, pub data::Revealed);
impl commit_encode::Strategy for MetadataLeaf {
    type Strategy = commit_encode::strategies::UsingStrict;
}
impl ConsensusCommit for MetadataLeaf {
    type Commitment = MerkleNode;
}
impl ConsensusMerkleCommit for MetadataLeaf {
    const MERKLE_NODE_PREFIX: &'static str = "metadata";
}
impl ToMerkleSource for Metadata {
    type Leaf = MetadataLeaf;

    fn to_merkle_source(&self) -> MerkleSource<Self::Leaf> {
        self.as_inner()
            .iter()
            .flat_map(|(type_id, i)| {
                i.iter()
                    .map(move |data| MetadataLeaf(*type_id, data.clone()))
            })
            .collect()
    }
}

impl Metadata {
    pub fn u8(&self, field_type: impl Into<schema::FieldType>) -> Vec<u8> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::u8).collect())
            .unwrap_or_default()
    }
    pub fn u16(&self, field_type: impl Into<schema::FieldType>) -> Vec<u16> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::u16).collect())
            .unwrap_or_default()
    }
    pub fn u32(&self, field_type: impl Into<schema::FieldType>) -> Vec<u32> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::u32).collect())
            .unwrap_or_default()
    }
    pub fn u64(&self, field_type: impl Into<schema::FieldType>) -> Vec<u64> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::u64).collect())
            .unwrap_or_default()
    }
    pub fn u128(&self, field_type: impl Into<schema::FieldType>) -> Vec<u128> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::u128).collect())
            .unwrap_or_default()
    }
    pub fn u256(&self, field_type: impl Into<schema::FieldType>) -> Vec<u256> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::u256).collect())
            .unwrap_or_default()
    }
    pub fn u512(&self, field_type: impl Into<schema::FieldType>) -> Vec<u512> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::u512).collect())
            .unwrap_or_default()
    }
    pub fn u1024(&self, field_type: impl Into<schema::FieldType>) -> Vec<u1024> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::u1024).collect())
            .unwrap_or_default()
    }

    pub fn i8(&self, field_type: impl Into<schema::FieldType>) -> Vec<i8> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::i8).collect())
            .unwrap_or_default()
    }
    pub fn i16(&self, field_type: impl Into<schema::FieldType>) -> Vec<i16> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::i16).collect())
            .unwrap_or_default()
    }
    pub fn i32(&self, field_type: impl Into<schema::FieldType>) -> Vec<i32> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::i32).collect())
            .unwrap_or_default()
    }
    pub fn i64(&self, field_type: impl Into<schema::FieldType>) -> Vec<i64> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::i64).collect())
            .unwrap_or_default()
    }
    pub fn i128(&self, field_type: impl Into<schema::FieldType>) -> Vec<i128> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::i128).collect())
            .unwrap_or_default()
    }
    pub fn i256(&self, field_type: impl Into<schema::FieldType>) -> Vec<i256> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::i256).collect())
            .unwrap_or_default()
    }
    pub fn i512(&self, field_type: impl Into<schema::FieldType>) -> Vec<i512> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::i512).collect())
            .unwrap_or_default()
    }
    pub fn i1024(&self, field_type: impl Into<schema::FieldType>) -> Vec<i1024> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::i1024).collect())
            .unwrap_or_default()
    }

    pub fn f16b(&self, field_type: impl Into<schema::FieldType>) -> Vec<bf16> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::f16b).collect())
            .unwrap_or_default()
    }
    pub fn f16(&self, field_type: impl Into<schema::FieldType>) -> Vec<ieee::Half> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::f16).collect())
            .unwrap_or_default()
    }
    pub fn f32(&self, field_type: impl Into<schema::FieldType>) -> Vec<f32> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::f32).collect())
            .unwrap_or_default()
    }
    pub fn f64(&self, field_type: impl Into<schema::FieldType>) -> Vec<f64> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::f64).collect())
            .unwrap_or_default()
    }
    pub fn f80(&self, field_type: impl Into<schema::FieldType>) -> Vec<ieee::X87DoubleExtended> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::f80).collect())
            .unwrap_or_default()
    }
    pub fn f128(&self, field_type: impl Into<schema::FieldType>) -> Vec<ieee::Quad> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::f128).collect())
            .unwrap_or_default()
    }
    pub fn f256(&self, field_type: impl Into<schema::FieldType>) -> Vec<ieee::Oct> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::f256).collect())
            .unwrap_or_default()
    }
    // TODO #100: Implement tapered float format

    pub fn bytes(&self, field_type: impl Into<schema::FieldType>) -> Vec<Vec<u8>> {
        self.get(&field_type.into())
            .map(|set| set.into_iter().filter_map(data::Revealed::bytes).collect())
            .unwrap_or_default()
    }
    pub fn ascii_string(&self, field_type: impl Into<schema::FieldType>) -> Vec<AsciiString> {
        self.get(&field_type.into())
            .map(|set| {
                set.into_iter()
                    .filter_map(data::Revealed::ascii_string)
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn unicode_string(&self, field_type: impl Into<schema::FieldType>) -> Vec<String> {
        self.get(&field_type.into())
            .map(|set| {
                set.into_iter()
                    .filter_map(data::Revealed::unicode_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use amplify::Wrapper;
    use bitcoin_hashes::Hash;
    use commit_verify::merkle::MerkleNode;
    use commit_verify::{merklize, CommitEncode};
    use secp256k1zkp::rand::{thread_rng, RngCore};
    use strict_encoding::{StrictDecode, StrictEncode};

    use super::*;
    //use lnpbp::commit_verify::CommitVerify;

    // Hard coded sample metadata object as shown below
    // Metadata({13: {U8(2), U8(3), U16(2), U32(2), U32(3),
    //    U64(2), U64(3), I8(2), I8(3), I32(2), I32(3),
    //    I64(2), I64(3), F32(2.0), F32(3.0), F64(2.0),
    //    F64(3.0), Bytes([1, 2, 3, 4, 5]), Bytes([10, 20, 30, 40, 50]),
    //    String("One Random String"), String("Another Random String")}})
    // It has Field_type = 13 with only single U16 and no I16 data types.
    static METADATA: [u8; 161] = include!("../../test/metadata.in");

    #[test]
    fn test_extraction() {
        let metadata = Metadata::strict_decode(&METADATA[..]).unwrap();

        let field_type = 13 as schema::FieldType;

        let field_1 = metadata.u8(field_type);
        let field_2 = metadata.u16(field_type);
        let field_3 = metadata.u32(field_type);
        let field_4 = metadata.u64(field_type);
        let field_5 = metadata.i8(field_type);
        let field_6 = metadata.i16(field_type);
        let field_7 = metadata.i32(field_type);
        let field_8 = metadata.i64(field_type);
        let field_9 = metadata.f32(field_type);
        let field_10 = metadata.f64(field_type);
        let field_11 = metadata.bytes(field_type);
        let field_12 = metadata.unicode_string(field_type);

        assert_eq!(field_1, vec![2, 3]);
        assert_eq!(field_2, vec![2]);
        assert_eq!(field_3, vec![2, 3]);
        assert_eq!(field_4, vec![2, 3]);
        assert_eq!(field_5, vec![2, 3]);
        assert_eq!(field_6, Vec::<i16>::new());
        assert_eq!(field_7, vec![2, 3]);
        assert_eq!(field_8, vec![2, 3]);
        assert_eq!(field_9, vec![2 as f32, 3 as f32]);
        assert_eq!(field_10, vec![2 as f64, 3 as f64]);
        assert_eq!(field_11, vec![
            [1u8, 2, 3, 4, 5].to_vec(),
            [10u8, 20, 30, 40, 50].to_vec()
        ]);
        assert_eq!(field_12, vec![
            "One Random String".to_string(),
            "Another Random String".to_string()
        ]);
    }

    #[test]
    fn test_encode_decode_meta() {
        test_encode!((METADATA, Metadata));
    }

    #[test]
    #[should_panic(expected = "UnexpectedEof")]
    fn test_eof_metadata() {
        let mut data = METADATA.clone();
        data[0] = 0x36 as u8;
        Metadata::strict_decode(&data[..]).unwrap();
    }

    #[test]
    fn test_iteration_field() {
        let metadata = Metadata::strict_decode(&METADATA[..]).unwrap();
        let field_values = metadata.f32(13 as schema::FieldType);

        assert_eq!(field_values.into_iter().sum::<f32>(), 5f32);
    }

    #[test]
    fn test_commitencoding_field() {
        let mut rng = thread_rng();
        let mut data1 = BTreeSet::new();
        data1.insert(data::Revealed::U8(rng.next_u64() as u8));
        data1.insert(data::Revealed::U16(rng.next_u64() as u16));
        data1.insert(data::Revealed::U32(rng.next_u64() as u32));
        data1.insert(data::Revealed::U64(rng.next_u64() as u64));

        let mut data2 = BTreeSet::new();
        data2.insert(data::Revealed::I8(rng.next_u64() as i8));
        data2.insert(data::Revealed::I16(rng.next_u64() as i16));
        data2.insert(data::Revealed::I32(rng.next_u64() as i32));
        data2.insert(data::Revealed::I64(rng.next_u64() as i64));

        let mut byte_vec = vec![];
        for i in 0..10 {
            byte_vec.insert(i, rng.next_u32() as u8);
        }

        let mut data3 = BTreeSet::new();
        data3.insert(data::Revealed::F32(rng.next_u32() as f32));
        data3.insert(data::Revealed::F64(rng.next_u32() as f64));
        data3.insert(data::Revealed::Bytes(byte_vec));
        data3.insert(data::Revealed::UnicodeString("Random String".to_string()));

        let field1 = 1 as schema::FieldType;
        let field2 = 2 as schema::FieldType;
        let field3 = 3 as schema::FieldType;

        let mut metadata_inner = BTreeMap::new();
        metadata_inner.insert(field1, data1.clone());
        metadata_inner.insert(field2, data2.clone());
        metadata_inner.insert(field3, data3.clone());

        let metadata = Metadata::from_inner(metadata_inner);

        let mut original_encoding = vec![];
        metadata
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut original_encoding);

        // Hand calculate the encoding
        // create the leaves
        let vec_1: Vec<(schema::FieldType, data::Revealed)> =
            data1.iter().map(|data| (field1, data.clone())).collect();
        let vec_2: Vec<(schema::FieldType, data::Revealed)> =
            data2.iter().map(|data| (field2, data.clone())).collect();
        let vec_3: Vec<(schema::FieldType, data::Revealed)> =
            data3.iter().map(|data| (field3, data.clone())).collect();

        // combine all the leaves
        let vec_4 = [vec_1, vec_2, vec_3].concat();

        // create MerkleNodes from each leaf
        let nodes: Vec<MerkleNode> = vec_4
            .iter()
            .map(|item| MerkleNode::hash(&StrictEncode::strict_serialize(item).unwrap()))
            .collect();

        // compute merkle root of all the nodes
        let (root, _) = merklize(MetadataLeaf::MERKLE_NODE_PREFIX, nodes);

        // Commit encode the root
        let handmade_encoding = root.commit_serialize();

        // This should match with original encoding
        assert_eq!(original_encoding, handmade_encoding);
    }
}
