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

//! Convenience metadata accessor methods for Genesis and state transitions.

#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};
use std::collections::{BTreeMap, BTreeSet};

use lnpbp::client_side_validation::{
    commit_strategy, CommitEncodeWithStrategy,
};
use lnpbp::strict_encoding;

use super::data;
use crate::schema;

type MetadataInner = BTreeMap<schema::FieldType, BTreeSet<data::Revealed>>;

/// Transition & genesis metadata fields
#[derive(Wrapper, Clone, PartialEq, Eq, Default, Debug, Display, From)]
#[display(Debug)]
pub struct Metadata(MetadataInner);

impl strict_encoding::Strategy for Metadata {
    type Strategy = strict_encoding::strategies::Wrapped;
}

#[cfg(feature = "serde")]
impl serde::Serialize for Metadata {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Metadata {
    fn deserialize<D>(
        deserializer: D,
    ) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(<Self as amplify::Wrapper>::Inner::deserialize(
            deserializer,
        )?))
    }
}

impl IntoIterator for Metadata {
    type Item = <MetadataInner as IntoIterator>::Item;
    type IntoIter = <MetadataInner as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl CommitEncodeWithStrategy for Metadata {
    type Strategy = commit_strategy::Merklization;
}

impl Metadata {
    pub fn u8(&self, field_type: schema::FieldType) -> Vec<u8> {
        self.get(&field_type)
            .map(|set| set.into_iter().filter_map(data::Revealed::u8).collect())
            .unwrap_or_default()
    }
    pub fn u16(&self, field_type: schema::FieldType) -> Vec<u16> {
        self.get(&field_type)
            .map(|set| {
                set.into_iter().filter_map(data::Revealed::u16).collect()
            })
            .unwrap_or_default()
    }
    pub fn u32(&self, field_type: schema::FieldType) -> Vec<u32> {
        self.get(&field_type)
            .map(|set| {
                set.into_iter().filter_map(data::Revealed::u32).collect()
            })
            .unwrap_or_default()
    }
    pub fn u64(&self, field_type: schema::FieldType) -> Vec<u64> {
        self.get(&field_type)
            .map(|set| {
                set.into_iter().filter_map(data::Revealed::u64).collect()
            })
            .unwrap_or_default()
    }
    pub fn i8(&self, field_type: schema::FieldType) -> Vec<i8> {
        self.get(&field_type)
            .map(|set| set.into_iter().filter_map(data::Revealed::i8).collect())
            .unwrap_or_default()
    }
    pub fn i16(&self, field_type: schema::FieldType) -> Vec<i16> {
        self.get(&field_type)
            .map(|set| {
                set.into_iter().filter_map(data::Revealed::i16).collect()
            })
            .unwrap_or_default()
    }
    pub fn i32(&self, field_type: schema::FieldType) -> Vec<i32> {
        self.get(&field_type)
            .map(|set| {
                set.into_iter().filter_map(data::Revealed::i32).collect()
            })
            .unwrap_or_default()
    }
    pub fn i64(&self, field_type: schema::FieldType) -> Vec<i64> {
        self.get(&field_type)
            .map(|set| {
                set.into_iter().filter_map(data::Revealed::i64).collect()
            })
            .unwrap_or_default()
    }
    pub fn f32(&self, field_type: schema::FieldType) -> Vec<f32> {
        self.get(&field_type)
            .map(|set| {
                set.into_iter().filter_map(data::Revealed::f32).collect()
            })
            .unwrap_or_default()
    }
    pub fn f64(&self, field_type: schema::FieldType) -> Vec<f64> {
        self.get(&field_type)
            .map(|set| {
                set.into_iter().filter_map(data::Revealed::f64).collect()
            })
            .unwrap_or_default()
    }
    pub fn bytes(&self, field_type: schema::FieldType) -> Vec<Vec<u8>> {
        self.get(&field_type)
            .map(|set| {
                set.into_iter().filter_map(data::Revealed::bytes).collect()
            })
            .unwrap_or_default()
    }
    pub fn string(&self, field_type: schema::FieldType) -> Vec<String> {
        self.get(&field_type)
            .map(|set| {
                set.into_iter().filter_map(data::Revealed::string).collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use amplify::Wrapper;
    use bitcoin::hashes::Hash;
    use lnpbp::client_side_validation::{
        merklize, CommitEncode, Conceal, MerkleNode,
    };
    use lnpbp::secp256k1zkp::rand::{thread_rng, RngCore};
    use lnpbp::strict_encoding::{StrictDecode, StrictEncode};
    use lnpbp::test_helpers::*;

    // Hard coded sample metadata object as shown below
    // Metadata({13: {U8(2), U8(3), U16(2), U32(2), U32(3),
    //    U64(2), U64(3), I8(2), I8(3), I32(2), I32(3),
    //    I64(2), I64(3), F32(2.0), F32(3.0), F64(2.0),
    //    F64(3.0), Bytes([1, 2, 3, 4, 5]), Bytes([10, 20, 30, 40, 50]),
    //    String("One Random String"), String("Another Random String")}})
    // It has Field_type = 13 with only single U16 and no I16 data types.
    static METADATA: [u8; 161] = [
        0x1, 0x0, 0xd, 0x0, 0x15, 0x0, 0x0, 0x2, 0x0, 0x3, 0x1, 0x2, 0x0, 0x2,
        0x2, 0x0, 0x0, 0x0, 0x2, 0x3, 0x0, 0x0, 0x0, 0x3, 0x2, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x3, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8,
        0x2, 0x8, 0x3, 0xa, 0x2, 0x0, 0x0, 0x0, 0xa, 0x3, 0x0, 0x0, 0x0, 0xb,
        0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb, 0x3, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x12, 0x0, 0x0, 0x0, 0x40, 0x12, 0x0, 0x0, 0x40, 0x40,
        0x13, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x13, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x8, 0x40, 0x20, 0x5, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5,
        0x20, 0x5, 0x0, 0xa, 0x14, 0x1e, 0x28, 0x32, 0x21, 0x11, 0x0, 0x4f,
        0x6e, 0x65, 0x20, 0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x20, 0x53, 0x74,
        0x72, 0x69, 0x6e, 0x67, 0x21, 0x15, 0x0, 0x41, 0x6e, 0x6f, 0x74, 0x68,
        0x65, 0x72, 0x20, 0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x20, 0x53, 0x74,
        0x72, 0x69, 0x6e, 0x67,
    ];

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
        let field_12 = metadata.string(field_type);

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
        assert_eq!(
            field_11,
            vec![[1u8, 2, 3, 4, 5].to_vec(), [10u8, 20, 30, 40, 50].to_vec()]
        );
        assert_eq!(
            field_12,
            vec![
                "One Random String".to_string(),
                "Another Random String".to_string()
            ]
        );
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
        data3.insert(data::Revealed::String("Random String".to_string()));

        let field1 = 1 as schema::FieldType;
        let field2 = 2 as schema::FieldType;
        let field3 = 3 as schema::FieldType;

        let mut metadata_inner = BTreeMap::new();
        metadata_inner.insert(field1, data1.clone());
        metadata_inner.insert(field2, data2.clone());
        metadata_inner.insert(field3, data3.clone());

        let metadata = Metadata::from_inner(metadata_inner);

        let mut original_encoding = vec![];
        metadata.commit_encode(&mut original_encoding);

        // Hand calculate the encoding

        let nodes1: Vec<MerkleNode> = data1
            .iter()
            .map(|data| {
                let mut encoder = std::io::Cursor::new(vec![]);
                data.clone().conceal().strict_encode(&mut encoder).unwrap();
                MerkleNode::hash(&encoder.into_inner())
            })
            .collect();

        let mid_node1 = merklize("", &nodes1[..], 0);

        let mut encoder = std::io::Cursor::new(vec![]);
        field1.strict_encode(&mut encoder).unwrap();
        mid_node1.strict_encode(&mut encoder).unwrap();
        let node1 = MerkleNode::hash(&encoder.into_inner());

        let nodes2: Vec<MerkleNode> = data2
            .iter()
            .map(|data| {
                let mut encoder = std::io::Cursor::new(vec![]);
                data.clone().conceal().strict_encode(&mut encoder).unwrap();
                MerkleNode::hash(&encoder.into_inner())
            })
            .collect();

        let mid_node2 = merklize("", &nodes2[..], 0);

        let mut encoder = std::io::Cursor::new(vec![]);
        field2.strict_encode(&mut encoder).unwrap();
        mid_node2.strict_encode(&mut encoder).unwrap();
        let node2 = MerkleNode::hash(&encoder.into_inner());

        let nodes3: Vec<MerkleNode> = data3
            .iter()
            .map(|data| {
                let mut encoder = std::io::Cursor::new(vec![]);
                data.clone().conceal().strict_encode(&mut encoder).unwrap();
                MerkleNode::hash(&encoder.into_inner())
            })
            .collect();

        let mid_node3 = merklize("", &nodes3[..], 0);

        let mut encoder = std::io::Cursor::new(vec![]);
        field3.strict_encode(&mut encoder).unwrap();
        mid_node3.strict_encode(&mut encoder).unwrap();
        let node3 = MerkleNode::hash(&encoder.into_inner());

        let final_node = merklize("", &[node1, node2, node3], 0);

        let mut computed_encoding = vec![];
        final_node.strict_encode(&mut computed_encoding).unwrap();

        assert_eq!(original_encoding, computed_encoding);
    }
}
