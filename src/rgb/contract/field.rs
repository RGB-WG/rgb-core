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

use core::fmt::Debug;
use core::hash::Hash;
use core::ops::Try;
use core::option::NoneError;
use std::collections::{BTreeMap, BTreeSet};

use super::data;
use crate::client_side_validation::{
    commit_strategy, CommitEncodeWithStrategy,
};
use crate::rgb::schema;

type MetadataInner = BTreeMap<schema::FieldType, BTreeSet<data::Revealed>>;

wrapper!(
    Metadata,
    MetadataInner,
    doc = "Transition & genesis metadata fields",
    derive = [Default, PartialEq]
);

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

impl CommitEncodeWithStrategy for BTreeSet<data::Revealed> {
    type Strategy = commit_strategy::Merklization;
}

// The data below are not part of the commitments! They are just helper iterator
// structs returned by convenience methods for metadata fields

macro_rules! field_extract {
    ($self:ident, $field:ident, $name:ident) => {
        $self
            .get(&$field)
            .and_then(|set| {
                let res: Vec<_> = set
                    .into_iter()
                    .filter_map(|data| match data {
                        data::Revealed::$name(val) => Some(val),
                        _ => None,
                    })
                    .cloned()
                    .collect();
                if res.is_empty() {
                    None
                } else if res.len() == 1 {
                    Some(FieldData::one(
                        res.first()
                            .expect("Rust core library is broken")
                            .clone(),
                    ))
                } else {
                    Some(FieldData::many(res))
                }
            })
            .unwrap_or(FieldData::empty())
    };
}

impl Metadata {
    pub fn u8(&self, field_type: schema::FieldType) -> FieldData<u8> {
        field_extract!(self, field_type, U8)
    }
    pub fn u16(&self, field_type: schema::FieldType) -> FieldData<u16> {
        field_extract!(self, field_type, U16)
    }
    pub fn u32(&self, field_type: schema::FieldType) -> FieldData<u32> {
        field_extract!(self, field_type, U32)
    }
    pub fn u64(&self, field_type: schema::FieldType) -> FieldData<u64> {
        field_extract!(self, field_type, U64)
    }
    pub fn i8(&self, field_type: schema::FieldType) -> FieldData<i8> {
        field_extract!(self, field_type, I8)
    }
    pub fn i16(&self, field_type: schema::FieldType) -> FieldData<i16> {
        field_extract!(self, field_type, I16)
    }
    pub fn i32(&self, field_type: schema::FieldType) -> FieldData<i32> {
        field_extract!(self, field_type, I32)
    }
    pub fn i64(&self, field_type: schema::FieldType) -> FieldData<i64> {
        field_extract!(self, field_type, I64)
    }
    pub fn f32(&self, field_type: schema::FieldType) -> FieldData<f32> {
        field_extract!(self, field_type, F32)
    }
    pub fn f64(&self, field_type: schema::FieldType) -> FieldData<f64> {
        field_extract!(self, field_type, F64)
    }
    pub fn bytes(&self, field_type: schema::FieldType) -> FieldData<Vec<u8>> {
        field_extract!(self, field_type, Bytes)
    }
    pub fn string(&self, field_type: schema::FieldType) -> FieldData<String> {
        field_extract!(self, field_type, String)
    }
}

#[derive(Clone, PartialEq, Hash, Debug, Display, Default)]
#[display(Debug)]
pub struct FieldData<T>
where
    T: Clone + Debug + PartialEq + Default,
{
    data: Vec<T>,
    next: usize,
}

impl<T> FieldData<T>
where
    T: Clone + Debug + PartialEq + Default,
{
    pub fn empty() -> Self {
        Self {
            data: vec![],
            ..Self::default()
        }
    }

    pub fn one(item: T) -> Self {
        Self {
            data: vec![item],
            ..Self::default()
        }
    }

    pub fn many(set: impl IntoIterator<Item = T>) -> Self {
        Self {
            data: set.into_iter().collect(),
            ..Self::default()
        }
    }
}

impl<T> Iterator for FieldData<T>
where
    T: Clone + Debug + PartialEq + Default,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.data.get(self.next);
        self.next += 1;
        item.cloned()
    }
}

impl<T> Try for FieldData<T>
where
    T: Clone + Debug + Hash + PartialEq + Default,
{
    type Ok = T;
    type Error = NoneError;

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.data.first()?.clone())
    }

    fn from_error(_: Self::Error) -> Self {
        Self::empty()
    }

    fn from_ok(v: Self::Ok) -> Self {
        Self::one(v)
    }
}

impl<T> FieldData<T>
where
    T: Clone + Debug + Hash + PartialEq + Default,
{
    #[inline]
    pub fn as_vec(&self) -> &Vec<T> {
        &self.data
    }

    #[inline]
    pub fn into_vec(self) -> Vec<T> {
        self.data
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<T> {
        self.data.clone()
    }
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{StrictDecode, StrictEncode};
    use amplify::Wrapper;
    use std::io;

    impl StrictEncode for Metadata {
        fn strict_encode<E: io::Write>(
            &self,
            e: E,
        ) -> Result<usize, Self::Error> {
            self.to_inner().strict_encode(e)
        }
    }

    impl StrictDecode for Metadata {
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
            Ok(Self::from_inner(<Self as Wrapper>::Inner::strict_decode(
                d,
            )?))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::amplify::Wrapper;
    use crate::client_side_validation::{
        merklize, CommitEncode, Conceal, MerkleNode,
    };
    use crate::strict_encoding::test::*;
    use crate::strict_encoding::{StrictDecode, StrictEncode};
    use bitcoin_hashes::Hash;
    use secp256k1zkp::rand::{thread_rng, RngCore};

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

        assert_eq!(
            field_1,
            FieldData {
                data: vec![2, 3],
                next: 0
            }
        );
        assert_eq!(
            field_2,
            FieldData {
                data: vec![2],
                next: 0
            }
        );
        assert_eq!(
            field_3,
            FieldData {
                data: vec![2, 3],
                next: 0
            }
        );
        assert_eq!(
            field_4,
            FieldData {
                data: vec![2, 3],
                next: 0
            }
        );
        assert_eq!(
            field_5,
            FieldData {
                data: vec![2, 3],
                next: 0
            }
        );
        assert_eq!(field_6, FieldData::empty());
        assert_eq!(
            field_7,
            FieldData {
                data: vec![2, 3],
                next: 0
            }
        );
        assert_eq!(
            field_8,
            FieldData {
                data: vec![2, 3],
                next: 0
            }
        );
        assert_eq!(
            field_9,
            FieldData {
                data: vec![2 as f32, 3 as f32],
                next: 0
            }
        );
        assert_eq!(
            field_10,
            FieldData {
                data: vec![2 as f64, 3 as f64],
                next: 0
            }
        );
        assert_eq!(
            field_11,
            FieldData {
                data: vec![
                    [1u8, 2, 3, 4, 5].to_vec(),
                    [10u8, 20, 30, 40, 50].to_vec()
                ],
                next: 0
            }
        );
        assert_eq!(
            field_12,
            FieldData {
                data: vec![
                    "One Random String".to_string(),
                    "Another Random String".to_string()
                ],
                next: 0
            }
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
