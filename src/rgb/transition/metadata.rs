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

use bitcoin::util::uint::{Uint128, Uint256};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub struct Type(pub u16);

#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Value {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(Uint128),
    U256(Uint256),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Bytes(Box<[u8]>),
    Str(String),
    // TODO: Add other supported field types according to the schema
}

#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub struct Field {
    pub id: Type,
    pub val: Value,
}

wrapper!(
    Metadata,
    Vec<Field>,
    doc = "Set of metadata fields",
    derive = [Default]
);
