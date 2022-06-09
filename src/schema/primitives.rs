
pub enum PrimitiveType {
    U8 { min: u8, max: u8 },
    U16 { min: u16, max: u16 },
    U32 { min: u32, max: u32 },
    U64 { min: u64, max: u64 },
    U128 { min: u128, max: u128 },
    U256 { min: u256, max: u256 },
    U512 { min: u512, max: u512 },
    U1024 { min: u1024, max: u1024 },

    I8 { min: i8, max: i8 },
    I16 { min: i16, max: i16 },
    I32 { min: i32, max: i32 },
    I64 { min: i64, max: i64 },
    I128 { min: i128, max: i128 },
    I256 { min: i256, max: i256 },
    I512 { min: i512, max: i512 },
    I1024 { min: i1024, max: i1024 },

    F16b,
    F16,
    F32,
    F64,
    F80,
    F128,
    F256,
    F512,
}

pub enum DataType {
    Primitive(PrimitiveType),
    Union(BTreeSet<PrimitiveType>),
    Enum(BTreeSet<u8>),
    Fixed {
        count: u16,
        ty: PrimitiveType,
    },
    Array {
        min: u16,
        max: u16,
        ty: PrimitiveType,
    },
    Ascii {
        min_chars: u16,
        max_chars: u16,
    },
    Unicode {
        min_chars: u16,
        max_chars: u16,
    },
}

const RSA: DataType = DataType::Fixed { count: 4096, ty: PrimitiveType::U8 { min: 0, max: u8::MAX } };
