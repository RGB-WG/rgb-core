// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2019 by
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

use std::fmt::Debug;
use std::fs::File;
use std::io::{BufWriter, Write};

use crate::strict_encoding::{StrictDecode, StrictEncode};

// TODO: (new) Move into derive macro
#[macro_export]
macro_rules! test_enum_u8_exhaustive {
    ($enum:ident; $( $item:path => $val:expr ),+) => { {
        use ::num_traits::{FromPrimitive, ToPrimitive};

        $( assert_eq!($item.to_u8().unwrap(), $val); )+
        $( assert_eq!($enum::from_u8($val).unwrap(), $item); )+
        let mut set = ::std::collections::HashSet::new();
        $( set.insert($val); )+
        for x in 0..=core::u8::MAX {
            if !set.contains(&x) {
                assert_eq!($enum::from_u8(x), None);
                let decoded: Result<$enum, _> = $crate::strict_encoding::strict_deserialize(&[x]);
                assert_eq!(decoded.unwrap_err(), $crate::strict_encoding::Error::EnumValueNotKnown(stringify!($enum).to_string(), x));
            }
        }
        let mut all = ::std::collections::BTreeSet::new();
        $( all.insert($item); )+
        for (idx, a) in all.iter().enumerate() {
            assert_eq!(a, a);
            for b in all.iter().skip(idx + 1) {
                assert_ne!(a, b);
                assert!(a < b);
            }
        }
        $( assert_eq!($crate::strict_encoding::strict_serialize(&$item).unwrap(), &[$val]); )+
        $( assert_eq!($item, $crate::strict_encoding::strict_deserialize(&[$val]).unwrap()); )+
    } };
}

/// Macro to run test_suite
#[macro_export]
macro_rules! test_encode {
    ($(($x:ident, $ty:ty)),*) => (
        {
            $(
                let object = <$ty>::strict_decode(&$x[..]).unwrap();
                test_suite(&object, &$x[..], $x.to_vec().len());
            )*
        }
    );
}

/// Macro to run test suite with garbage vector against all non-consensus
/// enum values
#[macro_export]
macro_rules! test_garbage_exhaustive {
    ($range:expr; $( ($x:ident, $ty:ty, $err:ident) ),+ ) => (
        {$(
            let mut cp = $x.clone();
            for byte in $range {
                cp[0] = byte as u8;
                assert_eq!(
                    <$ty>::strict_decode(&cp[..]).unwrap_err(),
                    lnpbp::strict_encoding::Error::EnumValueNotKnown($err.to_string(), byte)
                );
            }
        )+}
    );
}

/// Helper function to print decoded object in console
pub fn print_bytes<T: StrictEncode + StrictDecode>(object: &T) {
    let mut buf = vec![];
    object.strict_encode(&mut buf).unwrap();
    println!("{:#x?}", buf);
}

/// Helper function to print encoded bytes to a file
/// Used for large objects that doesn't fit in console output
pub fn print_to_file<T: StrictEncode + StrictDecode>(
    object: &T,
) -> Result<usize, Box<dyn std::error::Error>> {
    let write_file = File::create("./enocded.txt").unwrap();
    let mut writer = BufWriter::new(&write_file);

    let mut buf = vec![];
    let written = object.strict_encode(&mut buf).unwrap();

    writeln!(&mut writer, "{:#x?}", buf)?;
    Ok(written)
}

pub fn encode_decode<T: StrictEncode + StrictDecode>(object: &T) {
    let mut encoded_object: Vec<u8> = vec![];
    object.strict_encode(&mut encoded_object).unwrap();
    T::strict_decode(&encoded_object[..]).unwrap();
}

/// Test suite function to test against the vectors
pub fn test_suite<T: StrictEncode + StrictDecode + PartialEq + Debug>(
    object: &T,
    test_vec: &[u8],
    test_size: usize,
) -> T {
    let mut encoded_object: Vec<u8> = vec![];
    let write_1 = object.strict_encode(&mut encoded_object).unwrap();
    let decoded_object = T::strict_decode(&encoded_object[..]).unwrap();
    assert_eq!(write_1, test_size);
    assert_eq!(decoded_object, *object);
    encoded_object.clear();
    let write_2 = decoded_object.strict_encode(&mut encoded_object).unwrap();
    assert_eq!(encoded_object, test_vec);
    assert_eq!(write_2, test_size);
    decoded_object
}
