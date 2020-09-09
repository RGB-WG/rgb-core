use crate::paradigms::client_side_validation::{CommitEncode, Conceal};
use crate::paradigms::strict_encoding::{Error, StrictDecode, StrictEncode};
use std::fmt::Debug;
use std::{
    fs::File,
    io::{BufWriter, Write},
};

// Test suite function to test against the vectors
pub fn test_suite<T: StrictEncode + StrictDecode + PartialEq + Debug>(
    object: &T,
    test_vec: &[u8],
    test_size: usize,
) -> Result<T, Error> {
    let mut encoded_object: Vec<u8> = vec![];
    let write_1 = object.strict_encode(&mut encoded_object).unwrap();
    let decoded_object = T::strict_decode(&encoded_object[..]).unwrap();
    assert_eq!(write_1, test_size);
    assert_eq!(decoded_object, *object);
    encoded_object.clear();
    let write_2 = decoded_object.strict_encode(&mut encoded_object).unwrap();
    assert_eq!(encoded_object, test_vec);
    assert_eq!(write_2, test_size);
    Ok(decoded_object)
}

// Macro to run test_suite
macro_rules! test_encode {
        ($(($x:ident, $ty:ty)),*) => (
            {
                $(
                    let object = <$ty>::strict_decode(&$x[..]).unwrap();
                    assert!(test_suite(&object, &$x[..], $x.to_vec().len()).is_ok());
                )*
            }
        );
    }

// Macro to run test suite with garbage vector
// Should produce "EnumValueNotKnown" error
macro_rules! test_garbage {
        ($(($x:ident, $ty:ty)),*) => (
            {
                $(
                    let mut cp = $x.clone();
                    cp[0] = 0x36 as u8;
                    <$ty>::strict_decode(&cp[..]).unwrap();
                )*
            }
        );
    }

pub fn test_confidential<T>(data: &[u8], commitment: &[u8]) -> Result<T, Error>
where
    T: Conceal + StrictDecode + StrictEncode + Clone + CommitEncode,
    <T as Conceal>::Confidential: StrictDecode + StrictEncode + Eq,
{
    // Create the Revealed Structure from data bytes
    let revealed = T::strict_decode(data).unwrap();

    // Conceal the Revealed structure into Confidential
    let confidential = revealed.conceal();

    // Strict_encode Confidential data
    let mut confidential_encoded = vec![];
    confidential
        .strict_encode(&mut confidential_encoded)
        .unwrap();

    // strict_encode Revealed data
    let mut revealed_encoded: Vec<u8> = vec![];
    revealed.strict_encode(&mut revealed_encoded).unwrap();

    // Assert encoded Confidential matches precomputed vector
    assert_eq!(commitment, confidential_encoded);

    // Assert encoded Confidential and Revealed are not equal
    assert_ne!(confidential_encoded.to_vec(), revealed_encoded);

    // commit_encode Revealed structure
    let mut commit_encoded_revealed = vec![];
    revealed.clone().commit_encode(&mut commit_encoded_revealed);

    // Assert commit_encode and encoded Confidential matches
    assert_eq!(commit_encoded_revealed, confidential_encoded);

    // Assert commit_encode and precomputed Confidential matches
    assert_eq!(commit_encoded_revealed, commitment);

    Ok(revealed)
}

// Macro to test confidential encoding
macro_rules! test_conf {
        ($(($revealed:ident, $conf:ident, $T:ty)),*) => (
            {
                $(
                    assert!(test_confidential::<$T>(&$revealed[..], &$conf[..]).is_ok());
                )*
            }
        );
    }

// Helper function to print decoded object in console
pub fn print_bytes<T: StrictEncode + StrictDecode>(object: &T) {
    let mut buf = vec![];
    object.strict_encode(&mut buf).unwrap();
    println!("{:#x?}", buf);
}

// Helper function to print encoded bytes to a file
// Used for large objects that doesn't fit in console output
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

pub fn encode_decode<T: StrictEncode + StrictDecode>(object: &T) -> Result<(T, usize), Error> {
    let mut encoded_object: Vec<u8> = vec![];
    let written = object.strict_encode(&mut encoded_object).unwrap();
    let decoded_object = T::strict_decode(&encoded_object[..]).unwrap();
    Ok((decoded_object, written))
}
