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

#[macro_use]
#[allow(dead_code)]
#[allow(unused_macros)]
pub mod test_helpers {
    use crate::paradigms::client_side_validation::{CommitEncode, Conceal};
    use crate::paradigms::strict_encoding::{Error, StrictDecode, StrictEncode};
    use std::fmt::Debug;

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
        ($($x:ident),*) => (
            {
                $(
                    let object = Revealed::strict_decode(&$x[..]).unwrap();
                    assert!(test_suite(&object, &$x[..], $x.to_vec().len()).is_ok());
                )*
            }
        );
    }

    // Macro to run test suite with garbage vector
    // Should produce "EnumValueNotKnown" error
    macro_rules! test_garbage {
        ($($x:ident),*) => (
            {
                $(
                    let mut cp = $x.clone();
                    cp[0] = 0x36 as u8;
                    Revealed::strict_decode(&cp[..]).unwrap();
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

    pub fn encode_decode<T: StrictEncode + StrictDecode>(object: &T) -> Result<(T, usize), Error> {
        let mut encoded_object: Vec<u8> = vec![];
        let written = object.strict_encode(&mut encoded_object).unwrap();
        let decoded_object = T::strict_decode(&encoded_object[..]).unwrap();
        Ok((decoded_object, written))
    }
}

pub mod amount;
mod assignments;
pub mod data;
#[macro_use]
mod field;
mod conceal;
pub mod nodes;
pub mod seal;

pub use amount::Amount;
pub use assignments::{
    Ancestors, Assignment, Assignments, AssignmentsVariant, ConfidentialState, DeclarativeStrategy,
    HashStrategy, PedersenStrategy, RevealedState, StateTypes,
};
pub use conceal::AutoConceal;
pub use field::{FieldData, Metadata};
pub use nodes::{ContractId, Genesis, Node, NodeId, Transition};
pub use seal::SealDefinition;

use secp256k1zkp::Secp256k1 as Secp256k1zkp;
lazy_static! {
    /// Secp256k1zpk context object
    pub(crate) static ref SECP256K1_ZKP: Secp256k1zkp = Secp256k1zkp::with_caps(secp256k1zkp::ContextFlag::Commit);
}
