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

use std::collections::BTreeSet;
use std::io;

use bitcoin::Txid;

use crate::bp;
use crate::rgb::{validation, Anchor, Genesis, Node, NodeId, Schema, Transition, Validator};
use crate::strict_encoding::{self, StrictDecode, StrictEncode};

pub type ConsignmentEndpoints = Vec<(NodeId, bp::blind::OutpointHash)>;
pub type ConsignmentData = Vec<(Anchor, Transition)>;

pub const RGB_CONSIGNMENT_VERSION: u16 = 0;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Consignment {
    version: u16,
    pub genesis: Genesis,
    pub endpoints: ConsignmentEndpoints,
    pub data: ConsignmentData,
}

impl Consignment {
    pub fn with(
        genesis: Genesis,
        endpoints: ConsignmentEndpoints,
        data: ConsignmentData,
    ) -> Consignment {
        Self {
            version: RGB_CONSIGNMENT_VERSION,
            genesis,
            endpoints,
            data,
        }
    }

    #[inline]
    pub fn txids(&self) -> BTreeSet<Txid> {
        self.data.iter().map(|(anchor, _)| anchor.txid).collect()
    }

    #[inline]
    pub fn node_ids(&self) -> BTreeSet<NodeId> {
        let mut set: BTreeSet<NodeId> = self.data.iter().map(|(_, node)| node.node_id()).collect();
        set.insert(self.genesis.node_id());
        set
    }

    pub fn validate<R: validation::TxResolver>(
        &self,
        schema: &Schema,
        resolver: R,
    ) -> validation::Status {
        Validator::validate(schema, self, resolver)
    }
}

impl StrictEncode for Consignment {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Ok(strict_encode_list!(e; self.version, self.genesis, self.endpoints, self.data))
    }
}

impl StrictDecode for Consignment {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self {
            version: u16::strict_decode(&mut d)?,
            genesis: Genesis::strict_decode(&mut d)?,
            endpoints: ConsignmentEndpoints::strict_decode(&mut d)?,
            data: ConsignmentData::strict_decode(&mut d)?,
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::rgb::schema::test::schema;
    use crate::rgb::validation::TxResolver;

    pub(crate) fn consignment() -> Consignment {
        let data: Vec<u8> = vec![
            0, 0, 32, 0, 211, 66, 50, 8, 132, 162, 132, 224, 141, 136, 241, 106, 62, 52, 132, 32,
            85, 122, 53, 167, 151, 135, 178, 70, 187, 68, 10, 209, 232, 38, 153, 97, 11, 17, 9, 7,
            7, 0, 0, 0, 1, 0, 33, 4, 0, 85, 83, 68, 84, 1, 0, 1, 0, 33, 10, 0, 85, 83, 68, 32, 84,
            101, 116, 104, 101, 114, 3, 0, 1, 0, 3, 160, 134, 1, 0, 0, 0, 0, 0, 4, 0, 1, 0, 3, 160,
            134, 1, 0, 0, 0, 0, 0, 5, 0, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 1, 0, 0, 0, 8, 0,
            1, 0, 11, 129, 58, 36, 95, 0, 0, 0, 0, 2, 0, 1, 0, 1, 3, 1, 0, 1, 0, 172, 198, 241,
            181, 165, 20, 213, 54, 40, 73, 173, 36, 33, 53, 221, 119, 251, 0, 189, 217, 213, 41,
            198, 175, 58, 121, 140, 28, 146, 37, 87, 64, 38, 143, 99, 202, 152, 114, 142, 39, 0, 0,
            0, 0, 3, 160, 134, 1, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 1, 0, 119,
            31, 120, 181, 213, 239, 72, 20, 181, 14, 218, 85, 151, 249, 249, 0, 34, 112, 87, 248,
            175, 199, 165, 38, 102, 156, 251, 196, 1, 155, 240, 11, 89, 186, 209, 42, 101, 37, 228,
            34, 242, 78, 181, 53, 50, 131, 104, 49, 210, 154, 160, 244, 233, 215, 118, 60, 109,
            208, 57, 250, 158, 106, 0, 250, 1, 0, 40, 60, 217, 167, 244, 2, 37, 149, 49, 155, 251,
            143, 97, 38, 157, 145, 70, 26, 1, 55, 226, 254, 248, 79, 245, 146, 206, 78, 133, 169,
            41, 40, 3, 0, 0, 84, 58, 167, 47, 84, 222, 139, 254, 20, 54, 254, 23, 40, 20, 240, 121,
            252, 19, 90, 52, 55, 246, 119, 163, 115, 68, 213, 191, 221, 242, 223, 85, 0, 236, 157,
            125, 216, 45, 29, 21, 128, 28, 221, 79, 169, 116, 83, 179, 83, 228, 196, 75, 217, 96,
            20, 17, 13, 55, 81, 51, 28, 151, 83, 41, 135, 1, 44, 67, 210, 154, 72, 87, 82, 60, 148,
            202, 96, 0, 34, 227, 220, 39, 91, 26, 55, 190, 155, 201, 78, 248, 246, 29, 193, 42,
            235, 69, 155, 195, 119, 31, 120, 181, 213, 239, 72, 20, 181, 14, 218, 85, 151, 249,
            249, 0, 34, 112, 87, 248, 175, 199, 165, 38, 102, 156, 251, 196, 1, 155, 240, 11, 1,
            126, 204, 108, 187, 10, 227, 183, 4, 3, 158, 255, 31, 84, 122, 29, 95, 146, 223, 162,
            186, 122, 246, 172, 151, 26, 75, 208, 59, 164, 167, 52, 176, 49, 86, 162, 86, 184, 173,
            58, 30, 249, 0, 1, 0, 0, 0, 1, 0, 44, 67, 210, 154, 72, 87, 82, 60, 148, 202, 96, 0,
            34, 227, 220, 39, 91, 26, 55, 190, 155, 201, 78, 248, 246, 29, 193, 42, 235, 69, 155,
            195, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 3, 2, 0, 2, 89, 186, 209, 42, 101, 37, 228,
            34, 242, 78, 181, 53, 50, 131, 104, 49, 210, 154, 160, 244, 233, 215, 118, 60, 109,
            208, 57, 250, 158, 106, 0, 250, 3, 100, 0, 0, 0, 0, 0, 0, 0, 32, 0, 94, 225, 8, 249,
            174, 126, 227, 191, 87, 70, 139, 92, 167, 220, 218, 31, 21, 6, 130, 248, 84, 18, 137,
            87, 242, 81, 220, 82, 184, 99, 93, 135, 1, 0, 50, 112, 155, 170, 111, 145, 181, 32,
            190, 173, 32, 142, 81, 240, 183, 249, 253, 225, 241, 208, 43, 50, 220, 113, 160, 83,
            117, 66, 39, 54, 213, 157, 241, 15, 215, 23, 180, 230, 84, 244, 1, 0, 0, 0, 3, 60, 134,
            1, 0, 0, 0, 0, 0, 32, 0, 161, 30, 247, 6, 81, 129, 28, 64, 168, 185, 116, 163, 88, 35,
            37, 223, 165, 168, 89, 238, 91, 54, 22, 227, 205, 128, 130, 58, 23, 210, 227, 187, 0,
            0,
        ];

        Consignment::strict_decode(&data[..]).unwrap()
    }

    struct TestResolver;

    impl TxResolver for TestResolver {
        fn resolve(
            &self,
            txid: &Txid,
        ) -> Result<Option<(bitcoin::Transaction, u64)>, validation::TxResolverError> {
            eprintln!("Validating txid {}", txid);
            Err(validation::TxResolverError)
        }
    }

    #[test]
    fn test_consignment_validation() {
        let consignment = consignment();
        let schema = schema();
        let status = consignment.validate(&schema, TestResolver);
        println!("{}", status);
    }
}
