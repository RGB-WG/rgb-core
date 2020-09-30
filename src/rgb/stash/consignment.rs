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

use bitcoin::Txid;

use crate::bp;
use crate::rgb::{
    validation, Anchor, Extension, Genesis, Node, NodeId, Schema, Transition, Validator,
};

pub type ConsignmentEndpoints = Vec<(NodeId, bp::blind::OutpointHash)>;
pub type OwnedData = Vec<(Anchor, Transition)>;
pub type ExtensionData = Vec<Extension>;

pub const RGB_CONSIGNMENT_VERSION: u16 = 0;

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[strict_crate(crate)]
#[display(Debug)]
pub struct Consignment {
    version: u16,
    pub genesis: Genesis,
    pub endpoints: ConsignmentEndpoints,
    pub data: OwnedData,
    pub extensions: ExtensionData,
}

impl Consignment {
    pub fn with(
        genesis: Genesis,
        endpoints: ConsignmentEndpoints,
        data: OwnedData,
        extensions: ExtensionData,
    ) -> Consignment {
        Self {
            version: RGB_CONSIGNMENT_VERSION,
            genesis,
            extensions,
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
        let mut set = bset![self.genesis.node_id()];
        set.extend(self.data.iter().map(|(_, node)| node.node_id()));
        set.extend(self.extensions.iter().map(Extension::node_id));
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

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::rgb::schema::test::schema;
    use crate::rgb::validation::TxResolver;
    use crate::strict_encoding::StrictDecode;

    pub(crate) fn consignment() -> Consignment {
        let data: Vec<u8> = vec![
            // ** Version: 0 (2 bytes)
            0, 0, //
            // ** Genesis
            // * Schema Id (32 bytes)
            // 32, 0, // Length
            211, 66, 50, 8, 132, 162, 132, 224, //
            141, 136, 241, 106, 62, 52, 132, 32, //
            85, 122, 53, 167, 151, 135, 178, 70, //
            187, 68, 10, 209, 232, 38, 153, 97, //
            // * Chain
            0x6f, 0xe2, 0x8c, 0xa, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
            0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x8, 0x9c, 0x68, 0xd6, 0x19, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x7, 0x0, 0x62, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0xf9, 0xbe, 0xb4, 0xd9,
            0x4, 0x0, 0x6d, 0x61, 0x69, 0x6e, 0x2, 0x0, 0x62, 0x63, 0x8d, 0x20, 0x8c, 0x20, 0xb4,
            0xb2, 0x7, 0x0, 0x10, 0xeb, 0x9, 0x0, 0x0, 0x22, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x3, 0x0, 0x42, 0x54, 0x43, 0x7, 0x0, 0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x7,
            0x0, 0x73, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0x0, 0xe1, 0xf5, 0x5, 0x0, 0x0, 0x0,
            0x0, 0x6f, 0xe2, 0x8c, 0xa, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
            0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x8, 0x9c, 0x68, 0xd6, 0x19, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x1, // Bitcoin mainnet
            // * Network - replaced with Chain
            // 0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71, 0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce,
            // 0xc3, 0xae, 0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad, 0x01, 0xea, 0x33, 0x09,
            // 0x00, 0x00, 0x00, 0x00, // testnet
            // * Metadata
            7, 0, // No of fields: 7
            // Field 1
            0, 0, // Field type: Ticker
            1, 0,  // No of values
            33, // Value type: string
            4, 0, // Value length: 4
            85, 83, 68, 84, // Value: USDT
            // Field 2
            1, 0, // Field type: Name
            1, 0,  // No of values
            33, // Value type: string
            10, 0, // Value length: 16
            85, 83, 68, 32, 84, 101, 116, 104, 101, 114, // Value: USD Tether
            // Field 3
            3, 0, // Field type: total supply
            1, 0, // No of values
            3, // Value type: U64
            160, 134, 1, 0, 0, 0, 0, 0, // Value
            // Field 4
            4, 0, // Field type: Issued supply
            1, 0, // No of values
            3, // Value type: U64
            160, 134, 1, 0, 0, 0, 0, 0, // Value
            // Field 5
            5, 0, // Field type: dust limit
            1, 0, // No of values
            3, // Value type: U64
            0, 0, 0, 0, 0, 0, 0, 0, // Value
            // Field 6
            6, 0, // Field type: precision
            1, 0, // No of values
            0, // Value type: U8
            0, // Value
            // Field 7
            8, 0, // Field type: timestamp
            1, 0,  // No of values
            11, // Value type: I64
            129, 58, 36, 95, 0, 0, 0, 0, // Value
            // * Assignments
            2, 0, // No of assignments
            1, 0, 1, 3, 1, 0, 1, 0, 172, 198, 241, 181, 165, 20, 213, 54, 40, 73, 173, 36, 33, 53,
            221, 119, 251, 0, 189, 217, 213, 41, 198, 175, 58, 121, 140, 28, 146, 37, 87, 64, 38,
            143, 99, 202, 152, 114, 142, 39, 0, 0, 0, 0, 3, 160, 134, 1, 0, 0, 0, 0, 0, 32, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 2, 0, 0, 0, 0, 0, 0, 1, 0, 119, 31, 120, 181, 213, 239, 72, 20, 181, 14, 218, 85,
            151, 249, 249, 0, 34, 112, 87, 248, 175, 199, 165, 38, 102, 156, 251, 196, 1, 155, 240,
            11, 89, 186, 209, 42, 101, 37, 228, 34, 242, 78, 181, 53, 50, 131, 104, 49, 210, 154,
            160, 244, 233, 215, 118, 60, 109, 208, 57, 250, 158, 106, 0, 250, 1, 0, 40, 60, 217,
            167, 244, 2, 37, 149, 49, 155, 251, 143, 97, 38, 157, 145, 70, 26, 1, 55, 226, 254,
            248, 79, 245, 146, 206, 78, 133, 169, 41, 40, 3, 0, 0, 84, 58, 167, 47, 84, 222, 139,
            254, 20, 54, 254, 23, 40, 20, 240, 121, 252, 19, 90, 52, 55, 246, 119, 163, 115, 68,
            213, 191, 221, 242, 223, 85, 0, 236, 157, 125, 216, 45, 29, 21, 128, 28, 221, 79, 169,
            116, 83, 179, 83, 228, 196, 75, 217, 96, 20, 17, 13, 55, 81, 51, 28, 151, 83, 41, 135,
            1, 44, 67, 210, 154, 72, 87, 82, 60, 148, 202, 96, 0, 34, 227, 220, 39, 91, 26, 55,
            190, 155, 201, 78, 248, 246, 29, 193, 42, 235, 69, 155, 195, 119, 31, 120, 181, 213,
            239, 72, 20, 181, 14, 218, 85, 151, 249, 249, 0, 34, 112, 87, 248, 175, 199, 165, 38,
            102, 156, 251, 196, 1, 155, 240, 11, 1, 126, 204, 108, 187, 10, 227, 183, 4, 3, 158,
            255, 31, 84, 122, 29, 95, 146, 223, 162, 186, 122, 246, 172, 151, 26, 75, 208, 59, 164,
            167, 52, 176, 49, 86, 162, 86, 184, 173, 58, 30, 249, 0, 1, 0, 0, 0, 1, 0, 44, 67, 210,
            154, 72, 87, 82, 60, 148, 202, 96, 0, 34, 227, 220, 39, 91, 26, 55, 190, 155, 201, 78,
            248, 246, 29, 193, 42, 235, 69, 155, 195, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 3, 2,
            0, 2, 89, 186, 209, 42, 101, 37, 228, 34, 242, 78, 181, 53, 50, 131, 104, 49, 210, 154,
            160, 244, 233, 215, 118, 60, 109, 208, 57, 250, 158, 106, 0, 250, 3, 100, 0, 0, 0, 0,
            0, 0, 0, 32, 0, 94, 225, 8, 249, 174, 126, 227, 191, 87, 70, 139, 92, 167, 220, 218,
            31, 21, 6, 130, 248, 84, 18, 137, 87, 242, 81, 220, 82, 184, 99, 93, 135, 1, 0, 50,
            112, 155, 170, 111, 145, 181, 32, 190, 173, 32, 142, 81, 240, 183, 249, 253, 225, 241,
            208, 43, 50, 220, 113, 160, 83, 117, 66, 39, 54, 213, 157, 241, 15, 215, 23, 180, 230,
            84, 244, 1, 0, 0, 0, 3, 60, 134, 1, 0, 0, 0, 0, 0, 32, 0, 161, 30, 247, 6, 81, 129, 28,
            64, 168, 185, 116, 163, 88, 35, 37, 223, 165, 168, 89, 238, 91, 54, 22, 227, 205, 128,
            130, 58, 23, 210, 227, 187, 0, 0,
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
