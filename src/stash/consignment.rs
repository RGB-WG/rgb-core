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

use bitcoin::hashes::{sha256, sha256t};
use bitcoin::Txid;
use lnpbp::bech32::{self, ToBech32String};
use lnpbp::client_side_validation::{
    commit_strategy, commit_verify::CommitVerify, CommitEncodeWithStrategy,
    ConsensusCommit,
};
use lnpbp::seals::{OutpointHash, OutpointReveal};
use lnpbp::TaggedHash;

use crate::{
    validation, Anchor, Extension, Genesis, Node, NodeId, Schema, Transition,
    Validator,
};

pub type ConsignmentEndpoints = Vec<(NodeId, OutpointHash)>;
pub type TransitionData = Vec<(Anchor, Transition)>;
pub type ExtensionData = Vec<Extension>;

pub const RGB_CONSIGNMENT_VERSION: u16 = 0;

static MIDSTATE_CONSIGNMENT_ID: [u8; 32] = [
    8, 36, 37, 167, 51, 70, 76, 241, 171, 132, 169, 56, 76, 108, 174, 226, 197,
    98, 75, 254, 29, 125, 170, 233, 184, 121, 13, 183, 90, 51, 134, 6,
];

/// Tag used for [`NodeId`] and [`ContractId`] hash types
pub struct ConsignmentIdTag;

impl sha256t::Tag for ConsignmentIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_CONSIGNMENT_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Unique consignment identifier equivalent to the commitment hash
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Wrapper,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[wrapper(Debug, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[display(ConsignmentId::to_bech32_string)]
pub struct ConsignmentId(sha256t::Hash<ConsignmentIdTag>);

impl<MSG> CommitVerify<MSG> for ConsignmentId
where
    MSG: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &MSG) -> ConsignmentId {
        ConsignmentId::hash(msg)
    }
}

impl CommitEncodeWithStrategy for ConsignmentId {
    type Strategy = commit_strategy::UsingStrict;
}

impl bech32::Strategy for ConsignmentId {
    const HRP: &'static str = "id";
    type Strategy = bech32::strategies::UsingStrictEncoding;
}

#[derive(Clone, PartialEq, Eq, Debug, Display, StrictEncode, StrictDecode)]
#[display(Consignment::to_bech32_string)]
pub struct Consignment {
    version: u16,
    pub genesis: Genesis,
    pub endpoints: ConsignmentEndpoints,
    pub state_transitions: TransitionData,
    pub state_extensions: ExtensionData,
}

impl lightning_encoding::Strategy for Consignment {
    type Strategy = lightning_encoding::strategies::AsStrict;
}

impl CommitEncodeWithStrategy for Consignment {
    type Strategy = commit_strategy::UsingStrict;
}

impl ConsensusCommit for Consignment {
    type Commitment = ConsignmentId;
}

impl bech32::Strategy for Consignment {
    const HRP: &'static str = "consignment";
    type Strategy = bech32::strategies::CompressedStrictEncoding;
}

impl Consignment {
    #[inline]
    pub fn with(
        genesis: Genesis,
        endpoints: ConsignmentEndpoints,
        state_transitions: TransitionData,
        state_extensions: ExtensionData,
    ) -> Consignment {
        Self {
            version: RGB_CONSIGNMENT_VERSION,
            genesis,
            endpoints,
            state_extensions,
            state_transitions,
        }
    }

    #[inline]
    pub fn id(&self) -> ConsignmentId {
        self.clone().consensus_commit()
    }

    #[inline]
    pub fn txids(&self) -> BTreeSet<Txid> {
        self.state_transitions
            .iter()
            .map(|(anchor, _)| anchor.txid)
            .collect()
    }

    #[inline]
    pub fn node_ids(&self) -> BTreeSet<NodeId> {
        let mut set = bset![self.genesis.node_id()];
        set.extend(
            self.state_transitions
                .iter()
                .map(|(_, node)| node.node_id()),
        );
        set.extend(self.state_extensions.iter().map(Extension::node_id));
        set
    }

    pub fn validate<R: validation::TxResolver>(
        &self,
        schema: &Schema,
        resolver: R,
    ) -> validation::Status {
        Validator::validate(schema, self, resolver)
    }

    /// Reveals previously known seal information (replacing blind UTXOs with
    /// unblind ones). Function is used when a peer receives consignment
    /// containing concealed seals for the outputs owned by the peer
    pub fn reveal_seals<'a>(
        &mut self,
        known_seals: impl Iterator<Item = &'a OutpointReveal> + Clone,
    ) -> usize {
        let counter = 0;
        for (_, transition) in &mut self.state_transitions {
            transition.owned_rights_mut().into_iter().fold(
                counter,
                |counter, (_, assignment)| {
                    counter + assignment.reveal_seals(known_seals.clone())
                },
            );
        }
        for extension in &mut self.state_extensions {
            extension.owned_rights_mut().into_iter().fold(
                counter,
                |counter, (_, assignment)| {
                    counter + assignment.reveal_seals(known_seals.clone())
                },
            );
        }
        counter
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::schema::test::schema;
    use crate::validation::TxResolver;
    use lnpbp::strict_encoding::StrictDecode;
    use lnpbp::tagged_hash;

    static CONSIGNMENT: [u8; 1555] = include!("../../test/consignment.in");

    pub(crate) fn consignment() -> Consignment {
        Consignment::strict_decode(&CONSIGNMENT[..]).unwrap()
    }

    struct TestResolver;

    impl TxResolver for TestResolver {
        fn resolve(
            &self,
            txid: &Txid,
        ) -> Result<
            Option<(bitcoin::Transaction, u64)>,
            validation::TxResolverError,
        > {
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

    #[test]
    fn test_consignment_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:consignment");
        assert_eq!(**midstate, MIDSTATE_CONSIGNMENT_ID);
    }

    #[test]
    fn test_consignment_bech32() {
        let consignment = consignment();
        assert_eq!(
            "id1shgyllf9v399wmsgryf7h8sxkuw2sqenfx6tsg9z3gfu69az8shs3nh86v",
            consignment.id().to_string()
        );
        assert_eq!(
            "consignment1qxz4x7e563u3fll7vmjrjwx7j8rscr2e2602hdpz2wsmt6e\
        4n8gxg0fx3ldx5xrf6rqa4g434q8vnz3n3hghsxm09xjlyxynz8n8s4pjg70x8z735qnvnn\
        kga8k870nlm3enla77a77lw7l0hyq83d7avmmmh6777je8keckayc4zllhlxaf2tr8n84r2\
        w467mc2mtfzqneqr33ad8jfxufw29mtjk8evh0m86jkwg00yta72g2ngmerqlzfqqfyggxw\
        j8yp5jszyferk4ykpqq52t5843c4z2aa7sd6qqvv9spxc3hpwtqxqxcwyg9yfvjznaruuju\
        j69snfsap7yc3pyn9vajgy2m6kz3qfprzyq22pgw0w0vvs5j240zyg43qnfqggg69cmyq2w\
        h5ykm4larhvjqgmzprfyqcvhz4yg2yyc55sc5z3yysf9ey43p6rnth64yuraac2lk5dkda3\
        9dsxmf0saxtk6suepl7hhjyuwwgmv6rmxm68v6vyjhmaf68sfkspsd7d0swf0tzfgmeh0jz\
        33tsm4e2263327lqg3nshyudrp9kwqlzp6ldz4h54lqruzwvr4wq7uqlprprpx2t9dgnrft\
        2slcy97agpujm9mhzd7tev260r9zecdr4hf8j0hap5530vjknw5a0936l8ff56plcl8cs3u\
        gugtje3qtne6pf8tmxllufelverx502kpf24wnk7nu7htgeu5emf9ktke4qx0xn58q307fa\
        aa2auy034yztn9tryvv9ek3dfd04tztelkxxs8qtssjhr54l5uf8d4sk0v94604pkw5rcxl\
        0uq3ku5xz6axvvryhm3sw3jxwkmgqkfx7q30mgcvp3htqhw7f526udtjhum50m5n7sr8mqe\
        2mlrg0ck42rh65txh2srqhwtztklezc5aj9gvczmpk9pud347vjzshngkswlustlfql4seu\
        ny0s67l56caq28u0r64r68n0y20erxw8sypt7567sp7gey874yyenepwdyt6cnf07kd4nrg\
        j4xltyte9858p2teg345rfnmpj5jpegyp4a8mayulp98efnv7p67fyu5gcrqgnj2awvfw09\
        gy4dy7n60m5xxvwv3dc6ej34tggdqa2h5xp69wdxw2gk03n08zpd0v0xr2amc753ze6955x\
        gak79mx0e0s3eqv0fg30xqumgcsu369j4u3nxfz49hk0902kscjs67a9rcgt2d836khcade\
        khmn7rsnlr4clmqe95v4yswdukjss0qhsn8zw6d2x6n6e837dgqhxyq7zrpf8ajgefy5epl\
        hv7m3ekputdy2mkhg7ml7e57lth88d9x4a4q2wn39r0q657hycn6skc5845lq2uck99rm9x\
        y5jz6gnd46ghvft3tak4x4d74d63zyp24sucgyz9apwy5ryuwxq8tswd3n7z7k4pyv6ssc8\
        2vqnns99znryscywrkczmfj487m7yvr9an9fzlgtp059mmlntqmnpej2mp8c256n48t64mn\
        qanfmhpz3wlvfa0uly8pzlhgsm7vpcm25j2efew8xyh4xt4h54gzscwl5wk0e2ugv4a2zek\
        kea8k6n6r7yftvwffaav7wk9qf7lz0574qx0kx4z6s99y9naqt5yh49mwxr486u602p5m34\
        v72jsqadleeefcmk3k3zsaepescy36tjf0ra9clrhmw43vndgvpzla9t3lpyqzfhm0wqlqg\
        d2l6x05x0p3dkgerla9jcchg4a440qgvadlun02duk9fm8jwd2m4ygs00susc8epuhvw8de\
        56668jkuuam6tfs0n8sul5hfukvd3ag82lu7cddnw4fgtegjecc9p8phm6w6th0avh88z8h\
        lma37wrqwr8el6wrf4cepy3kfaukww20u00r7c5cfj8w7gcqkppkf8g8ghuwxarpxmnh875\
        g699q50ekv2e9u2e94ny8tshgal5v9dejuwgz0x7g3amh9gt00halh9dcayl27yhksl66tk\
        tjt5gyfm8gls7k9ya4h4slf0deqlthrrxkjl6ekccnxt7yd9u6pxu99k4w9jvch3g0ldce8\
        ng9zlfgx6t95uakg2v0ezeke903q4vs09vdte39rqced0mw3ua9plkc8my2rnwef643cuj2\
        lmwte6r4xlu6wkxmt0s3w07a5a0uqcz74flw",
            consignment.to_string()
        );
    }
}
