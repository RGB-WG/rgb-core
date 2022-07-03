// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use stens::TypeRef;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_value, repr = u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[repr(u8)]
pub enum StateType {
    Declarative = 0,
    DiscreteFiniteField = 1,
    CustomData = 2,
    DataContainer = 3,
}

#[derive(Clone, PartialEq, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
pub enum StateSchema {
    Declarative,
    DiscreteFiniteField(DiscreteFiniteFieldFormat),
    CustomData(TypeRef),
    DataContainer,
}

#[derive(Clone, PartialEq, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_value, repr = u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "lowercase")
)]
#[repr(u8)]
/// Today we support only a single format of confidential data, because of the
/// limitations of the underlying secp256k1-zkp library: it works only with
/// u64 numbers. Nevertheless, homomorphic commitments can be created to
/// everything that has up to 256 bits and commutative arithmetics, so in the
/// future we plan to support more types. We reserve this possibility by
/// internally encoding [ConfidentialFormat] with the same type specification
/// details as used for [DateFormat]
pub enum DiscreteFiniteFieldFormat {
    Unsigned64bit,
}

mod _validation {
    use core::any::Any;
    use std::io;

    use amplify::AsAny;
    use commit_verify::CommitConceal;
    use stens::{PrimitiveType, TypeConstr, TypeSystem, Validate};

    use super::*;
    use crate::contract::AttachmentStrategy;
    use crate::data::Revealed;
    use crate::schema::OwnedRightType;
    use crate::validation::Status;
    use crate::{
        data, validation, Assignment, DeclarativeStrategy, HashStrategy, NodeId, PedersenStrategy,
        State,
    };

    pub trait StenValidate {
        fn validate(
            &self,
            type_system: &TypeSystem,
            node_id: NodeId,
            schema_type_id: u16,
            data: &data::Revealed,
        ) -> validation::Status;
    }

    impl StenValidate for PrimitiveType {
        fn validate(
            &self,
            _: &TypeSystem,
            node_id: NodeId,
            schema_type_id: u16,
            data: &data::Revealed,
        ) -> validation::Status {
            let mut status = validation::Status::new();
            match (self, data) {
                (PrimitiveType::U8, data::Revealed::U8(_))
                | (PrimitiveType::U16, data::Revealed::U16(_))
                | (PrimitiveType::U32, data::Revealed::U32(_))
                | (PrimitiveType::U64, data::Revealed::U64(_))
                | (PrimitiveType::U128, data::Revealed::U128(_))
                | (PrimitiveType::U256, data::Revealed::U256(_))
                | (PrimitiveType::U512, data::Revealed::U512(_))
                | (PrimitiveType::U1024, data::Revealed::U1024(_))
                | (PrimitiveType::I8, data::Revealed::I8(_))
                | (PrimitiveType::I16, data::Revealed::I16(_))
                | (PrimitiveType::I32, data::Revealed::I32(_))
                | (PrimitiveType::I64, data::Revealed::I64(_))
                | (PrimitiveType::I128, data::Revealed::I128(_))
                | (PrimitiveType::I256, data::Revealed::I256(_))
                | (PrimitiveType::I512, data::Revealed::I512(_))
                | (PrimitiveType::I1024, data::Revealed::I1024(_))
                | (PrimitiveType::F16b, data::Revealed::F16B(_))
                | (PrimitiveType::F16, data::Revealed::F16(_))
                | (PrimitiveType::F32, data::Revealed::F32(_))
                | (PrimitiveType::F64, data::Revealed::F64(_))
                | (PrimitiveType::F80, data::Revealed::F80(_))
                | (PrimitiveType::F128, data::Revealed::F128(_))
                | (PrimitiveType::F256, data::Revealed::F256(_)) => {}
                _ => {
                    status.add_failure(validation::Failure::InvalidStateDataType(
                        node_id,
                        schema_type_id,
                        TypeRef::Primitive(TypeConstr::Plain(*self)),
                        data.clone(),
                    ));
                }
            }
            status
        }
    }

    impl StenValidate for TypeConstr<PrimitiveType> {
        fn validate(
            &self,
            type_system: &TypeSystem,
            node_id: NodeId,
            schema_type_id: u16,
            data: &Revealed,
        ) -> Status {
            let mut status = validation::Status::new();
            match (self, data) {
                (TypeConstr::Plain(ty), data) => {
                    status +=
                        StenValidate::validate(ty, type_system, node_id, schema_type_id, data);
                }
                (TypeConstr::List(PrimitiveType::AsciiChar), Revealed::AsciiString(_)) => {}
                (TypeConstr::List(PrimitiveType::UnicodeChar), Revealed::UnicodeString(_)) => {}
                (TypeConstr::List(PrimitiveType::U8), Revealed::Bytes(_)) => {}
                _ => {
                    status.add_failure(validation::Failure::InvalidStateDataType(
                        node_id,
                        schema_type_id,
                        TypeRef::Primitive(self.clone()),
                        data.clone(),
                    ));
                }
            }
            status
        }
    }

    impl StenValidate for TypeRef {
        fn validate(
            &self,
            type_system: &TypeSystem,
            node_id: NodeId,
            schema_type_id: u16,
            data: &data::Revealed,
        ) -> validation::Status {
            let mut status = validation::Status::new();
            match (self, data) {
                (TypeRef::Primitive(ty), _) => {
                    status +=
                        StenValidate::validate(ty, type_system, node_id, schema_type_id, data);
                }
                (TypeRef::Named(ty), data::Revealed::Bytes(bytes)) => {
                    let mut cursor = io::Cursor::new(bytes.as_slice());
                    if !ty.validate(type_system, &mut cursor) {
                        status.add_failure(validation::Failure::InvalidStateDataValue(
                            node_id,
                            schema_type_id,
                            self.clone(),
                            bytes.clone(),
                        ));
                    }
                }
                _ => {
                    status.add_failure(validation::Failure::InvalidStateDataType(
                        node_id,
                        schema_type_id,
                        self.clone(),
                        data.clone(),
                    ));
                }
            }
            status
        }
    }

    impl StateSchema {
        pub fn validate<STATE>(
            &self,
            type_system: &TypeSystem,
            node_id: &NodeId,
            assignment_id: OwnedRightType,
            data: &Assignment<STATE>,
        ) -> validation::Status
        where
            STATE: State,
            STATE::Confidential: PartialEq + Eq,
            STATE::Confidential: From<<STATE::Revealed as CommitConceal>::ConcealedCommitment>,
        {
            let mut status = validation::Status::new();
            match data {
                Assignment::Confidential { state, .. }
                | Assignment::ConfidentialState { state, .. } => {
                    let a: &dyn Any = state.as_any();
                    match self {
                        StateSchema::Declarative => {
                            if a.downcast_ref::<<DeclarativeStrategy as State>::Confidential>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                        }
                        StateSchema::DiscreteFiniteField(_) => {
                            if let Some(value) =
                                a.downcast_ref::<<PedersenStrategy as State>::Confidential>()
                            {
                                // [SECURITY-CRITICAL]: Bulletproofs validation
                                if let Err(err) = value.verify_bullet_proof() {
                                    status.add_failure(validation::Failure::InvalidBulletproofs(
                                        *node_id,
                                        assignment_id,
                                        err,
                                    ));
                                }
                            } else {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }

                            // TODO: When other homomorphic formats will be added,
                            //       add information to the status like with
                            //       hashed data below
                        }
                        StateSchema::CustomData(_) => {
                            match a.downcast_ref::<<HashStrategy as State>::Confidential>() {
                                None => {
                                    status.add_failure(
                                        validation::Failure::SchemaMismatchedStateType(
                                            assignment_id,
                                        ),
                                    );
                                }
                                Some(_) => {
                                    status.add_info(
                                        validation::Info::UncheckableConfidentialStateData(
                                            *node_id,
                                            assignment_id,
                                        ),
                                    );
                                }
                            }
                        }
                        StateSchema::DataContainer => {
                            if a.downcast_ref::<<AttachmentStrategy as State>::Confidential>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                        }
                    }
                }
                Assignment::Revealed { state, .. } | Assignment::ConfidentialSeal { state, .. } => {
                    let a: &dyn Any = state.as_any();
                    match self {
                        StateSchema::Declarative => {
                            if a.downcast_ref::<<DeclarativeStrategy as State>::Revealed>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                        }
                        StateSchema::DiscreteFiniteField(_format) => {
                            if a.downcast_ref::<<PedersenStrategy as State>::Revealed>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                            // TODO #15: When other homomorphic formats will be added,
                            //       add type check like with hashed data below
                        }
                        StateSchema::CustomData(format) => {
                            match a.downcast_ref::<<HashStrategy as State>::Revealed>() {
                                None => {
                                    status.add_failure(
                                        validation::Failure::SchemaMismatchedStateType(
                                            assignment_id,
                                        ),
                                    );
                                }
                                Some(data) => {
                                    status += StenValidate::validate(
                                        format,
                                        type_system,
                                        *node_id,
                                        assignment_id,
                                        data,
                                    );
                                }
                            }
                        }
                        StateSchema::DataContainer => {
                            if a.downcast_ref::<<AttachmentStrategy as State>::Revealed>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                        }
                    }
                }
            }
            status
        }
    }
}
pub(super) use _validation::StenValidate;

#[cfg(test)]
mod test {
    use bitcoin::blockdata::transaction::OutPoint;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::sha256;
    use commit_verify::{CommitConceal, TaggedHash};
    use secp256k1zkp::rand::thread_rng;
    use stens::TypeSystem;
    use strict_encoding::StrictDecode;

    use super::*;
    use crate::contract::{data, value, NodeId};
    use crate::validation::Failure;
    use crate::{Assignment, DeclarativeStrategy, HashStrategy, PedersenStrategy};

    // Txids to generate seals
    static TXID_VEC: [&str; 4] = [
        "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e",
        "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06",
        "12072893d951c633dcafb4d3074d1fc41c5e6e64b8d53e3b0705c41bc6679d54",
        "8f75db9f89c7c75f0a54322f18cd4d557ae75c24a8e5a95eae13fe26edc2d789",
    ];

    #[test]
    #[should_panic(expected = r#"EnumValueNotKnown("DiscreteFiniteFieldFormat", 1)"#)]
    fn test_garbage_df_format() {
        let bytes: Vec<u8> =
            vec![1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255];
        DiscreteFiniteFieldFormat::strict_decode(&bytes[..]).unwrap();
    }

    #[test]
    fn test_random() {
        let n = 67u8;
        println!("{}", ::core::mem::size_of_val(&n));
    }
    #[test]
    fn test_state_format() {
        // Create typical assignments
        // Only Revealed and Confidential variants are created for simplicity
        // Which covers the two validation branch
        let mut rng = thread_rng();

        let txid_vec: Vec<bitcoin::Txid> = TXID_VEC
            .iter()
            .map(|txid| bitcoin::Txid::from_hex(txid).unwrap())
            .collect();

        // Create Declarative Assignments
        let assignment_dec_rev = Assignment::<DeclarativeStrategy>::Revealed {
            seal: crate::contract::seal::Revealed::from(OutPoint::new(txid_vec[0], 1)),
            state: data::Void(),
        };

        let assignment_dec_conf = Assignment::<DeclarativeStrategy>::Confidential {
            seal: crate::contract::seal::Revealed::from(OutPoint::new(txid_vec[1], 2))
                .commit_conceal(),
            state: data::Void(),
        };

        // Create Pedersan Assignments
        let assignment_ped_rev = Assignment::<PedersenStrategy>::Revealed {
            seal: crate::contract::seal::Revealed::from(OutPoint::new(txid_vec[0], 1)),
            state: value::Revealed::with_amount(10u64, &mut rng),
        };

        let assignment_ped_conf = Assignment::<PedersenStrategy>::Confidential {
            seal: crate::contract::seal::Revealed::from(OutPoint::new(txid_vec[1], 1))
                .commit_conceal(),
            state: value::Revealed::with_amount(10u64, &mut rng).commit_conceal(),
        };

        // Create CustomData Assignmnets
        let state_data_vec: Vec<data::Revealed> = TXID_VEC
            .iter()
            .map(|data| data::Revealed::Bytes(sha256::Hash::from_hex(data).unwrap().to_vec()))
            .collect();

        let assignment_hash_rev = Assignment::<HashStrategy>::Revealed {
            seal: crate::contract::seal::Revealed::from(OutPoint::new(txid_vec[0], 1)),
            state: state_data_vec[0].clone(),
        };

        let assignment_hash_conf = Assignment::<HashStrategy>::Confidential {
            seal: crate::contract::seal::Revealed::from(OutPoint::new(txid_vec[1], 1))
                .commit_conceal(),
            state: state_data_vec[0].clone().commit_conceal(),
        };

        // Create NodeId amd Stateformats
        let node_id =
            NodeId::from_hex("201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e")
                .unwrap();
        let dec_format = StateSchema::Declarative;
        let ped_format = StateSchema::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit);
        let hash_format = StateSchema::CustomData(TypeRef::bytes());

        // Assert different failure combinations
        let ts = TypeSystem::default();
        assert_eq!(
            dec_format
                .validate(&ts, &node_id, 3u16, &assignment_ped_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            dec_format
                .validate(&ts, &node_id, 3u16, &assignment_ped_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            dec_format
                .validate(&ts, &node_id, 3u16, &assignment_hash_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            dec_format
                .validate(&ts, &node_id, 3u16, &assignment_hash_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );

        assert_eq!(
            ped_format
                .validate(&ts, &node_id, 3u16, &assignment_dec_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            ped_format
                .validate(&ts, &node_id, 3u16, &assignment_dec_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            ped_format
                .validate(&ts, &node_id, 3u16, &assignment_hash_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            ped_format
                .validate(&ts, &node_id, 3u16, &assignment_hash_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );

        assert_eq!(
            hash_format
                .validate(&ts, &node_id, 3u16, &assignment_dec_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            hash_format
                .validate(&ts, &node_id, 3u16, &assignment_dec_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            hash_format
                .validate(&ts, &node_id, 3u16, &assignment_ped_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            hash_format
                .validate(&ts, &node_id, 3u16, &assignment_ped_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
    }
}
