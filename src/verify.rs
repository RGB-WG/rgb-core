// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};

use amplify::confinement::SmallOrdMap;
use amplify::ByteArray;
use single_use_seals::{PublishedWitness, SealError, SealWitness};
use ultrasonic::{
    AuthToken, CallError, CellAddr, Codex, ContractId, LibRepo, Memory, Operation, Opid, VerifiedOperation,
};

use crate::{RgbSeal, RgbSealDef, LIB_NAME_RGB};

/// Combination of an operation with operation-defined seals.
///
/// An operation contains only [`AuthToken`]'s, which are commitments to seal definitions.
/// Hence, we have to separately include a full seal definition next to the operation data.
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound = "Seal::Definition: serde::Serialize + for<'d> serde::Deserialize<'d>, Seal::PubWitness: \
                 serde::Serialize + for<'d> serde::Deserialize<'d>, Seal::CliWitness: serde::Serialize + for<'d> \
                 serde::Deserialize<'d>"
    )
)]
pub struct OperationSeals<Seal: RgbSeal> {
    /// The operation.
    pub operation: Operation,
    /// Seals defined by an operation.
    pub defined_seals: SmallOrdMap<u16, Seal::Definition>,
    /// An optional witness for the closing of the operation input seals.
    pub witness: Option<SealWitness<Seal>>,
}

impl<Seal: RgbSeal> Clone for OperationSeals<Seal>
where
    Seal::PubWitness: Clone,
    Seal::CliWitness: Clone,
{
    fn clone(&self) -> Self {
        Self {
            operation: self.operation.clone(),
            defined_seals: self.defined_seals.clone(),
            witness: self.witness.clone(),
        }
    }
}

/// Provider which reads an operation and its seals from a consignment stream.
pub trait ReadOperation: Sized {
    /// Seal definition type used by operations.
    type Seal: RgbSeal;

    /// Reads an operation and its seals from a consignment stream and initialize the witness
    /// reader.
    fn read_operation(&mut self) -> Option<OperationSeals<Self::Seal>>;
}

/// API exposed by the contract required for evaluating and verifying the contract state (see
/// [`ContractVerify`]).
///
/// NB: `apply_operation` is called only after `apply_witness`.
pub trait ContractApi<Seal: RgbSeal> {
    /// Returns contract id for the processed contract.
    ///
    /// Called only once during the operation verification.
    fn contract_id(&self) -> ContractId;

    /// Returns a codex agains which the contract must be verified.
    ///
    /// Called only once during the operation verification.
    fn codex(&self) -> &Codex;

    /// Returns repository providing script libraries used during the verification.
    ///
    /// Called only once during the operation verification.
    fn repo(&self) -> &impl LibRepo;

    /// Returns a memory implementation providing read access to all the contract state cells,
    /// including immutable and destructible memory.
    fn memory(&self) -> &impl Memory;

    /// Detects whether an operation with a given id is already known as a _valid_ operation for the
    /// ledger.
    ///
    /// The method MUST return `true` for genesis operation.
    fn is_known(&self, opid: Opid) -> bool;

    /// # Nota bene:
    ///
    /// The method is called only for those operations which are not known (i.e. [`Self::is_known`]
    /// returns `false` for the operation id).
    ///
    /// The method is NOT called for the genesis operation.
    fn apply_operation(&mut self, op: VerifiedOperation);

    /// # Nota bene:
    ///
    /// The method is called for all operations, including known ones, for which the consignment
    /// provides at least single seal definition information (thus, it may be called for the genesis
    /// operation as well).
    fn apply_seals(&mut self, opid: Opid, seals: SmallOrdMap<u16, Seal::Definition>);

    /// # Nota bene:
    ///
    /// The method is called for all operations, including known ones, which have a witness (i.e.,
    /// except genesis or operations with no destroyed state).
    fn apply_witness(&mut self, opid: Opid, witness: SealWitness<Seal>);
}

/// Main implementation of the contract verification procedure.
///
/// # Nota bene
///
/// This trait cannot be manually implemented; it is always accessible as a blanked implementation
/// for all types implementing [`ContractApi`] trait.
///
/// The purpose of the trait is to prevent overriding of the implementation in client libraries.
pub trait ContractVerify<Seal: RgbSeal>: ContractApi<Seal> {
    /// Evaluate contract state by verifying and applying contract operations coming from a
    /// consignment `reader`.
    fn evaluate<R: ReadOperation<Seal = Seal>>(&mut self, mut reader: R) -> Result<(), VerificationError<Seal>> {
        let contract_id = self.contract_id();
        let codex_id = self.codex().codex_id();

        let mut is_genesis = true;
        let mut seals = BTreeMap::<CellAddr, Seal>::new();

        while let Some(mut block) = reader.read_operation() {
            // Genesis cannot commit to the contract id since the contract does not exist yet;
            // thus, we have to apply this little trick
            if is_genesis {
                if block.operation.contract_id.to_byte_array() != codex_id.to_byte_array() {
                    return Err(VerificationError::NoCodexCommitment);
                }
                block.operation.contract_id = contract_id;
            }
            let opid = block.operation.opid();

            // We need to check that all seal definitions strictly match operation-defined destructible cells
            let defined = block
                .operation
                .destructible_out
                .iter()
                .map(|cell| cell.auth)
                .collect::<BTreeSet<_>>();
            let reported = block
                .defined_seals
                .values()
                .map(|seal| seal.auth_token())
                .collect::<BTreeSet<_>>();
            // It is a subset and not an equal set since some seals might be unknown to us:
            // we know their commitment auth token but do not know the definition.
            if !reported.is_subset(&defined) {
                let sources = block
                    .defined_seals
                    .iter()
                    .map(|(pos, seal)| (*pos, seal.to_string()))
                    .collect();
                return Err(VerificationError::SealsDefinitionMismatch { opid, reported, defined, sources });
            }

            // Collect single-use seal closings by the operation
            let mut closed_seals = Vec::<Seal>::new();
            for input in &block.operation.destructible_in {
                let seal = seals
                    .remove(&input.addr)
                    .ok_or(VerificationError::SealUnknown(input.addr))?;
                closed_seals.push(seal);
            }

            // If the operation was validated before, we need to skip its validation, since its inputs are not a
            // part of the state anymore.
            let operation = if self.is_known(opid) {
                None
            } else {
                // Verify the operation
                let verified = self
                    .codex()
                    .verify(contract_id, block.operation, self.memory(), self.repo())?;
                Some(verified)
            };

            // This convoluted logic happens since we use a state machine which ensures the client can't lie to
            // the verifier
            // Now we can add operation-defined seals to the set of known seals
            let mut seal_sources: BTreeSet<_> = block
                .defined_seals
                .iter()
                .filter_map(|(pos, seal)| seal.to_src().map(|seal| (CellAddr::new(opid, *pos), seal)))
                .collect();

            if let Some(witness) = block.witness {
                let msg = opid.to_byte_array();
                witness
                    .verify_seals_closing(&closed_seals, msg.into())
                    .map_err(|e| VerificationError::SealsNotClosed(witness.published.pub_id(), opid, e))?;

                //  Each witness actually produces its own set of witness-output-based seal sources.
                let pub_id = witness.published.pub_id();
                let iter = block
                    .defined_seals
                    .iter()
                    .filter(|(_, seal)| seal.to_src().is_none())
                    .map(|(pos, seal)| (CellAddr::new(opid, *pos), seal.resolve(pub_id)));
                seal_sources.extend(iter);

                self.apply_witness(opid, witness);
            } else if !closed_seals.is_empty() {
                return Err(VerificationError::NoWitness(opid));
            }

            seals.extend(seal_sources);
            if is_genesis {
                is_genesis = false
            } else if let Some(operation) = operation {
                self.apply_operation(operation);
            }

            if !block.defined_seals.is_empty() {
                self.apply_seals(opid, block.defined_seals);
            }
        }

        Ok(())
    }
}

impl<Seal: RgbSeal, C: ContractApi<Seal>> ContractVerify<Seal> for C {}

/// Errors returned from the verification.
#[derive(Display, Error, From)]
#[display(doc_comments)]
pub enum VerificationError<Seal: RgbSeal> {
    /// genesis does not commit to the codex id; a wrong contract genesis is used.
    NoCodexCommitment,

    /// no witness known for the operation {0}.
    NoWitness(Opid),

    /// single-use seals are not closed properly with witness {0} for operation {1}.
    ///
    /// Details: {2}
    SealsNotClosed(<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Opid, SealError<Seal>),

    /// unknown seal definition for cell address {0}.
    SealUnknown(CellAddr),

    /// seals, reported to be defined by the operation {opid}, do match the assignments in the
    /// operation.
    ///
    /// Actual operation seals from the assignments: {defined:#?}
    ///
    /// Reported seals: {reported:#?}
    ///
    /// Sources for the reported seals: {sources:#?}
    #[allow(missing_docs)]
    SealsDefinitionMismatch {
        opid: Opid,
        reported: BTreeSet<AuthToken>,
        defined: BTreeSet<AuthToken>,
        sources: BTreeMap<u16, String>,
    },

    /// Eror returned by the virtual machine script.
    #[from]
    #[display(inner)]
    Vm(CallError),
}

// We need manual implementation since otherwise we get an unneeded `Seal::PubWitness: Debug` bound
impl<Seal: RgbSeal> Debug for VerificationError<Seal> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result { write!(f, "{}", self) }
}

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use std::collections::HashMap;
    use std::vec;

    use bp::seals::{TxoSeal, TxoSealExt, WOutpoint, WTxoSeal};
    use bp::{Outpoint, Sats, ScriptPubkey, SeqNo, Tx, TxIn, TxOut, Vout};
    use strict_encoding::StrictDumb;
    use ultrasonic::aluvm::alu::{aluasm, CoreConfig, Lib, LibId, LibSite};
    use ultrasonic::aluvm::FIELD_ORDER_SECP;
    use ultrasonic::{fe256, CodexId, Genesis, Identity, Input, StateCell, StateData, StateValue};

    use super::*;

    #[derive(Clone)]
    struct TestReader(vec::IntoIter<OperationSeals<TxoSeal>>);
    impl ReadOperation for TestReader {
        type Seal = TxoSeal;
        fn read_operation(&mut self) -> Option<OperationSeals<Self::Seal>> { self.0.next() }
    }
    impl TestReader {
        pub fn new(vec: Vec<OperationSeals<TxoSeal>>) -> Self { Self(vec.into_iter()) }
    }

    struct TestContract {
        pub codex: Codex,
        pub contract_id: ContractId,
        pub libs: HashMap<LibId, Lib>,
        pub global: HashMap<CellAddr, StateValue>,
        pub owned: HashMap<CellAddr, StateCell>,
        pub known_ops: BTreeMap<Opid, Operation>,
        pub seal_definitions: BTreeMap<Opid, HashMap<u16, WTxoSeal>>,
        pub witnesses: BTreeMap<Opid, Vec<SealWitness<TxoSeal>>>,
    }
    impl Memory for TestContract {
        fn destructible(&self, addr: CellAddr) -> Option<StateCell> { self.owned.get(&addr).cloned() }
        fn immutable(&self, addr: CellAddr) -> Option<StateValue> { self.global.get(&addr).cloned() }
    }
    impl LibRepo for TestContract {
        fn get_lib(&self, lib_id: LibId) -> Option<&Lib> { self.libs.get(&lib_id) }
    }
    impl ContractApi<TxoSeal> for TestContract {
        fn contract_id(&self) -> ContractId { self.contract_id }
        fn codex(&self) -> &Codex { &self.codex }
        fn repo(&self) -> &impl LibRepo { self }
        fn memory(&self) -> &impl Memory { self }
        fn is_known(&self, opid: Opid) -> bool { self.known_ops.contains_key(&opid) }
        fn apply_operation(&mut self, op: VerifiedOperation) {
            let opid = op.opid();
            let op = op.into_operation();
            for (no, inp) in op.immutable_out.iter().enumerate() {
                self.global
                    .insert(CellAddr::new(opid, no as u16), inp.value);
            }
            for (no, inp) in op.destructible_out.iter().enumerate() {
                self.owned.insert(CellAddr::new(opid, no as u16), *inp);
            }
            self.known_ops.insert(opid, op);
        }
        fn apply_seals(&mut self, opid: Opid, seals: SmallOrdMap<u16, WTxoSeal>) {
            self.seal_definitions.entry(opid).or_default().extend(seals);
        }
        fn apply_witness(&mut self, opid: Opid, witness: SealWitness<TxoSeal>) {
            self.witnesses.entry(opid).or_default().push(witness);
        }
    }

    fn lib() -> Lib {
        let code = aluasm! {
            stop;
        };
        Lib::assemble(&code).unwrap()
    }

    fn codex() -> Codex {
        let lib_id = lib().lib_id();
        Codex {
            name: tiny_s!("TestCodex"),
            developer: Identity::default(),
            version: default!(),
            timestamp: 1732529307,
            field_order: FIELD_ORDER_SECP,
            input_config: CoreConfig::default(),
            verification_config: CoreConfig::default(),
            verifiers: tiny_bmap! {
                0 => LibSite::new(lib_id, 0),
            },
        }
    }

    const SEAL_WOUT: WTxoSeal = WTxoSeal {
        primary: WOutpoint::Wout(Vout::from_u32(0)),
        secondary: TxoSealExt::Fallback(Outpoint::coinbase()),
    };

    const SEAL_1: WTxoSeal = WTxoSeal {
        primary: WOutpoint::Extern(Outpoint::coinbase()),
        secondary: TxoSealExt::Fallback(Outpoint::coinbase()),
    };

    fn genesis() -> Genesis {
        let mut genesis = Genesis::strict_dumb();
        genesis.codex_id = codex().codex_id();
        genesis.immutable_out = small_vec![StateData::new(0u64, 1000u64)];
        genesis.destructible_out = small_vec![StateCell {
            data: StateValue::None,
            auth: SEAL_1.auth_token(),
            lock: None
        }];
        genesis
    }

    fn contract() -> TestContract {
        let lib = lib();
        let lib_id = lib.lib_id();
        let genesis = genesis();
        let genesis_op = genesis.to_operation(ContractId::strict_dumb());
        let genesis_opid = genesis_op.opid();
        TestContract {
            codex: codex(),
            contract_id: ContractId::strict_dumb(),
            libs: map! { lib_id => lib },
            global: none!(),
            owned: map! { CellAddr::new(genesis_opid, 0) => genesis_op.destructible_out[0] },
            known_ops: bmap! { genesis_opid => genesis_op },
            seal_definitions: bmap! { genesis_opid => none!() },
            witnesses: bmap! { genesis_opid => none!() },
        }
    }

    fn operation() -> Operation {
        let genesis = genesis();
        let contract = contract();
        let genesis_op = genesis.to_operation(contract.contract_id);
        let genesis_opid = genesis_op.opid();
        Operation {
            version: default!(),
            contract_id: contract.contract_id,
            call_id: 0,
            nonce: fe256::ZERO,
            destructible_in: small_vec![Input {
                addr: CellAddr::new(genesis_opid, 0),
                witness: StateValue::None
            }],
            immutable_in: Default::default(),
            destructible_out: Default::default(),
            immutable_out: Default::default(),
        }
    }

    #[allow(clippy::result_large_err)]
    fn run(reader: TestReader) -> Result<(), VerificationError<TxoSeal>> {
        let mut contract = contract();
        contract.evaluate(reader.clone())?;

        // Check contract values
        let mut ops = bmap! {};
        let mut seals = bmap! {};
        let mut witnesses = bmap! {};
        for entry in reader.0 {
            let opid = entry.operation.opid();
            ops.insert(opid, entry.operation);
            seals.insert(opid, entry.defined_seals.into_iter().collect());
            witnesses.insert(opid, entry.witness.into_iter().collect());
        }

        ops.pop_first();
        let (genesis_opid, genesis_op) = contract.known_ops.first_key_value().unwrap();
        ops.insert(*genesis_opid, genesis_op.clone());
        seals.pop_first();
        let (genesis_opid, definitions) = contract.seal_definitions.first_key_value().unwrap();
        seals.insert(*genesis_opid, definitions.clone());
        witnesses.pop_first();
        let (genesis_opid, definitions) = contract.witnesses.first_key_value().unwrap();
        witnesses.insert(*genesis_opid, definitions.clone());

        assert_eq!(ops, contract.known_ops);
        assert_eq!(seals, contract.seal_definitions);
        assert_eq!(witnesses, contract.witnesses);
        Ok(())
    }

    #[test]
    fn empty() {
        let reader = TestReader::new(vec![]);
        run(reader).unwrap();
    }

    #[test]
    fn genesis_only() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());

        let reader =
            TestReader::new(vec![OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None }]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "genesis does not commit to the codex id; a wrong contract genesis is used.")]
    fn invalid_genesis() {
        let mut genesis = genesis();
        genesis.codex_id = CodexId::from_byte_array([0xAD; 32]);
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());

        let reader =
            TestReader::new(vec![OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None }]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "seals, reported to be defined by the operation \
                               eGD_HVjMj03qdCv7U_~k4qXGHKmcWVhEnOsM8gBj24M, do match the assignments in the \
                               operation.
Actual operation seals from the assignments: {
    AuthToken(
        fe256(
            0x0000141b74832b85ca7bc7e2899cc3e5617a29ac4340f09b105524a6f62bd597,
        ),
    ),
}
Reported seals: {
    AuthToken(
        fe256(
            0x000046c31ad97975e90e4ab2ee247f0e2f39ec8461823023e977cc14bcda14f5,
        ),
    ),
}
Sources for the reported seals: {
    0: \"~:0/00000000000000000000000000000000000000000000000000000000000000000000000000000000\",
}")]
    fn invalid_seals() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());

        let reader = TestReader::new(vec![OperationSeals {
            operation: genesis_op,
            defined_seals: small_bmap! { 0 => WTxoSeal::strict_dumb() },
            witness: None,
        }]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "unknown seal definition for cell address eGD_HVjMj03qdCv7U_~k4qXGHKmcWVhEnOsM8gBj24M:0.")]
    fn seal_unknown() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let reader = TestReader::new(vec![
            OperationSeals { operation: genesis_op, defined_seals: none!(), witness: None },
            OperationSeals { operation, defined_seals: none!(), witness: None },
        ]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "unknown seal definition for cell address eGD_HVjMj03qdCv7U_~k4qXGHKmcWVhEnOsM8gBj24M:0.")]
    fn genesis_with_wout() {
        let mut genesis = genesis();
        genesis.destructible_out[0].auth = SEAL_WOUT.auth_token();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let reader = TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_WOUT},
                witness: None,
            },
            OperationSeals { operation, defined_seals: none!(), witness: None },
        ]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "no witness known for the operation 6_oY0~xLEvJQgUHMU6POEjXm0I3PeaUWYiY1E2IHfm0.")]
    fn no_witness() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let reader = TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_1 },
                witness: None,
            },
            OperationSeals { operation, defined_seals: none!(), witness: None },
        ]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "single-use seals are not closed properly with witness \
                               4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a for operation \
                               6_oY0~xLEvJQgUHMU6POEjXm0I3PeaUWYiY1E2IHfm0.
Details: seal \
                               0000000000000000000000000000000000000000000000000000000000000000:0/\
                               0000000000000000000000000000000000000000000000000000000000000000:0 is not included in \
                               the public witness 4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a")]
    fn seals_unclosed() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let reader = TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_1 },
                witness: None,
            },
            OperationSeals {
                operation,
                defined_seals: none!(),
                witness: Some(SealWitness::new(strict_dumb!(), strict_dumb!())),
            },
        ]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "ingle-use seals are not closed properly with witness \
                               1692606e775129a6733b6dc48ec7f5771f8e30d8c5304c0949d36efad2411812 for operation \
                               6_oY0~xLEvJQgUHMU6POEjXm0I3PeaUWYiY1E2IHfm0.
Details: seal \
                               0000000000000000000000000000000000000000000000000000000000000000:0/\
                               0000000000000000000000000000000000000000000000000000000000000000:0 is not included in \
                               the public witness 1692606e775129a6733b6dc48ec7f5771f8e30d8c5304c0949d36efad2411812")]
    fn not_spending_utxo() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let mut witness = Tx::strict_dumb();
        witness
            .outputs
            .push(TxOut {
                value: Sats::ZERO,
                script_pubkey: ScriptPubkey::op_return(&[]),
            })
            .unwrap();

        let reader = TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_1 },
                witness: None,
            },
            OperationSeals {
                operation,
                defined_seals: none!(),
                witness: Some(SealWitness::new(witness, strict_dumb!())),
            },
        ]);
        run(reader).unwrap();
    }

    #[test]
    #[should_panic(expected = "single-use seals are not closed properly with witness \
                               0520b790b442e9c023e2ea0e0e284fbe60086d64f01037082f19464b44f9642e for operation \
                               6_oY0~xLEvJQgUHMU6POEjXm0I3PeaUWYiY1E2IHfm0.
Details: seal \
                               0000000000000000000000000000000000000000000000000000000000000000:0/\
                               0000000000000000000000000000000000000000000000000000000000000000:0 is not included in \
                               the public witness 0520b790b442e9c023e2ea0e0e284fbe60086d64f01037082f19464b44f9642e")]
    fn missing_commitment() {
        let genesis = genesis();
        let genesis_op = genesis.to_operation(genesis.codex_id.to_byte_array().into());
        let operation = operation();

        let mut witness = Tx::strict_dumb();
        witness
            .inputs
            .push(TxIn {
                prev_output: Outpoint::coinbase(),
                sig_script: none!(),
                sequence: SeqNo::from_consensus_u32(0),
                witness: none!(),
            })
            .unwrap();
        witness
            .outputs
            .push(TxOut {
                value: Sats::ZERO,
                script_pubkey: ScriptPubkey::op_return(&[]),
            })
            .unwrap();

        let reader = TestReader::new(vec![
            OperationSeals {
                operation: genesis_op,
                defined_seals: small_bmap! { 0 => SEAL_1 },
                witness: None,
            },
            OperationSeals {
                operation,
                defined_seals: none!(),
                witness: Some(SealWitness::new(witness, strict_dumb!())),
            },
        ]);
        run(reader).unwrap();
    }
}
