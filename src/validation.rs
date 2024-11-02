// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use std::borrow::Borrow;
use std::error::Error;
use std::fmt::Debug;
use std::marker::PhantomData;

use aluvm::Lib;
use amplify::confinement::{MediumOrdMap, SmallDeque, TinyOrdMap, TinyOrdSet};
use single_use_seals::SealWitness;

use crate::{
    Assign, Assignments, ContractId, Extension, Genesis, GlobalState, GlobalStateType, OpId, Opout, RgbSeal, RgbVm,
    Schema, SchemaId, Transition, VerifiableState, VmError, VmSchema, LIB_NAME_RGB_LOGIC,
};

pub trait RgbWitness<Seal>: SealWitness<Seal, Message = (ContractId, OpId)> + Ord + Debug {
    fn order(&self) -> impl Ord;
}

/// Error validating and computing the contract state.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ValidationError<E: Error> {
    /// operation {0} belongs to a different contract {1}.
    InvalidContract(OpId, ContractId),

    /// state transition {transition_id} contains an input referencing non-existing assignment
    /// {prev_out}.
    InvalidInput { transition_id: OpId, prev_out: Opout },

    /// too many unspent assignments, consider compressing history with zk-STARKs.
    TooManyUnspent,

    #[display(inner)]
    Seal(E),

    #[from]
    #[display(inner)]
    Vm(VmError),
}

/// Contract repository API should be implemented by any object which hosts consistent and complete
/// RGB contract information; for instance by consignments and stash.
pub trait ContractRepository<Seal: RgbSeal, Witness: RgbWitness<Seal>> {
    fn transitions(&self) -> impl Iterator<Item = (impl Borrow<Witness>, impl Borrow<Transition<Seal>>)>;
    fn extension(&self, opid: OpId) -> Option<impl Borrow<Extension<Seal>>>;
    fn libs(&self) -> impl Borrow<TinyOrdSet<Lib>>;
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct GlobalRef {
    pub opid: OpId,
    pub pos: u16,
    pub state: VerifiableState,
}

// TODO: Add rolling bloom filter for the validated transitions.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase", bound = "Seal: serde::Serialize + serde::de::DeserializeOwned")
)]
pub struct VerifiedContractState<Seal: RgbSeal, Witness: RgbWitness<Seal>> {
    pub contract_id: ContractId,
    pub schema_id: SchemaId,
    pub global_limits: TinyOrdMap<GlobalStateType, u16>,
    pub global: TinyOrdMap<GlobalStateType, SmallDeque<GlobalRef>>,
    /// Unspent operations' outputs.
    ///
    /// There could be up to 2^24 unspent outputs participating in some history at the same time.
    /// If the number of outputs grows lager, a zk-STARK compression should be applied.
    pub unspent: MediumOrdMap<Opout, Assign<Seal>>,
    #[strict_type(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    _phantom: PhantomData<Witness>,
}

impl<Seal: RgbSeal, Witness: RgbWitness<Seal>> VerifiedContractState<Seal, Witness> {
    fn new_inner(genesis: &Genesis<Seal>) -> Self {
        Self {
            contract_id: genesis.contract_id(),
            schema_id: genesis.schema_id(),
            global_limits: TinyOrdMap::from_iter_checked(
                genesis
                    .schema
                    .global
                    .iter()
                    .map(|(ty, sc)| (*ty, sc.max_len)),
            ),
            unspent: none!(),
            global: none!(),
            _phantom: PhantomData,
        }
    }

    /// Constructs initial contract state out of genesis data.
    pub fn new(genesis: &Genesis<Seal>, libs: &TinyOrdSet<Lib>) -> Result<Self, ValidationError<Witness::Error>> {
        let mut me = Self::new_inner(genesis);
        let mut vm = me.vm(&genesis.schema, libs);
        me.validate_genesis(&mut vm, genesis)?;
        Ok(me)
    }

    /// Computes and validates contract state starting from genesis.
    pub fn with(
        genesis: &Genesis<Seal>,
        repo: &impl ContractRepository<Seal, Witness>,
    ) -> Result<Self, ValidationError<Witness::Error>> {
        let mut me = Self::new_inner(genesis);
        let mut vm = me.vm(&genesis.schema, repo.libs().borrow());
        me.validate_genesis(&mut vm, genesis)?;
        me.validate_history(vm, repo)?;
        Ok(me)
    }

    /// Validates and evolves contract state given additional operations.
    ///
    /// The operation is not idempotent: the client of the API must ensure
    /// [`ContractRepository::transitions`] do provide the same transition twice, or transitions
    /// which were already processed in previous calls to [`Self::extend`] and [`Self::with`]
    /// methods.
    pub fn extend(
        &mut self,
        schema: &Schema,
        repo: &impl ContractRepository<Seal, Witness>,
    ) -> Result<(), ValidationError<Witness::Error>> {
        assert_eq!(self.schema_id, schema.schema_id(), "invalid schema for the contract {}", self.contract_id);

        let vm = self.vm(schema, repo.libs().borrow());
        self.validate_history(vm, repo)?;
        Ok(())
    }

    fn vm(&self, schema: &Schema, libs: &TinyOrdSet<Lib>) -> RgbVm {
        match &schema.vm {
            VmSchema::AluVm(isa, config) => RgbVm::with(isa, *config, schema.validators.clone(), libs),
        }
    }

    fn validate_history(
        &mut self,
        mut vm: RgbVm,
        repo: &impl ContractRepository<Seal, Witness>,
    ) -> Result<(), ValidationError<Witness::Error>> {
        let mut prev_witness = None;
        for (witness, transition) in repo.transitions() {
            let transition = transition.borrow();
            let trans_id = transition.opid();

            if let Some(witness_before) = prev_witness.replace(witness) {
                assert!(
                    witness_before.borrow().order() <= prev_witness.as_ref().unwrap().borrow().order(),
                    "the client of RGB consensus API provides invalid ordering of single-use seal witnesses",
                );
            }
            let witness_ref = prev_witness.as_ref().expect("just replaced").borrow();

            // Collect inputs
            let mut closed_seals = vec![];
            for input in &transition.inputs {
                // If input is not known, try to find it in a state extension
                if !self.unspent.contains_key(&input.prev_out) {
                    let prev_opid = input.prev_out.op;
                    if let Some(extension) = repo.extension(prev_opid) {
                        let extension = extension.borrow();
                        assert_eq!(
                            extension.opid(),
                            prev_opid,
                            "client of RGB consensus API provides invalid with state extension for {prev_opid}; the \
                             use of this software is unsafe."
                        );
                        self.validate_extension(&mut vm, extension)?;
                    }
                }

                // Now, if input is unknown (and was not found in extensions) it means that the contract is invalid
                let Some(input_assignment) = self.unspent.get(&input.prev_out) else {
                    return Err(ValidationError::InvalidInput {
                        transition_id: trans_id,
                        prev_out: input.prev_out,
                    });
                };

                closed_seals.push(input_assignment.seal);
            }

            // Check that the witness closes all seals from the state transition inputs
            witness_ref
                .verify_many_seals(&closed_seals, &(self.contract_id, trans_id))
                .map_err(ValidationError::Seal)?;
            // Validate transition with VM
            self.validate_transition(&mut vm, transition)?;

            // Remove inputs from unspents
            for input in &transition.inputs {
                let was_present = self.unspent.remove(&input.prev_out);
                debug_assert!(matches!(was_present, Ok(Some(_))));
            }
        }
        Ok(())
    }

    fn validate_genesis(
        &mut self,
        vm: &mut RgbVm,
        genesis: &Genesis<Seal>,
    ) -> Result<(), ValidationError<Witness::Error>> {
        debug_assert!(self.global.is_empty());
        debug_assert!(self.unspent.is_empty());
        vm.validate_genesis(&genesis.metadata, &genesis.globals, &genesis.assignments)?;
        self.process_state(genesis.opid(), &genesis.globals, &genesis.assignments)
    }

    fn validate_extension(
        &mut self,
        vm: &mut RgbVm,
        se: &Extension<Seal>,
    ) -> Result<(), ValidationError<Witness::Error>> {
        if se.contract_id != self.contract_id {
            return Err(ValidationError::InvalidContract(se.opid(), se.contract_id));
        }
        vm.validate_extension(se.extension_type, &self.global, &se.metadata, &se.globals, &se.assignments)?;
        self.process_state(se.opid(), &se.globals, &se.assignments)
    }

    fn validate_transition(
        &mut self,
        vm: &mut RgbVm,
        st: &Transition<Seal>,
    ) -> Result<(), ValidationError<Witness::Error>> {
        if st.contract_id != self.contract_id {
            return Err(ValidationError::InvalidContract(st.opid(), st.contract_id));
        }
        vm.validate_transition(
            st.transition_type,
            &self.global,
            &self.unspent,
            &st.metadata,
            &st.globals,
            &st.assignments,
        )?;
        self.process_state(st.opid(), &st.globals, &st.assignments)
    }

    fn process_state(
        &mut self,
        opid: OpId,
        global: &GlobalState,
        assignments: &Assignments<Seal>,
    ) -> Result<(), ValidationError<Witness::Error>> {
        // Add global state
        for (ty, state) in global {
            let max_count = self.global_limits.get(ty).cloned().unwrap_or(u16::MAX) as u32;
            let entries = self
                .global
                .entry(*ty)
                .expect("same dimension of indexes and maximum size")
                .or_insert(SmallDeque::with_capacity(max_count as usize));
            let new_count = state.len_u16() as u32;
            let old_count = entries.len_u16() as u32;
            // NB: We can't overflow here since we double bit dimensions
            if old_count + new_count > max_count {
                let excess = (old_count + new_count - max_count) as usize;
                entries.drain(0..excess);
            }
            entries
                .extend(state.iter().enumerate().map(|(pos, s)| GlobalRef {
                    opid,
                    pos: pos as u16,
                    state: s.verifiable,
                }))
                .expect("excessive entries were already removed")
        }

        // Add assignments to unspents
        for (ty, pos, assignment) in assignments.all() {
            let opout = Opout::new(opid, ty, pos);
            let existed = self
                .unspent
                .insert(opout, assignment.clone())
                .map_err(|_| ValidationError::TooManyUnspent)?
                .is_some();
            debug_assert!(!existed, "unspent assignment already existed");
        }
        Ok(())
    }
}
