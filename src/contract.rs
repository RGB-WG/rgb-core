use std::borrow::Borrow;
use std::collections::BTreeSet;

use aluvm::Lib;
use amplify::confinement::TinyOrdSet;
use commit_verify::CommitId;
use single_use_seals::SealProtocol;

use crate::client_side_validation::Witness;
use crate::vm::ContractStateAccess;
use crate::{
    Extension, Genesis, OpId, Operation, Opout, Schema, Transition, TransitionBundle, VmSchema,
};

/// Error validating and computing the contract state.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
pub enum ValidationError {
    InvalidInput {
        transition_id: OpId,
        prev_out: Opout,
    },

    NotAllInputAnchorsValidated(BTreeSet<OpId>),
}

/// Contract repository API should be implemented by any object which hosts consistent and complete
/// RGB contract information; for instance by consignments and stash.
pub trait ContractRepository<Seal> {
    fn schema(&self) -> impl Borrow<Schema>;
    fn genesis(&self) -> impl Borrow<Genesis>;
    fn operations(&self) -> impl Iterator<Item = (&Witness<Seal>, &TransitionBundle)>;

    /// The random state transition access API.
    ///
    /// This API is needed to validate the inputs in the AluVM validation scripts. We can't assume
    /// that the outputs we spent are already part of a contract state, since a re-org can put a
    /// witness of a following transaction before a witness of an ancestor transaction. Thus, we
    /// always query state transition and extension to collect the input state information.
    /// However, such query must return the whole operation and not just a single output, so we
    /// can chat that the output is indeed part of the operation and committed into an operation
    /// id.
    fn transition(&self, opid: OpId) -> Option<impl Borrow<Transition>>;
    fn extension(&self, opid: OpId) -> Option<impl Borrow<Extension>>;
    fn libs(&self) -> TinyOrdSet<Lib>;
}

/// Checked repository ensures that the data returned by a [`ContractRepository`] instance are
/// consistent.
pub struct CheckedRepository<Seal, R: ContractRepository<Seal>>(R);

impl<Seal, R: ContractRepository<Seal>> ContractRepository<Seal> for CheckedRepository<Seal, R> {
    fn schema(&self) -> impl Borrow<Schema> { self.0.schema() }
    fn genesis(&self) -> impl Borrow<Genesis> { self.0.genesis() }
    fn operations(
        &self,
    ) -> impl Iterator<Item = (impl Borrow<Witness<Seal>>, impl Borrow<TransitionBundle>)> {
        self.0.operations()
    }
    fn transition(&self, opid: OpId) -> Option<impl Borrow<Transition>> {
        let op = self.0.transition(opid)?;
        assert_eq!(
            op.borrow().opid(),
            opid,
            "the client of RGB consensus API cheats with state transition for {opid}; the use of \
             this software is unsafe."
        );
        Some(op)
    }
    fn extension(&self, opid: OpId) -> Option<impl Borrow<Extension>> {
        let op = self.0.extension(opid)?;
        assert_eq!(
            op.borrow().opid(),
            opid,
            "the client of RGB consensus API cheats with state extension for {opid}; the use of \
             this software is unsafe."
        );
        Some(op)
    }
    fn libs(&self) -> TinyOrdSet<Lib> { self.0.libs() }
}

pub trait Contract<Seal>: ContractStateAccess<Seal> {
    type Context;

    fn new(context: Self::Context) -> Self;

    // TODO: Do not allow lib clients to re-define this method (use sealed trait).
    fn with_contract_validated(
        repo: &impl ContractRepository<Seal>,
        context: Self::Context,
    ) -> Result<Self, ValidationError> {
        let repo = CheckedRepository(repo);
        // Cache initial data
        let schema = repo.schema().borrow();
        let genesis = repo.genesis().borrow();
        let schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();
        if genesis.schema_id != schema_id {
            panic!(
                "genesis provided for the contract validation doesn't commit to the schema \
                 provided for the validation."
            );
        }

        let vm = match schema.vm {
            VmSchema::AluVm(config) => RgbVm::with(config, repo.libs()),
        };

        let mut contract = Self::new(context);
        let mut validated_ops = bset![];
        // We collect state transition ids which were used as inputs for other state transitions
        // before they appear in the consensus ordered witnesses. This might happen in cases of
        // blockchain re-orgs for the witnesses which do not spend each other outputs.
        // We track such ids to ensure that all state transitions accounted in the contract state
        // were validated against their witnesses.
        let mut out_of_order_opids = bset![];

        vm.validate(genesis, &mut contract)?;
        contract.add(genesis)?;

        let mut prev_witness = None;
        for (witness, bundle) in repo.operations() {
            let witness = witness.borrow();
            let witness_id = witness.witness_id();
            let bundle = bundle.borrow();

            if let Some(witness_before) = prev_witness.replace(witness) {
                assert!(
                    witness_before.order() < witness.order(),
                    "the client of RGB consensus API cheats with ordering of single-use seal \
                     witnesses, putting witness {} with higher priority after the witness {} with \
                     lower priority",
                    witness_before.id(),
                    witness.id(),
                );
            }

            for transition in bundle.known_transitions.values() {
                let trans_id = transition.id();

                // Previous outputs which are not yet known to the contract. This happens when state
                // transition witnesses were re-ordered due to a blockchain re-org.
                let mut prev_outs = vec![];
                for input in transition.inputs.iter() {
                    // If the opout was spent it must return `false`
                    let prev_opid = input.prev_out.op;
                    let prev_assignment =
                        if let Some(assignment) = contract.assignment(input.prev_out) {
                            Some(assignment.borrow())
                        } else if let Some(extension) = repo.extension(prev_opid) {
                            let extension = extension.borrow();
                            vm.validate(extension, &mut contract)?;
                            validated_ops.insert(prev_opid);
                            contract.add(extension)?;
                            contract.assignment(input.prev_out)
                        } else if let Some(prev_op) = repo.transition(prev_opid) {
                            let prev_op = prev_op.borrow();
                            if let Some(assignment) = prev_op
                                .assignments_by_type(input.prev_out.ty)
                                .and_then(|a| a.get(input.prev_out.no))
                            {
                                // We put the state into the out-of-order previous outputs.
                                prev_outs.push(assignment);
                                // We need to track that this transition to ensure that it will be
                                // validated later against its witness.
                                out_of_order_opids.insert(prev_opid);
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                        .ok_or(ValidationError::InvalidInput {
                            transition_id: trans_id,
                            prev_out: input.prev_out,
                        })?;

                    // Check that the input was defined as a seal which was closed by the witness.
                    if !witness.does_close_seal(&prev_assignment.seal) {
                        return Err(ValidationError::UnrelatedInput {
                            transition_id: trans_id,
                            prev_out: input.prev_out,
                            witness_id,
                        });
                    }
                }

                vm.validate(transition, prev_outs, &mut contract)?;
                validated_ops.insert(trans_id);
                contract.add(transition)?;

                // We have validated the state transition, so we can remove it from the out-of-order
                // list, if it were there.
                out_of_order_opids.remove(trans_id);
            }

            // Must verify:
            // - witness contains a valid commitment to the bundle id.
            // - witness closes single-use seals matching the bundle transition inputs
            witness.verify(contract_id, bundle.bundle_id())?;
        }

        if !out_of_order_opids.is_empty() {
            return Err(ValidationError::NotAllInputAnchorsValidated(out_of_order_opids));
        }

        Ok(contract)
    }

    fn add(&mut self, op: &impl Operation) -> Result<(), ValidationError> { todo!() }
}
