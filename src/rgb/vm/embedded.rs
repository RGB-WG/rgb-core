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

use core::any::Any;

use super::VirtualMachine;
use crate::client_side_validation::Conceal;
use crate::rgb::{amount, schema, script::StandardProcedure, AssignmentsVariant, Metadata};

// Data are taken according to RGB-20 (LNPBP-20) standard
#[allow(unused)]
const META_TOTAL_SUPPLY: usize = 3;
#[allow(unused)]
const META_ISSUED_SUPPLY: usize = 4;
#[allow(unused)]
const SEAL_ISSUE: usize = 0;
#[allow(unused)]
const SEAL_ASSETS: usize = 1;
#[allow(unused)]
const SEAL_PRUNE: usize = 2;
#[allow(unused)]
const TRANSITION_ISSUE: usize = 0;
#[allow(unused)]
const TRANSITION_TRANSFER: usize = 1;
#[allow(unused)]
const TRANSITION_PRUNE: usize = 2;

macro_rules! push_stack {
    ($self:ident, $ident:literal) => {
        $self.push_stack(Box::new($ident));
    };
}

#[derive(Debug)]
pub struct Embedded {
    transition_type: Option<schema::TransitionType>,
    previous_state: Option<AssignmentsVariant>,
    current_state: Option<AssignmentsVariant>,
    current_meta: Metadata,

    stack: Vec<Box<dyn Any>>,
}

impl Embedded {
    pub fn with(
        transition_type: Option<schema::TransitionType>,
        previous_state: Option<AssignmentsVariant>,
        current_state: Option<AssignmentsVariant>,
        current_meta: Metadata,
    ) -> Self {
        Self {
            transition_type,
            previous_state,
            current_state,
            current_meta,

            stack: vec![],
        }
    }

    pub fn execute(&mut self, proc: StandardProcedure) {
        match proc {
            StandardProcedure::ConfidentialAmount => {
                match self.previous_state {
                    None => {
                        if self.transition_type == None
                            || self.transition_type == Some(TRANSITION_ISSUE)
                        {
                            // We are at genesis or issue transition, must check
                            // issue metadata

                            // Collect outputs
                            let outputs = if let Some(ref state) = self.current_state {
                                state.all_state_pedersen()
                            } else {
                                push_stack!(self, 6u8);
                                return;
                            };

                            // Check their bulletproofs
                            for c in &outputs {
                                if c.verify_bullet_proof().is_err() {
                                    push_stack!(self, 2u8);
                                    return;
                                }
                            }

                            // Get issued supply data
                            let supply = match self.current_meta.u64(META_ISSUED_SUPPLY).next() {
                                Some(supply) => supply,
                                _ => {
                                    push_stack!(self, 7u8);
                                    return;
                                }
                            };

                            // Check zero knowledge correspondence
                            if amount::Confidential::verify_commit_sum(
                                outputs.into_iter().map(|c| c.commitment).collect(),
                                vec![
                                    amount::Revealed {
                                        amount: supply,
                                        blinding: secp256k1zkp::key::ZERO_KEY,
                                    }
                                    .conceal()
                                    .commitment,
                                ],
                            ) {
                                push_stack!(self, 0u8);
                            } else {
                                push_stack!(self, 3u8);
                            }
                        } else {
                            // Other types of transitions are required to have
                            // a previous state
                            push_stack!(self, 5u8);
                        }
                    }
                    Some(ref variant) => {
                        if let AssignmentsVariant::DiscreteFiniteField(_) = variant {
                            let prev = variant.all_state_pedersen();
                            let curr = self.current_state.as_ref().unwrap().all_state_pedersen();

                            for p in &prev {
                                if p.verify_bullet_proof().is_err() {
                                    push_stack!(self, 1u8);
                                    return;
                                }
                            }
                            for c in &curr {
                                if c.verify_bullet_proof().is_err() {
                                    push_stack!(self, 2u8);
                                    return;
                                }
                            }

                            if amount::Confidential::verify_commit_sum(
                                curr.into_iter().map(|c| c.commitment).collect(),
                                prev.into_iter().map(|c| c.commitment).collect(),
                            ) {
                                push_stack!(self, 0u8);
                                return;
                            } else {
                                push_stack!(self, 3u8);
                                return;
                            }
                        }
                        push_stack!(self, 4u8);
                    }
                }
            }
            StandardProcedure::IssueControl => {
                push_stack!(self, 0u8);
                // TODO: Implement secondary issue validation (trivial)
            }
            StandardProcedure::Prunning => {
                push_stack!(self, 0u8);
                // TODO: Implement prunning validation (currently none)
            }
        }
    }
}

impl VirtualMachine for Embedded {
    fn stack(&mut self) -> &mut Vec<Box<dyn Any>> {
        &mut self.stack
    }
}
