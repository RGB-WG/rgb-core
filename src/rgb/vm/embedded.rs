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

use amplify::AsAny;
use core::any::Any;

use super::VirtualMachine;
use crate::rgb::{amount, script::StandardProcedure, AssignmentsVariant, Metadata};

// Data are taken according to RGB-20 (LNPBP-20) standard
#[allow(unused)]
const META_TOTAL_SUPPLY: u16 = 3;
#[allow(unused)]
const META_ISSUED_SUPPLY: u16 = 4;
#[allow(unused)]
const SEAL_ISSUE: u16 = 0;
#[allow(unused)]
const SEAL_ASSETS: u16 = 1;
#[allow(unused)]
const SEAL_PRUNE: u16 = 2;
#[allow(unused)]
const TRANSITION_ISSUE: u16 = 0;
#[allow(unused)]
const TRANSITION_TRANSFER: u16 = 1;
#[allow(unused)]
const TRANSITION_PRUNE: u16 = 2;

macro_rules! push_stack {
    ($self:ident, $ident:literal) => {
        $self.push_stack(Box::new($ident.as_any()));
    };
}

#[derive(Debug)]
pub struct Embedded {
    previous_state: Option<AssignmentsVariant>,
    current_state: Option<AssignmentsVariant>,
    current_meta: Metadata,

    stack: Vec<Box<dyn Any>>,
}

impl Embedded {
    pub fn with(
        previous_state: Option<AssignmentsVariant>,
        current_state: Option<AssignmentsVariant>,
        current_meta: Metadata,
    ) -> Self {
        Self {
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
                        // TODO: We are at genesis, must check issue metadata
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
                            } else {
                                push_stack!(self, 3u8);
                            }
                        }
                        push_stack!(self, 4u8);
                    }
                }
            }
            StandardProcedure::IssueControl => {
                push_stack!(self, 0u8);
                // TODO: Implement issue validation
            }
            StandardProcedure::Prunning => unimplemented!(),
        }
    }
}

impl VirtualMachine for Embedded {
    fn stack(&mut self) -> &mut Vec<Box<dyn Any>> {
        &mut self.stack
    }
}
