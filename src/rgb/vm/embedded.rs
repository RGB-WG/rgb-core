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
use crate::rgb::{script::StandardProcedure, AssignmentsVariant, Metadata};

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
                // TODO: Implement confidential amount validation
            }
            StandardProcedure::IssueControl => {
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
