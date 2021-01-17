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

#[derive(Debug)]
pub struct Simplicity {
    stack: Vec<Box<dyn Any>>,
}

impl VirtualMachine for Simplicity {
    fn stack(&mut self) -> &mut Vec<Box<dyn Any>> {
        &mut self.stack
    }
}
