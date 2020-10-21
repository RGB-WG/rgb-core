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

pub const RGB_VM_STACK_SIZE_LIMIT: u16 = core::u16::MAX;

pub trait VirtualMachine {
    fn stack(&mut self) -> &mut Vec<Box<dyn Any>>;

    fn push_stack(&mut self, data: Box<dyn Any>) -> bool {
        if self.stack().len() >= RGB_VM_STACK_SIZE_LIMIT as usize {
            false
        } else {
            self.stack().push(data);
            true
        }
    }

    fn pop_stack(&mut self) -> Option<Box<dyn Any>> {
        self.stack().pop()
    }
}
