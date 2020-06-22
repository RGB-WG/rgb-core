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

use core::cmp::Ord;
use std::collections::BTreeSet;

use super::seal;

pub trait AutoConceal {
    fn conceal_all(&mut self) -> usize {
        self.conceal_except(&vec![])
    }
    fn conceal_except(&mut self, seals: &Vec<seal::Confidential>) -> usize;
}

// TODO: Do an auto implementation for Vec and other collection types

impl<T> AutoConceal for BTreeSet<T>
where
    T: AutoConceal + Ord + Clone,
{
    fn conceal_except(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        let mut count = 0;
        let mut new_self = BTreeSet::<T>::new();
        for item in self.iter() {
            let mut new_item = item.clone();
            count += new_item.conceal_except(seals);
            new_self.insert(new_item);
        }
        *self = new_self;
        count
    }
}
