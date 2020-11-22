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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::seal;

pub trait AutoConceal {
    fn conceal_all(&mut self) -> usize {
        self.conceal_except(&vec![])
    }
    fn conceal_except(&mut self, seals: &Vec<seal::Confidential>) -> usize;
}

impl<T> AutoConceal for Vec<T>
where
    T: AutoConceal,
{
    fn conceal_except(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.conceal_except(seals))
    }
}

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

impl<K, V> AutoConceal for BTreeMap<K, V>
where
    V: AutoConceal,
{
    fn conceal_except(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.1.conceal_except(seals))
    }
}

impl<T> AutoConceal for HashSet<T>
where
    T: AutoConceal + Ord + Clone + std::hash::Hash,
{
    fn conceal_except(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        let mut count = 0;
        let mut new_self = HashSet::<T>::new();
        for item in self.iter() {
            let mut new_item = item.clone();
            count += new_item.conceal_except(seals);
            new_self.insert(new_item);
        }
        *self = new_self;
        count
    }
}

impl<K, V> AutoConceal for HashMap<K, V>
where
    V: AutoConceal,
{
    fn conceal_except(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.1.conceal_except(seals))
    }
}
