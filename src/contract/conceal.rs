// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use core::cmp::Ord;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::seal;

pub trait ConcealSeals {
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize;
}

pub trait ConcealState {
    fn conceal_state(&mut self) -> usize { self.conceal_state_except(&vec![]) }
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize;
}

impl<T> ConcealSeals for Vec<T>
where T: ConcealSeals
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.conceal_seals(seals))
    }
}

impl<T> ConcealSeals for BTreeSet<T>
where T: ConcealSeals + Ord + Clone
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        let mut new_self = BTreeSet::<T>::new();
        for item in self.iter() {
            let mut new_item = item.clone();
            count += new_item.conceal_seals(seals);
            new_self.insert(new_item);
        }
        *self = new_self;
        count
    }
}

impl<K, V> ConcealSeals for BTreeMap<K, V>
where V: ConcealSeals
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.1.conceal_seals(seals))
    }
}

impl<T> ConcealSeals for HashSet<T>
where T: ConcealSeals + Ord + Clone + std::hash::Hash
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        let mut new_self = HashSet::<T>::new();
        for item in self.iter() {
            let mut new_item = item.clone();
            count += new_item.conceal_seals(seals);
            new_self.insert(new_item);
        }
        *self = new_self;
        count
    }
}

impl<K, V> ConcealSeals for HashMap<K, V>
where V: ConcealSeals
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.1.conceal_seals(seals))
    }
}

impl<T> ConcealState for Vec<T>
where T: ConcealState
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.conceal_state_except(seals))
    }
}

impl<T> ConcealState for BTreeSet<T>
where T: ConcealState + Ord + Clone
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        let mut new_self = BTreeSet::<T>::new();
        for item in self.iter() {
            let mut new_item = item.clone();
            count += new_item.conceal_state_except(seals);
            new_self.insert(new_item);
        }
        *self = new_self;
        count
    }
}

impl<K, V> ConcealState for BTreeMap<K, V>
where V: ConcealState
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.1.conceal_state_except(seals))
    }
}

impl<T> ConcealState for HashSet<T>
where T: ConcealState + Ord + Clone + std::hash::Hash
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        let mut new_self = HashSet::<T>::new();
        for item in self.iter() {
            let mut new_item = item.clone();
            count += new_item.conceal_state_except(seals);
            new_self.insert(new_item);
        }
        *self = new_self;
        count
    }
}

impl<K, V> ConcealState for HashMap<K, V>
where V: ConcealState
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.1.conceal_state_except(seals))
    }
}
