// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2023 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::cmp::Ord;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;

use amplify::confinement::{Collection, Confined};

use super::seal;

/// Trait which must be implemented by all data structures having seals in their
/// hierarchy.
pub trait ConcealSeals {
    /// Request to conceal all seals from a given subset of seals.
    ///
    /// # Returns
    ///
    /// Number of seals instances which were concealed.
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize;
}

/// Trait which must be implemented by all data structures having state data.
pub trait ConcealState {
    /// Request to conceal all state.
    ///
    /// # Returns
    ///
    /// Count of state atoms which were concealed.
    fn conceal_state(&mut self) -> usize { self.conceal_state_except(&[]) }

    /// Request to conceal all of the state except given subset.
    ///
    /// The function doesn't requires that the state from the subset should
    /// be a revealed state; if the state atom is concealed than it is just
    /// ignored.
    ///
    /// # Returns
    ///
    /// Count of state atoms which were concealed.
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize;
}

impl<T, const MIN: usize, const MAX: usize> ConcealSeals for Confined<Vec<T>, MIN, MAX>
where T: ConcealSeals
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.conceal_seals(seals))
    }
}

impl<T, const MIN: usize, const MAX: usize> ConcealSeals for Confined<BTreeSet<T>, MIN, MAX>
where T: ConcealSeals + Ord + Clone
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        let mut new_self = BTreeSet::<T>::with_capacity(self.len());
        for item in self.iter() {
            let mut new_item = item.clone();
            count += new_item.conceal_seals(seals);
            new_self.insert(new_item);
        }
        *self = Confined::try_from(new_self).expect("same size");
        count
    }
}

impl<K, V, const MIN: usize, const MAX: usize> ConcealSeals for Confined<BTreeMap<K, V>, MIN, MAX>
where
    K: Ord + Hash,
    V: ConcealSeals,
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        self.keyed_values_mut()
            .fold(0usize, |sum, item| sum + item.1.conceal_seals(seals))
    }
}

impl<T, const MIN: usize, const MAX: usize> ConcealState for Confined<Vec<T>, MIN, MAX>
where T: ConcealState
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        self.iter_mut()
            .fold(0usize, |sum, item| sum + item.conceal_state_except(seals))
    }
}

impl<T, const MIN: usize, const MAX: usize> ConcealState for Confined<BTreeSet<T>, MIN, MAX>
where T: ConcealState + Ord + Clone
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        let mut new_self = BTreeSet::<T>::with_capacity(self.len());
        for item in self.iter() {
            let mut new_item = item.clone();
            count += new_item.conceal_state_except(seals);
            new_self.insert(new_item);
        }
        *self = Confined::try_from(new_self).expect("same size");
        count
    }
}

impl<K, V, const MIN: usize, const MAX: usize> ConcealState for Confined<BTreeMap<K, V>, MIN, MAX>
where
    K: Ord + Hash,
    V: ConcealState,
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        self.keyed_values_mut()
            .fold(0usize, |sum, item| sum + item.1.conceal_state_except(seals))
    }
}
