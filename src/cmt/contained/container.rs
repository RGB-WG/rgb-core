// LNP/BP Rust Library
// Written in 2019 by
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

use crate::Wrapper;

pub trait Container: Clone + Eq {
    type Message;

    fn commit(&mut self, msg: &Self::Message);

    fn verify(&self, msg: &Self::Message, origin: &Self) -> bool {
        let mut origin = origin.clone();
        origin.commit(msg);
        origin == *self
    }
}
