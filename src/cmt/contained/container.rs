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

pub trait Wrapper<T: Clone> {
    fn inner_ref(&self) -> &T;
}

#[macro_export]
macro_rules! impl_wrapper {
    ($type:ident, $inner:ident) => (
        #[derive(Clone, PartialEq, Eq)]
        pub struct $type($inner);
        impl Wrapper<$inner> for $type {
            #[inline]
            fn inner_ref(&self) -> &$inner { &self.0 }
        }
    )
}

pub trait Container<T: Clone + Eq>: Wrapper<T> + Clone + Eq {
    type Message;

    fn commit(&mut self, msg: &Self::Message);

    fn verify(&self, msg: &Self::Message, origin: &Self) -> bool {
        let mut origin = origin.clone();
        origin.commit(msg);
        origin == *self
    }
}
