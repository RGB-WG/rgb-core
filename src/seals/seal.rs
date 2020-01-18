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

pub type Message = dyn AsRef<[u8]>;

pub trait Context {
    type Promise;
    type Witness;
    type Error;
}

pub trait SingleUseSeal<Ctx>: Sized where Ctx: Context {
    fn define(promice: &Ctx::Promise, ctx: &Ctx) -> Result<Self, Ctx::Error>;
    fn close(&mut self, msg: &Message, ctx: &mut Ctx) -> Result<Ctx::Witness, Ctx::Error>;
    fn is_closed(&self, ctx: &Ctx) -> bool;
    fn verify(&self, msg: &Message, witness: &Ctx::Witness, ctx: &Ctx) -> Result<bool, Ctx::Error>;
}
