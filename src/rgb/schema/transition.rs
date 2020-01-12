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

use std::collections::HashMap;

use super::{
    types::*,
    field::*,
};

pub struct Transition {
    pub closes: Option<HashMap<usize, Occurences<u32>>>,
    pub fields: Vec<Field>,
    pub binds: HashMap<usize, Occurences<u32>>,
    pub scripts: ScriptRequirements,
}
