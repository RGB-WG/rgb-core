// LNP/BP Core Library implementing LNPBP specifications & standards
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

//! Common data types, structures and functions for LNPBPs

#[macro_use]
mod macros;
#[macro_use]
pub(crate) mod convert;
#[macro_use]
pub mod wrapper;
pub mod internet;
#[cfg(feature = "serde")]
pub(crate) mod serde;
#[cfg(feature = "daemons")]
pub mod service;

#[cfg(feature = "node")]
pub use service::*;
pub use wrapper::*;
