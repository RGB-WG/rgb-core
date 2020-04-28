// LNP/BP Core Library implementing LNPBP specifications & standards
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

//! Primitives module defines core strict interfaces from informational LNPBP
//! standards specifying secure and robust practices for function calls
//! used in main LNP/BP development paradigms:
//! * Cryptographic commitments and verification
//! * Single-use seals
//! * Client-side validation
//! * Strict binary data serialization used by client-side validation
//!
//! The goal of this module is to maximally reduce the probability of errors and
//! mistakes within particular implementations of this paradigms by
//! standartizing typical workflow processes in a form of interfaces that
//! will be nearly impossible to use in the wrong form.

pub mod client_side_validation;
pub mod commit_verify;
pub mod single_use_seals;
pub mod strict_encoding;
