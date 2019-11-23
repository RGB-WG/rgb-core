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

//! Implementation of different cryptographic commitment primitives, focused around LNPBPS-0001
//! (collision-resistant elliptic curve-based commitments). Also covers more standard hash
//! commitments. In the future, with the addition of new LNPBPS for cryptographic commitments the
//! support must be extended to cover sign-to-contract scheme, Schnorr's signatures etc
//!
//! Define which of the provided commitment schemes you plan to use and construct corresponding
//! `CommitmentSource` type containing all data necessary for constructing the actual commitment,
//! for instance implementing trait `From` for CommitmentSource-derived type on some source data
//! type. Then use corresponding `CommitmentEngine` to produce `CommitTarget`-typed structure.
//! From the reveal data you can both generate the actual commitment with `commit` function or
//! verify existing commitment with `verify` function.

/// Data structure containing all necessary information for producing deterministic commitment
pub trait CommitmentSource {}

/// Any structure which may contain cryptographic commitment must implement this trait
pub trait CommitTarget {}

/// Trait for preparing structured data for commitment and verification from some source data
pub trait CommitmentEngine<CT: CommitTarget, CSRC: CommitmentSource, CS: CommitmentScheme<CT>> {
    /// Creates data in form of `CommitTarget` that is used for both commit and verify procedures.
    /// Takes `CommitmentSource`-enabled data source.
    fn construct(&self, src: &CSRC) -> CS;
}

/// Trait that must be implemented by a structured data that have to be committed to
pub trait CommitmentScheme<CT: CommitTarget>: Sized {
    /// Commits to it's content returning the actual commitment supporting `CommitTarget` trait
    fn commit(&self) -> CT;

    /// Verifies the provided commitment against it's own data
    fn verify(&self, commit: CT) -> bool;
}
