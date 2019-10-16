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

///! Implementation of different cryptographic commitment primitives, focused around LNPBPS-0001
///! (collision-resistant elliptic curve-based commitments). Also covers more standard hash
///! commitments. In the future, with the addition of new LNPBPS for cryptographic commitments the
///! support must be extended to cover sign-to-contract scheme, Schnorr's signatures etc
///!
///! To use, first implement `Committable` trait for the data structure to which you'd like commit to.
///! Define which of the provided commitment schemes you plan to use and consruct corresponding
///! `CommitmentSource` type containing all data necessary for constructing the actual commitment,
///! for instance implementing trait `From` for CommitmentSource-derived type on some source data
///! type. Then use corresponding `CommitmentEngine` to produce `RevealData`-typed structure.
///! From the reveal data you can both generate the actual commitment with `commit` function or
///! verify existing commitment with `verify` function.

/// In order to commit to some data the data structure must implement this trait
pub trait Committable<CS: CommitmentSource> {}

/// Data structure containing all necessary information for producing deterministic commitment
pub trait CommitmentSource {}

/// Any structure which may contain cryptographic commitment must implement this trait
pub trait CommitTarget {}

/// Trait for preparing structured data for commitment and verification from some source data
pub trait CommitmentEngine<CT: CommitTarget, CS: CommitmentSource, RD: RevealData<CT>> {
    fn reveal(&self, src: &CS) -> RD;
}

/// Trait that must be implemented by a structured data that have to be committed to
pub trait RevealData<CT: CommitTarget>: Sized {
    fn commit(&self) -> CT;
    fn verify(&self, commit: CT) -> bool;
}
