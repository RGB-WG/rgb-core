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

pub mod amount {
    use rand;
    // We do not import particular modules to keep aware with namespace prefixes that we do not use
    // the standard secp256k1zkp library
    use secp256k1zkp::*;

    // TODO: Convert Amount into a wrapper type later
    //wrapper!(Amount, _AmountPhantom, u64, doc="64-bit data for amounts");
    pub type Amount = u64;

    #[derive(Clone, PartialEq, Debug, Display)]
    #[display_from(Debug)]
    pub struct Commitment {
        pub commitment: pedersen::Commitment,
        pub bulletproof: pedersen::RangeProof,
    }

    #[derive(Clone, PartialEq, Debug, Display)]
    #[display_from(Debug)]
    pub struct Proof(secp256k1zkp::key::SecretKey);

    #[derive(Clone, PartialEq, Debug, Display)]
    #[display_from(Debug)]
    pub struct Confidential {
        pub commitment: Commitment,
        pub proof: Proof,
    }

    impl From<Amount> for Confidential {
        fn from(amount: Amount) -> Self {
            let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);
            let blinding = secp256k1zkp::key::SecretKey::new(&secp, &mut rand::thread_rng());
            let value = amount;
            let commitment = secp.commit(value, blinding.clone())
                .expect("Internal inconsistency in Grin secp256k1zkp library Pedersen commitments");
            let bulletproof = secp.bullet_proof(
                value, blinding.clone(),
                blinding.clone(), blinding.clone(),
                None, None
            );
            Confidential {
                commitment: Commitment { commitment, bulletproof },
                proof: Proof(blinding)
            }
        }
    }
}

pub use amount::Amount;

#[non_exhaustive]
#[derive(Clone, PartialEq, Debug, Display)]
#[display_from(Debug)]
pub enum Data {
    Balance(amount::Commitment),
    Binary(Box<[u8]>),
    // TODO: Add other supported bound state types according to the schema
}
