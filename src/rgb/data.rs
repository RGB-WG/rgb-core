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
    use std::ops::Add;
    use rand;

    // We do not import particular modules to keep aware with namespace prefixes that we do not use
    // the standard secp256k1zkp library
    use secp256k1zkp::*;
    pub use secp256k1zkp::pedersen::Commitment as PedersenCommitment;

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

    impl std::ops::Deref for Proof {
        type Target = secp256k1zkp::key::SecretKey;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

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

    pub fn commit_last_item(amount: Amount, blinding_factors: Vec<secp256k1zkp::key::SecretKey>) -> Confidential {
        // TODO: refactor duplicated code

        let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);
        let blinding = secp.blind_sum(vec![secp256k1zkp::key::ONE_KEY], blinding_factors).unwrap(); // FIXME: that's probably broken, but it works

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

    pub fn zero_pedersen_commitment() -> PedersenCommitment {
        let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);

        secp
            .commit_value(0)
            .expect("Internal inconsistency in Grin secp256k1zkp library Pedersen commitments")
    }

    impl Add<pedersen::Commitment> for Commitment {
        type Output = pedersen::Commitment;

        fn add(self, other: pedersen::Commitment) -> Self::Output {
            let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);

            secp
                .commit_sum(vec![self.commitment, other], vec![])
                .expect("Failed to add Pedersen commitments")
        }
    }

    pub fn verify_bullet_proof(commitment: &Commitment) -> Result<pedersen::ProofRange, secp256k1zkp::Error> {
        let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);

        secp.
            verify_bullet_proof(commitment.commitment.clone(), commitment.bulletproof.clone(), None)
    }

    pub fn verify_commit_sum(positive: Vec<pedersen::Commitment>, negative: Vec<pedersen::Commitment>) -> bool {
        let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);

        secp.
            verify_commit_sum(positive, negative)
    }
}

pub use amount::{Amount, PedersenCommitment};

#[non_exhaustive]
#[derive(Clone, PartialEq, Debug, Display)]
#[display_from(Debug)]
pub enum Data {
    Balance(amount::Commitment),
    Binary(Box<[u8]>),
    None,
    // TODO: Add other supported bound state types according to the schema
}
