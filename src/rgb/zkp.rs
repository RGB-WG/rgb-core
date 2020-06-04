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

use super::amount::BlindingFactor;

pub fn blinding_correction(blinding_factors: Vec<BlindingFactor>) -> BlindingFactor {
    // TODO: Cache Secp value
    let secp = secp256k1zkp::Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
    let mut blinding_correction = secp
        .blind_sum(vec![secp256k1zkp::key::ZERO_KEY], blinding_factors)
        .expect("Internal inconsistency in Grin secp256k1zkp library Pedersen commitments");
    blinding_correction.neg_assign(&secp).expect(
        "You won lottery and will live forever: the probability \
                    of this event is less than a life of the universe",
    );
    blinding_correction
}
