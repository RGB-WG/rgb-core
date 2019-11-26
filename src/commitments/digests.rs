use std::ops::{Index, RangeFull};

use bitcoin::hashes::Hash;

use crate::commitments::committable::*;

struct DigestCommitment<HF: Hash>(HF);

impl<HF: Hash, T> Committable<HF> for T where T: Index<RangeFull, Output = [u8]> {
    fn commit(&self) -> HF { <HF as Hash>::hash(&self[..]) }
}

/* looks redundant
impl<HF: Hash> Committable<DigestCommitment<HF>> for DigestCommitment<HF> {
    fn commit(&self) -> Self { HF::hash(self) }
}
*/
