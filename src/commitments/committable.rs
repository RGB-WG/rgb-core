use std::ops::*;
use crate::common::raw_representable::RawRepresentable;

pub trait Committable<CMT: Sized + Eq + RawRepresentable> {
    fn commit(&self) -> CMT;
    fn verify(&self, commitment: &CMT) -> bool { self.commit() == *commitment }
}

/*
impl<CMT> Index<RangeFull> for Committable<CMT> {
    type Output = [u8];
    fn index(&self, index: RangeFull) -> &[u8] { self.as_bytes() }
}
*/