use std::ops::{Index, RangeFull};

pub trait RawRepresentable: Index<RangeFull, Output = [u8]> {
    fn as_bytes(&self) -> &[u8];
}

impl<T> RawRepresentable for T where T: Index<RangeFull, Output = [u8]> {
    fn as_bytes(&self) -> &[u8] { &self[..] }
}
