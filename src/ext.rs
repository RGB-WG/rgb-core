//! Parts which need to be moved to other crates

use amplify::{Array, Wrapper};

pub trait RawArray<const LEN: usize> {
    fn from_raw_array(val: [u8; LEN]) -> Self;
    fn to_raw_array(&self) -> [u8; LEN];
}

impl<Id, const LEN: usize> RawArray<LEN> for Id
where Id: Wrapper<Inner = Array<u8, LEN>>
{
    fn from_raw_array(val: [u8; LEN]) -> Self { Self::from_inner(Array::from_inner(val)) }

    fn to_raw_array(&self) -> [u8; LEN] { self.as_inner().into_inner() }
}
