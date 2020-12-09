#![allow(dead_code, bare_trait_objects)]

#[macro_use]
extern crate lnpbp_derive;
extern crate lnpbp;

use ::core::marker::PhantomData;

#[derive(StrictEncode, StrictDecode)]
struct Me(u8);

#[derive(StrictEncode, StrictDecode)]
struct One {
    a: Vec<u8>,
}

#[derive(StrictEncode, StrictDecode)]
struct Heap(Box<[u8]>);

#[derive(StrictEncode, StrictDecode)]
struct You {
    //    a: (),
    b: Vec<u8>,
}

#[derive(StrictEncode, StrictDecode)]
struct Other {
    //    a: (),
    b: u8,
}

//#[derive(StrictEncode, StrictDecode)]
//#[strict_error(Error)]
enum Hi<T> {
    /// Docstring
    First(u8),
    Second(Heap),
    Third,
    Fourth {
        other: Other,
    },
    Fifth(PhantomData<T>),
    Seventh,
}

//#[derive(StrictEncode, StrictDecode)]
//#[strict_error(Error)]
enum CustomErr<E: std::error::Error> {
    Other(E),
}

fn main() {}
