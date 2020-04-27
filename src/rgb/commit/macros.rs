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


macro_rules! commitment_serialize_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.commitment_serialize(&mut $encoder)?;
            )+
            len
        }
    }
}

macro_rules! impl_commitment_enum {
    ($type:ident) => {
        impl Commitment for $type {
            #[inline]
            fn commitment_serialize<E: ::std::io::Write>(&self, e: E) -> Result<usize, $crate::csv::serialize::Error> {
                match self.to_u8() {
                    Some(result) => result.commitment_serialize(e),
                    None => Err($crate::csv::serialize::Error::EnumValueOverflow),
                }
            }

            #[inline]
            fn commitment_deserialize<D: ::std::io::Read>(d: D) -> Result<Self,$crate::csv::serialize::Error> {
                let value = u8::commitment_deserialize(d)?;
                match Self::from_u8(value) {
                    Some(result) => Ok(result),
                    None => Err($crate::csv::serialize::Error::EnumValueUnknown(value)),
                }
            }
        }
    };
}
