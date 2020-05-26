// LNP/BP Core Library implementing LNPBP specifications & standards
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

pub trait Wrapper {
    type Inner: Clone;

    /// Instantiates wrapper type with the inner data
    fn from_inner(inner: Self::Inner) -> Self;

    /// Returns reference to the inner representation for the wrapper type
    fn as_inner(&self) -> &Self::Inner;

    /// Clones inner data of the wrapped type and return them
    #[inline]
    fn to_inner(&self) -> Self::Inner {
        self.as_inner().clone()
    }

    /// Unwraps the wrapper returning the inner type
    fn into_inner(self) -> Self::Inner;
}

// TODO: Add generic support to the wrapper
// TODO: Convert to derive macro
#[macro_export]
macro_rules! wrapper {
    ($name:ident, $from:ty, $docs:meta, derive=[$( $derive:ident ),+]) => {
        #[$docs]
        #[derive(Clone, Debug)]
        $( #[derive($derive)] )+
        pub struct $name($from);

        impl crate::common::Wrapper for $name {
            type Inner = $from;

            #[inline]
            fn from_inner(inner: $from) -> Self {
                Self(inner)
            }

            #[inline]
            fn as_inner(&self) -> &$from {
                &self.0
            }

            #[inline]
            fn into_inner(self) -> $from {
                self.0
            }
        }

        impl ::core::convert::AsRef<$from> for $name {
            #[inline]
            fn as_ref(&self) -> &$from {
                &self.0
            }
        }

        impl ::core::convert::AsMut<$from> for $name {
            #[inline]
            fn as_mut(&mut self) -> &mut $from {
                &mut self.0
            }
        }

        impl ::core::borrow::Borrow<$from> for $name {
            #[inline]
            fn borrow(&self) -> &$from {
                &self.0
            }
        }

        impl ::core::borrow::BorrowMut<$from> for $name {
            #[inline]
            fn borrow_mut(&mut self) -> &mut $from {
                &mut self.0
            }
        }

        impl ::core::ops::Deref for $name {
            type Target = $from;
            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl ::core::ops::DerefMut for $name {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl ::std::convert::From<$from> for $name
        where
            Self: ::core::clone::Clone,
        {
            #[inline]
            fn from(x: $from) -> Self {
                Self(x)
            }
        }

        impl ::std::convert::From<&$from> for $name
        where
            Self: ::core::clone::Clone,
        {
            #[inline]
            fn from(x: &$from) -> Self {
                Self(x.clone())
            }
        }
    };
}
