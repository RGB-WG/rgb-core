// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//  The convert.rs file written in 2020 by
//     Martin Habovstiak <martin.habovstiak@gmail.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! This module contains various tools for converting values

/// impls TryFrom<T> where T: Deref<Target=str> in terms of FromStr.
///
/// This needs to be a macro instead of blanket imple in order to resolve the
/// conflict with T: Into<Self>
#[macro_export]
macro_rules! impl_try_from_stringly {
    ($to:ty $(, $from:ty)+ $(,)?) => {
        $(
            impl std::convert::TryFrom<$from> for $to {
                type Error = <$to as FromStr>::Err;
                #[inline]
                fn try_from(value: $from) -> Result<Self, Self::Error> {
                    <$to>::from_str(&value)
                }
            }
        )*
    }
}

/// Calls impl_try_from_stringly!() with a set of standard stringly types.
#[macro_export]
macro_rules! impl_try_from_stringly_standard {
    ($type:ty) => {
        use std::borrow::Cow;
        use std::rc::Rc;
        use std::sync::Arc;

        impl_try_from_stringly! { $type,
            &str,
            String,
            Box<str>,
            Cow<'_, str>,
            Box<Cow<'_, str>>,
            Rc<str>,
            Rc<String>,
            Rc<Cow<'_, str>>,
            Arc<str>,
            Arc<String>,
            Arc<Cow<'_, str>>,

        }

        #[cfg(feature = "serde")]
        impl_try_from_stringly!($type, crate::common::serde::CowHelper<'_>);
    };
}

/// Impls From<T> for Stringly where String: Into<Stringly>, T: Display
#[macro_export]
macro_rules! impl_into_stringly {
    ($from:ty $(, $into:ty)+ $(,)?) => {
        $(
            impl From<$from> for $into {
                fn from(value: $from) -> Self {
                    value.to_string().into()
                }
            }
        )+
    }
}

macro_rules! impl_into_stringly_standard {
    ($type:ty) => {
        impl_into_stringly! { $type,
            String,
            Box<str>,
            Cow<'_, str>,
            Rc<str>,
            Rc<String>,
            Arc<str>,
            Arc<String>,
        }
    };
}
