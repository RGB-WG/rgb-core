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

#[macro_export]
macro_rules! bytes {
    [ $($value:expr),+ ] => {
        &vec![
        $(
            $value,
        )+
        ][..] as &[u8]
    }
}

#[macro_export]
macro_rules! map {
    { } =>  {
        {
            ::std::collections::HashMap::new()
        }
    };

    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::HashMap::new();
            $(
                m.insert($key, $value);
            )+
            m
        }
    }
}

#[macro_export]
macro_rules! bmap {
    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::BTreeMap::new();
            $(
                m.insert($key, $value);
            )+
            m
        }
    }
}

#[macro_export]
macro_rules! hlist {
    [ $($value:expr),+ ] => {
        {
            let mut m = ::std::vec::Vec::<::std::boxed::Box<dyn ::std::any::Any>>::new();
            $(
                m.push(::std::boxed::Box::new($value));
            )+
            m
        }
    }
}
