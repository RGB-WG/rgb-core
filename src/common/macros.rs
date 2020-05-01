// LNP/BP Core Library implementing LNPBP specifications & standards
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
macro_rules! set {
    { } =>  {
        {
            ::std::collections::HashSet::new()
        }
    };

    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::HashSet::new();
            $(
                m.insert($key, $value);
            )+
            m
        }
    }
}

#[macro_export]
macro_rules! bmap {
    { } =>  {
        {
            ::std::collections::BTreeMap::new()
        }
    };

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
macro_rules! bset {
    { } =>  {
        {
            ::std::collections::BTreeSet::new()
        }
    };

    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::BTreeSet::new();
            $(
                m.insert($key, $value);
            )+
            m
        }
    }
}

#[macro_export]
macro_rules! list {
    { } =>  {
        {
            ::std::collections::LinkedList::new()
        }
    };

    { $($value:expr)=>+ } => {
        {
            let mut m = ::std::collections::LinkedList::new();
            $(
                m.push_back($value);
            )+
            m
        }
    }
}
