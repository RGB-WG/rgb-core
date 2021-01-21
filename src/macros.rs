// RGB standard library
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
macro_rules! type_map {
    { } =>  {
        {
            ::std::collections::BTreeMap::new()
        }
    };

    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::BTreeMap::new();
            $(
                m.insert(*$key, $value);
            )+
            m
        }
    }
}

#[macro_export]
macro_rules! field {
    ($type:ident, $value:expr) => {
        bset![::lnpbp::rgb::data::Revealed::$type($value)]
    };
}
