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
                m.insert($key.into(), $value);
            )+
            m
        }
    }
}

#[macro_export]
macro_rules! field {
    ($type:ident, $value:expr) => {
        vec![::rgb::data::Revealed::$type($value)]
    };
}
