// Rust language amplification library providing multiple generic trait
// implementations, type wrappers, derive macros and other language enhancements
//
// Written in 2019-2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
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

use ::core::fmt::{Display, Formatter};
use ::core::str::pattern::Pattern;
use ::core::str::FromStr;

use num_traits::{FromPrimitive, ToPrimitive};

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, ToPrimitive, FromPrimitive)]
pub enum DataFormat {
    Yaml,
    Json,
    Toml,
    StrictEncode,
}

impl_enum_strict_encoding!(DataFormat);

impl DataFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            DataFormat::Yaml => "yaml",
            DataFormat::Json => "json",
            DataFormat::Toml => "toml",
            DataFormat::StrictEncode => "se",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display_from(Debug)]
pub enum FileFormatParseError {
    UnknownFormat,
}

impl FromStr for DataFormat {
    type Err = FileFormatParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match &s.to_lowercase() {
            s if "yaml".is_suffix_of(s) || "yml".is_suffix_of(s) => Self::Yaml,
            s if "json".is_suffix_of(s) => Self::Json,
            s if "toml".is_suffix_of(s) => Self::Toml,
            s if "se".is_suffix_of(s)
                || "dat".is_suffix_of(s)
                || "strictencode".is_suffix_of(s)
                || "strict-encode".is_suffix_of(s)
                || "strict_encode".is_suffix_of(s) =>
            {
                Self::StrictEncode
            }
            _ => Err(FileFormatParseError::UnknownFormat)?,
        })
    }
}

impl Display for DataFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::std::fmt::Result {
        let s = match self {
            DataFormat::Yaml => "yaml",
            DataFormat::Json => "json",
            DataFormat::Toml => "toml",
            DataFormat::StrictEncode => "strict-encode",
        };
        write!(f, "{}", s)
    }
}
