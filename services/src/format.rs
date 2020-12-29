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

/// Formats representing generic binary data input or output
#[derive(Copy, Clone, Debug, Display, Serialize, Deserialize)]
#[serde(crate = "serde_crate")]
#[cfg_attr(feature = "clap", derive(Clap))]
#[non_exhaustive]
pub enum BinaryData {
    /// Raw/binary file with data
    #[display("bin")]
    Binary,

    /// Data encoded as hexadecimal (Base16) string
    #[display("hex")]
    Hex,

    /// Data encoded as Base64 string
    #[display("base64")]
    Base64,

    /// Data encoded as Bech32 string starting with `data1` prefix
    #[display("bech32")]
    Bech32,
}

/// Formats representing data structures supporting binary encoding and which
/// can be represented by hierarchical data structures, including types
/// supporting LNP/BP strict encoding, bitcoin consensus encoding
/// (`bitcoin::consensus::encode`) or other bitcoin-specific binary encodings
/// (BIP-32 specific encodings, PSBT encoding)
#[derive(Copy, Clone, Debug, Display, Serialize, Deserialize)]
#[serde(crate = "serde_crate")]
#[cfg_attr(feature = "clap", derive(Clap))]
#[non_exhaustive]
pub enum StructuredData {
    /// JSON
    #[display("json")]
    Json,

    /// YAML
    #[display("yaml")]
    Yaml,

    /// TOML
    #[display("toml")]
    Toml,

    /// Binary representation
    #[display("bin")]
    Bin,

    /// Hexadecimal representation
    #[display("hex")]
    Hex,

    /// Bech32 representation
    #[display("bech32")]
    Bech32,

    /// Base64 representation
    #[display("base64")]
    Base64,
}

/// Representation formats for bitcoin script data
#[derive(Copy, Clone, Debug, Display, Serialize, Deserialize)]
#[serde(crate = "serde_crate")]
#[cfg_attr(feature = "clap", derive(Clap))]
#[non_exhaustive]
pub enum BitcoinScript {
    /// Binary script source encoded as hexadecimal string
    #[display("hex")]
    Hex,

    /// Binary script source encoded as Base64 string
    #[display("base64")]
    Base64,

    /// Miniscript string or descriptor
    #[display("miniscript")]
    Miniscript,

    /// String with assembler opcodes
    #[display("asm")]
    Assembler,
}

#[derive(
    Copy, Clone, PartialEq, Eq, Hash, Debug, Display, Serialize, Deserialize,
)]
#[serde(crate = "serde_crate")]
#[non_exhaustive]
pub enum FileStorage {
    #[display("strict-encoded")]
    StrictEncoded,

    #[display("yaml")]
    Yaml,

    #[display("toml")]
    Toml,

    #[display("json")]
    Json,
}
