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
#[derive(Copy, Clone, Debug, Display)]
#[cfg_attr(feature = "clap", derive(Clap))]
#[display(doc_comments)]
pub enum BinaryData {
    /// Raw/binary file with data
    Binary,

    /// Data encoded as hexadecimal (Base16) string
    Hex,

    /// Data encoded as Base64 string
    Base64,

    /// Data encoded as Bech32 string starting with `data1` prefix
    Bech32,
}

/// Formats representing data structures supporting
/// [strict encoding](`strict_encoding`)
#[derive(Copy, Clone, Debug, Display)]
#[cfg_attr(feature = "clap", derive(Clap))]
#[display(doc_comments)]
pub enum StrictData {
    /// JSON
    Json,

    /// YAML
    Yaml,

    /// TOML
    Toml,

    /// Strict encoding - binary representation
    StrictBin,

    /// Strict encoding - hex representation
    StrictHex,

    /// Strict encoding - Bech32 representation
    StrictBech32,

    /// Strict encoding - base64 representation
    StrictBase64,
}

/// formats representing data structures supporting bitcoin consensus encoding
/// (`bitcoin::consensus::encode`) or other bitcoin-specific binary encodings
/// (BIP-32 specific encodings, PSBT encoding)
#[derive(Copy, Clone, Debug, Display)]
#[cfg_attr(feature = "clap", derive(Clap))]
#[display(doc_comments)]
pub enum BitcoinData {
    /// Binary data
    Binary,

    /// Bitcoin structure data encoded as hexadecimal string
    Hex,

    /// Bitcoin structure data encoded with Base64 encoding
    Base64,

    /// Bitcoin structure data encoded with Base64 encoding. While this is
    /// non-standard encoding for most of bitcoin structures, we support
    /// extended set of prefixes (see [`bech32`] module).
    Bech32,

    /// JSON description of Bitcoin structure data
    Json,

    /// YAML description of Bitcoin structure data
    Yaml,
}

/// Representation formats for bitcoin script data
#[derive(Copy, Clone, Debug, Display)]
#[cfg_attr(feature = "clap", derive(Clap))]
#[display(doc_comments)]
pub enum BitcoinScript {
    /// Binary script source encoded as hexadecimal string
    Hex,

    /// Binary script source encoded as Base64 string
    Base64,

    /// Miniscript string or descriptor
    Miniscript,

    /// String with assembler opcodes
    Assembler,
}
