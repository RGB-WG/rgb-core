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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate amplify_derive;
extern crate serde_crate as serde;

use clap::{AppSettings, Clap};
use serde::Serialize;
use std::fmt::{Debug, Display};
use std::io::{self, Read};
use std::str::FromStr;

use bitcoin::hashes::hex::{self, FromHex, ToHex};
use lnpbp::client_side_validation::ConsensusCommit;
use rgb::Consignment;
use strict_encoding::{StrictDecode, StrictEncode};

#[derive(Clap, Clone, Debug)]
#[clap(
    name = "rgb",
    bin_name = "rgb",
    author,
    version,
    about = "Command-line tool for working with RGB smart contracts",
    setting = AppSettings::ColoredHelp,
)]
pub struct Opts {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clap, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[clap(setting = AppSettings::ColoredHelp)]
pub enum Command {
    /// Commands for working with consignments
    Consignment {
        #[clap(subcommand)]
        subcommand: ConsignmentCommand,
    },
}

#[derive(Clap, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[clap(setting = AppSettings::ColoredHelp)]
pub enum ConsignmentCommand {
    Convert {
        /// Consignment data
        consignment: Option<String>,

        /// Formatting of the input data
        #[clap(short, long, default_value = "bech32")]
        input: Format,

        /// Formatting for the output
        #[clap(short, long, default_value = "yaml")]
        output: Format,
    },
}

#[derive(
    Clap, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display,
)]
pub enum Format {
    /// Format according to the rust debug rules
    #[display("debug")]
    Debug,

    /// Format according to default display formatting
    #[display("bech32")]
    Bech32,

    /// Format as YAML
    #[display("yaml")]
    Yaml,

    /// Format as JSON
    #[display("json")]
    Json,

    /// Format according to the strict encoding rules
    #[display("hex")]
    Hexadecimal,

    /// Format as a rust array (using hexadecimal byte values)
    #[display("rust")]
    Rust,

    /// Produce binary (raw) output
    #[display("raw")]
    Binary,

    /// Produce client-validated commitment
    #[display("commitment")]
    Commitment,
}

impl FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_lowercase().as_str() {
            "debug" => Format::Debug,
            "bech32" => Format::Bech32,
            "yaml" => Format::Yaml,
            "json" => Format::Json,
            "hex" => Format::Hexadecimal,
            "raw" | "bin" | "binary" => Format::Binary,
            "rust" => Format::Rust,
            "commitment" => Format::Commitment,
            other => Err(format!("Unknown format: {}", other))?,
        })
    }
}

fn output_format<T>(data: T, format: Format) -> Result<(), String>
where
    T: Debug + Display + Serialize + StrictEncode + ConsensusCommit,
    <T as ConsensusCommit>::Commitment: Display,
{
    match format {
        Format::Debug => println!("{:#?}", data),
        Format::Bech32 => println!("{}", data),
        Format::Yaml => println!(
            "{}",
            serde_yaml::to_string(&data)
                .as_ref()
                .map_err(serde_yaml::Error::to_string)?
        ),
        Format::Json => println!(
            "{}",
            serde_json::to_string(&data)
                .as_ref()
                .map_err(serde_json::Error::to_string)?
        ),
        Format::Hexadecimal => {
            println!("{}", data.strict_serialize()?.to_hex())
        }
        Format::Rust => println!("{:#04X?}", data.strict_serialize()?),
        Format::Binary => {
            data.strict_encode(io::stdout())?;
        }
        Format::Commitment => {
            println!("{}", data.consensus_commit())
        }
    }
    Ok(())
}

fn main() -> Result<(), String> {
    let opts = Opts::parse();

    match opts.command {
        Command::Consignment { subcommand } => match subcommand {
            ConsignmentCommand::Convert {
                consignment,
                input,
                output,
            } => {
                let data = consignment
                    .map(|d| d.as_bytes().to_vec())
                    .ok_or(s!(""))
                    .or_else(|_| -> Result<Vec<u8>, String> {
                        let mut buf = Vec::new();
                        io::stdin()
                            .read_to_end(&mut buf)
                            .as_ref()
                            .map_err(io::Error::to_string)?;
                        Ok(buf)
                    })?;
                let consignment = match input {
                    Format::Bech32 => {
                        Consignment::from_str(&String::from_utf8_lossy(&data))?
                    }
                    Format::Yaml => {
                        serde_yaml::from_str(&String::from_utf8_lossy(&data))
                            .map_err(|err| err.to_string())?
                    }
                    Format::Json => {
                        serde_json::from_str(&String::from_utf8_lossy(&data))
                            .map_err(|err| err.to_string())?
                    }
                    Format::Hexadecimal => Consignment::strict_deserialize(
                        Vec::<u8>::from_hex(&String::from_utf8_lossy(&data))
                            .as_ref()
                            .map_err(hex::Error::to_string)?,
                    )?,
                    Format::Binary => Consignment::strict_deserialize(&data)?,
                    _ => panic!("Can't read data from {} format", input),
                };
                output_format(consignment, output)?;
            }
        },
    }

    Ok(())
}
