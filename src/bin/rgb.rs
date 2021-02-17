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
extern crate amplify_derive;
extern crate serde_crate as serde;

use clap::{AppSettings, Clap};
use serde::Serialize;
use std::fmt::{Debug, Display};
use std::str::FromStr;

use rgb::Consignment;

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
    Parse {
        /// Consignment data
        consignment: String,

        /// Formatting for the parsed information
        #[clap(short, long, default_value = "yaml")]
        format: ParseFormat,
    },
}

#[derive(
    Clap, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display,
)]
pub enum ParseFormat {
    /// Format according to the rust debug rules
    #[display("debug")]
    Debug,

    /// Format according to default display formatting
    #[display("display")]
    Display,

    /// Format as YAML
    #[display("yaml")]
    Yaml,

    /// Format as JSON
    #[display("json")]
    Json,
}

impl FromStr for ParseFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_lowercase().as_str() {
            "debug" => ParseFormat::Debug,
            "display" => ParseFormat::Display,
            "yaml" => ParseFormat::Yaml,
            "json" => ParseFormat::Json,
            other => Err(format!("Unknown format: {}", other))?,
        })
    }
}

fn output_format<T>(data: T, format: ParseFormat) -> Result<(), String>
where
    T: Debug + Display + Serialize,
{
    match format {
        ParseFormat::Debug => println!("{:#?}", data),
        ParseFormat::Display => println!("{}", data),
        ParseFormat::Yaml => println!(
            "{}",
            serde_yaml::to_string(&data)
                .as_ref()
                .map_err(serde_yaml::Error::to_string)?
        ),
        ParseFormat::Json => println!(
            "{}",
            serde_json::to_string(&data)
                .as_ref()
                .map_err(serde_json::Error::to_string)?
        ),
    }
    Ok(())
}

fn main() -> Result<(), String> {
    let opts = Opts::parse();

    match opts.command {
        Command::Consignment { subcommand } => match subcommand {
            ConsignmentCommand::Parse {
                consignment,
                format,
            } => {
                let consignment = Consignment::from_str(&consignment)?;
                output_format(consignment, format)?;
            }
        },
    }

    Ok(())
}
