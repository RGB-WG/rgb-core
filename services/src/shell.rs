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

//! Traits and structures simplifying creation of executable files, either for
//! daemons or command-line tools

use std::env;

/// Represents desired logging verbodity level
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "lowercase")
)]
pub enum LogLevel {
    /// Report only errors to `stderr` and normat program output to stdin
    /// (if it is not directed to a file). Corresponds to zero verbosity
    /// flags.
    Error = 0,

    /// Report warning messages and errors, plus standard program output.
    /// Corresponds to a single `-v` verbosity flag.
    Warn,

    /// Report genetic information messages, warnings and errors.
    /// Corresponds to a double `-vv` verbosity flag.
    Info,

    /// Report debugging information and all non-trace messages, including
    /// general information, warnings and errors.
    /// Corresponds to triple `-vvv` verbosity flag.
    Debug,

    /// Print all possible messages including tracing information.
    /// Corresponds to quadruple `-vvvv` verbosity flag.
    Trace,
}

impl LogLevel {
    /// Indicates number of required verbosity flags
    pub fn verbosity_flag_count(&self) -> u8 {
        match self {
            LogLevel::Error => 0,
            LogLevel::Warn => 1,
            LogLevel::Info => 2,
            LogLevel::Debug => 3,
            LogLevel::Trace => 4,
        }
    }

    /// Constructs enum value from a given number of verbosity flags
    pub fn from_verbosity_flag_count(level: u8) -> Self {
        match level {
            0 => LogLevel::Error,
            1 => LogLevel::Warn,
            2 => LogLevel::Info,
            3 => LogLevel::Debug,
            _ => LogLevel::Trace,
        }
    }

    /// Applies log level to the system
    pub fn apply(&self) {
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", self.to_string());
        }
        env_logger::init();
    }
}
