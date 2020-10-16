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

use std::error::Error;

/// Trait for simpler service implementation with run loops
pub trait Service {
    /// Run loop for the service, which must never return. If you have a run
    /// loop that may fail, use [`TryService`] trait instead
    fn run_loop(self) -> !;
}

/// Trait for simpler service implementation with run loops which may fail with
/// `TryService::ErrorType` errors; otherwise they should never return
pub trait TryService: Sized {
    /// Type of the error which is produced in case of service failure and
    /// is returned from the internal [`try_run_loop()`] procedure
    type ErrorType: Error;

    /// NB: Do not reimplement this one: the function keeps in check that if the
    /// failure happens during run loop, the program will panic reporting the
    /// failure. To implement the actual run loop please provide implementation
    /// for [`try_run_loop()`]
    fn run_or_panic(self, service_name: &str) -> ! {
        panic!(match self.try_run_loop() {
            Err(err) => {
                format!(
                    "{} run loop has failed with error {}",
                    service_name, err
                )
            }
            Ok(_) => {
                format!("{} has failed without reporting a error", service_name)
            }
        })
    }

    /// Main failable run loop implementation. Must produce an error of type
    /// [`TryService::ErrorType`] or never return.
    fn try_run_loop(self) -> Result<!, Self::ErrorType>;
}

/// Marker trait that can be implemented for data structures used by `Clap` or
/// by any other form of API handling.
pub trait Exec {
    /// Runtime context data type, that is provided for execution context.
    type Runtime: Sized;
    /// Error type that may result from the execution
    type Error: Error;
    /// Main execution routine
    fn exec(&self, runtime: &mut Self::Runtime) -> Result<(), Self::Error>;
}
