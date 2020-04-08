// Lightning network protocol (LNP) daemon suite
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

#[async_trait]
pub trait Service {
    async fn run_loop(self) -> !;
}

#[async_trait]
pub trait TryService: Sized {
    type ErrorType: Error;

    async fn run_or_panic(self, service_name: &str) -> ! {
        let should_not_return = self.try_run_loop().await;

        let message = match should_not_return {
            Err(err) => format!("{} run loop has failed with error {}", service_name, err),
            Ok(_) => format!("{} has failed without reporting a error", service_name),
        };
        error!("{}", message);
        panic!("{}", message);
    }

    async fn try_run_loop(self) -> Result<!, Self::ErrorType>;
}
