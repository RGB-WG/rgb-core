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

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(Debug)]
pub enum Error {
    #[from(zmq::Error)]
    #[from(std::io::Error)]
    SocketError,
    RequiresLocalSocket,
    UnreachableError,
}

// TODO: (new) Replace with `#[from(!)]` once the issue in amplify_derive will
//       be solved: <https://github.com/LNP-BP/rust-amplify/issues/3>
impl From<!> for Error {
    fn from(_: !) -> Self {
        Error::UnreachableError
    }
}
