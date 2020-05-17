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

use super::{Error, Message};
use core::convert::TryFrom;

impl Message {
    pub fn read_zmq(socket: zmq::Socket) -> Result<Self, Error> {
        Self::try_from(socker.recv_multipart(0)?.into_iter().flatten())
    }
}

impl TryFrom<Vec<u8>> for Message {
    type Error = Error;

    /// Converting binary data into LN message according to
    /// and LNPBP-19
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {}
}
