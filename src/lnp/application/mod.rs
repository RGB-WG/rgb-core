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

pub extern crate lightning_invoice as invoice;

pub mod channel;
mod features;
pub mod message;
pub mod peer_connection;
pub mod rpc_connection;

pub use channel::{
    AssetsBalance, ChannelId, ChannelKeys, ChannelNegotiationError,
    ChannelParams, ChannelState, OnionPacket, PaymentHash, PaymentPreimage,
    PaymentSecret, Slice32, TempChannelId,
};
pub use features::{FeatureContext, FeatureFlag, Features};
pub use message::{Messages, LNPWP_UNMARSHALLER};
pub use peer_connection::{
    PeerConnection, PeerReceiver, PeerSender, RecvMessage, SendMessage,
};
pub use rpc_connection::RpcConnection;

use invoice::Invoice;
use std::io;
use std::str::FromStr;

use self::invoice::ParseOrSemanticError;
use crate::strict_encoding::{self, StrictDecode, StrictEncode};

impl StrictEncode for Invoice {
    type Error = strict_encoding::Error;
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
        self.to_string().strict_encode(e)
    }
}

impl StrictDecode for Invoice {
    type Error = strict_encoding::Error;
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
        Self::from_str(&String::strict_decode(d)?).map_err(|e| {
            // TODO: (v0.3) this can be improved once PR got merged:
            //       <https://github.com/rust-bitcoin/rust-lightning-invoice/pull/43>
            strict_encoding::Error::DataIntegrityError(match e {
                ParseOrSemanticError::ParseError(err) => err.to_string(),
                ParseOrSemanticError::SemanticError(err) => {
                    s!("Lightning invoice semantic error")
                }
            })
        })
    }
}
