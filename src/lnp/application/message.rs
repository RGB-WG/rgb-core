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

use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Display, Formatter};
use std::io;

use super::{ChannelId, Features};
use crate::bp::chain::AssetId;
use crate::lnp::presentation::{
    CreateUnmarshaller, Encode, Unmarshall, Unmarshaller,
};
use crate::strict_encoding::{self, StrictDecode, StrictEncode};

lazy_static! {
    pub static ref LNPWP_UNMARSHALLER: Unmarshaller<Messages> =
        Messages::create_unmarshaller();
}

#[derive(Clone, Debug, Display, LnpApi)]
#[lnp_api(encoding = "strict")]
#[lnpbp_crate(crate)]
#[non_exhaustive]
pub enum Messages {
    // Part I: Generic messages outside of channel operations
    // ======================================================
    /// Once authentication is complete, the first message reveals the features
    /// supported or required by this node, even if this is a reconnection.
    #[lnp_api(type = 16)]
    #[display("init({_0})")]
    Init(Init),

    /// For simplicity of diagnosis, it's often useful to tell a peer that
    /// something is incorrect.
    #[lnp_api(type = 17)]
    #[display("error({_0})")]
    Error(Error),

    /// In order to allow for the existence of long-lived TCP connections, at
    /// times it may be required that both ends keep alive the TCP connection
    /// at the application level. Such messages also allow obfuscation of
    /// traffic patterns.
    #[lnp_api(type = 18)]
    #[display("ping()")]
    Ping,

    /// The pong message is to be sent whenever a ping message is received. It
    /// serves as a reply and also serves to keep the connection alive, while
    /// explicitly notifying the other end that the receiver is still active.
    /// Within the received ping message, the sender will specify the number of
    /// bytes to be included within the data payload of the pong message.
    #[lnp_api(type = 19)]
    #[display("pong()")]
    Pong,
}

impl StrictEncode for Messages {
    type Error = strict_encoding::Error;

    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        self.encode()
            .expect("Memory encoders does not fail")
            .strict_encode(e)
    }
}

impl StrictDecode for Messages {
    type Error = strict_encoding::Error;

    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        Ok((&*LNPWP_UNMARSHALLER
            .unmarshall(&Vec::<u8>::strict_decode(d)?)
            .map_err(|err| {
                strict_encoding::Error::UnsupportedDataStructure(
                    "can't unmarshall LNPWP message",
                )
            })?)
            .clone())
    }
}

/// For simplicity of diagnosis, it's often useful to tell a peer that something
/// is incorrect.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-error-message>
#[derive(Clone, PartialEq, Debug, Error, StrictEncode, StrictDecode)]
#[lnpbp_crate(crate)]
pub struct Error {
    /// The channel is referred to by channel_id, unless channel_id is 0 (i.e.
    /// all bytes are 0), in which case it refers to all channels.
    pub channel_id: Option<ChannelId>,

    /// Any specific error details, either as string or binary data
    pub data: Vec<u8>,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Error")?;
        if let Some(channel_id) = self.channel_id {
            write!(f, " on channel {}", channel_id)?;
        } else {
            f.write_str(" on all channels")?;
        }
        // NB: if data is not composed solely of printable ASCII characters (For
        // reference: the printable character set includes byte values 32
        // through 126, inclusive) SHOULD NOT print out data verbatim.
        if let Ok(msg) = String::from_utf8(self.data.clone()) {
            write!(f, ": {}", msg)?;
        }
        Ok(())
    }
}

/// Once authentication is complete, the first message reveals the features
/// supported or required by this node, even if this is a reconnection.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-init-message>
#[derive(
    Clone, PartialEq, Debug, Display, Error, StrictEncode, StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct Init {
    pub global_features: Features,
    pub local_features: Features,
    pub assets: HashSet<AssetId>,
    pub unknown_tlvs: BTreeMap<u64, Vec<u8>>,
}
