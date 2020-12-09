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

use std::collections::HashSet;
use std::io;

use crate::lightning_encoding::{self, LightningDecode, LightningEncode};
use crate::standards::features::FlagVec;
use crate::strict_encoding::{self, StrictDecode, StrictEncode};

/// Some features don't make sense on a per-channels or per-node basis, so each
/// feature defines how it is presented in those contexts. Some features may be
/// required for opening a channel, but not a requirement for use of the
/// channel, so the presentation of those features depends on the feature
/// itself.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md#bolt-9-assigned-feature-flags>
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
pub enum FeatureContext {
    /// `I`: presented in the init message.
    // TODO: Add `alt = doc_comments` when `amplify` crate will support it
    #[display("I")]
    Init,

    /// `N`: N: presented in the node_announcement messages
    #[display("N")]
    NodeAnnouncement,

    /// `C`: presented in the channel_announcement message.
    #[display("C")]
    ChannelAnnouncement,

    /// `9`: presented in BOLT 11 invoices.
    #[display("9")]
    Bolt11Invoice,
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Default)]
#[display("flag<{context:?}, global={global}>, required={required}>")]
pub struct FeatureFlag {
    pub context: HashSet<FeatureContext>,
    pub global: bool,
    pub required: bool,
}

/// Flags are numbered from the least-significant bit, at bit 0 (i.e. 0x1, an
/// even bit). They are generally assigned in pairs so that features can be
/// introduced as optional (odd bits) and later upgraded to be compulsory (even
/// bits), which will be refused by outdated nodes: see BOLT #1: The init
/// Message.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md>
#[derive(Clone, PartialEq, Eq, Debug, Display, Default)]
#[display(Debug)]
pub struct Features {
    /// Requires or supports extra `channel_reestablish` fields
    // #[lnpwp_feature(0, 1)]
    pub option_data_loss_protect: FeatureFlag,

    /// Sending node needs a complete routing information dump
    // #[lnpwp_feature(3)]
    pub initial_routing_sync: FeatureFlag,

    /// Commits to a shutdown scriptpubkey when opening channel
    // #[lnpwp_feature(4, 5)]
    pub option_upfront_sutdown_script: FeatureFlag,

    /// More sophisticated gossip control
    // #[lnpwp_feature(6, 7)]
    pub gossip_queries: FeatureFlag,

    /// Requires/supports variable-length routing onion payloads
    // #[lnpwp_feature(8, 9)]
    pub var_onion_optin: FeatureFlag,

    /// Gossip queries can include additional information
    // #[lnpwp_feature(10, 11, requires(gossip_queries))]
    pub gossip_queries_ex: FeatureFlag,

    /// Static key for remote output
    // #[lnpwp_feature(12, 13)]
    pub option_static_remotekey: FeatureFlag,

    /// Node supports `payment_secret` field
    // #[lnpwp_feature(14, 15, requires(var_onion_optin))]
    pub payment_secret: FeatureFlag,

    /// Node can receive basic multi-part payments
    // #[lnpwp_feature(16, 17, requires(payment_secret))]
    pub basic_mpp: FeatureFlag,

    /// Can create large channels
    // #[lnpwp_feature(18, 19)]
    pub option_support_large_channel: FeatureFlag,

    /// Anchor outputs
    // #[lnpwp_feature(20, 21, requires(option_static_remotekey))]
    pub option_anchor_outputs: FeatureFlag,

    /// Rest of feature flags which are unknown to the current implementation
    pub unknown: FlagVec,
}

/// TODO: Implement proper strict encoding for Features

impl StrictEncode for Features {
    fn strict_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, strict_encoding::Error> {
        Ok(0)
    }
}

impl StrictDecode for Features {
    fn strict_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, strict_encoding::Error> {
        Ok(none!())
    }
}

impl LightningEncode for Features {
    fn lightning_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, std::io::Error> {
        Ok(0)
    }
}

impl LightningDecode for Features {
    fn lightning_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        Ok(none!())
    }
}
