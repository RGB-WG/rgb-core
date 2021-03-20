// RGB20 Library: fungible digital assets for bitcoin & lightning
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

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};

use rgb::prelude::*;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u8)]
pub enum SupplyMeasure {
    KnownCirculating = 0,
    TotalCirculating = 1,
    IssueLimit = 2,
}

#[derive(
    Clone,
    Copy,
    Getters,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    Default,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("circulating {known_circulating}, max {issue_limit}")]
pub struct Supply {
    /// Sum of all issued amounts
    known_circulating: AtomicValue,

    /// Specifies if all issuances are known (i.e. there are data for issue
    /// state transitions for all already spent `inflation`
    /// single-use-seals). In this case `known_circulating` will be equal to
    /// `total_circulating`. The parameter is option since the fact that the
    /// UTXO is spend may be unknown without blockchain access
    is_issued_known: Option<bool>,

    /// We always know total supply, b/c even for assets without defined cap
    /// the cap *de facto* equals to u64::MAX
    issue_limit: AtomicValue,
}

impl Supply {
    #[inline]
    pub(crate) fn with(
        known_circulating: AtomicValue,
        is_issued_known: Option<bool>,
        issue_limit: AtomicValue,
    ) -> Supply {
        Supply {
            known_circulating,
            is_issued_known,
            issue_limit,
        }
    }

    #[inline]
    pub fn total_circulating(&self) -> Option<AtomicValue> {
        if self.is_issued_known.unwrap_or(false) {
            Some(self.known_circulating)
        } else {
            None
        }
    }
}

#[derive(
    Clone,
    Copy,
    Getters,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{id} -> {amount}")]
pub struct Issue {
    /// Unique primary key; equals to the state transition id that performs
    /// issuance (i.e. of `issue` type)
    id: NodeId,

    /// Amount of the issued asset
    amount: AtomicValue,

    /// Indicates transaction output which had an assigned inflation right and
    /// which spending produced this issue. `None` signifies that the issue
    /// was produced by genesis (i.e. it is a primary issue)
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    origin: Option<bitcoin::OutPoint>,
}

impl Issue {
    pub(crate) fn with(
        id: NodeId,
        amount: AtomicValue,
        origin: Option<bitcoin::OutPoint>,
    ) -> Issue {
        Issue { id, amount, origin }
    }

    #[inline]
    pub fn is_primary(&self) -> bool {
        self.origin.is_none()
    }

    #[inline]
    pub fn is_secondary(&self) -> bool {
        self.origin.is_some()
    }
}
