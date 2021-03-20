// RGB20 Library: fungible digital assets for bitcoin & lightning
// Written in 2020-2021 by
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

//! Asset supply information & management

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use bitcoin::OutPoint;
use rgb::prelude::*;

/// Specific supply measure to be provided; used as an argument for methods
/// returning supply information
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u8)]
pub enum SupplyMeasure {
    /// Supply known to be issued, minus all known burns, plus known
    /// replacements
    KnownCirculating = 0,

    /// Forces method to return precise supply data, either equal to the
    /// known circulating supply, or if some of the supply-related operations
    /// are unknown, [`FractionalSupply:NAN`] value
    TotalCirculating = 1,

    /// Maximum issue limit, defined as a sum of all genesis-defined inflation
    /// allowed amounts, plus amount of assets issued in genesis
    IssueLimit = 2,
}

/// Structure providing extended information about the asset supply, derived
/// from the known/available contract data.
///
/// Structure fields are immutable since they are bound with
/// client-side-validation commitments and can't be changed.
#[derive(
    Getters,
    Clone,
    Copy,
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
    /// Sum of all already issued amounts which are known from the stash
    known_circulating: AtomicValue,

    /// Specifies if all supply-changing operations are known.
    ///
    /// This include:
    /// - issue state transitions for all already spent `inflation`
    ///   single-use-seals,
    /// - burn operations from all opened epochs
    /// - replace operations from all opened epochs
    ///
    /// The field takes three states:
    /// - `None`, meaning that it is unknown are all data is present (this is
    ///   default state indicating that blockchain was not scanned for the
    ///   closed seals from supply-chaning operations, and we do not know do we
    ///   have all of the data or not)
    /// - `Some(false)`: there are supply-changing operations on which we do
    ///   not have client-validated state data
    /// - `Some(true)`: we have a complete set of client-validated data and
    ///   know the exact supply
    ///
    /// In this case `known_circulating` will be equal to `total_circulating`.
    /// The parameter is option since the fact that the UTXO is spend may
    /// be unknown without blockchain access
    is_known: Option<bool>,

    /// Maximum total supply that might be issued
    ///
    /// We always know total supply, b/c even for assets without defined cap
    /// the cap *de facto* equals to `u64::MAX`
    issue_limit: AtomicValue,
}

impl Supply {
    /// Constructor for structure initialization. Can not be used externally;
    /// the structure is always created from RGB contract data.
    #[inline]
    pub(crate) fn with(
        known_circulating: AtomicValue,
        is_known: Option<bool>,
        issue_limit: AtomicValue,
    ) -> Supply {
        Supply {
            known_circulating,
            is_known,
            issue_limit,
        }
    }

    /// Return precise supply data, if known, equal to the known circulating
    /// supply, or if some of the supply-related operations are unknown,
    /// `None` value
    #[inline]
    pub fn total_circulating(&self) -> Option<AtomicValue> {
        if self.is_known.unwrap_or(false) {
            Some(self.known_circulating)
        } else {
            None
        }
    }
}

/// Structure keeping information about particular asset issue (primary or
/// secondary, also called inflationary).
///
/// Structure fields are immutable since they are bound with
/// client-side-validation commitments and can't be changed.
#[derive(
    Getters,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
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

    /// Contract ID to which this issue is related to
    contract_id: ContractId,

    /// Amount of the issued asset
    amount: AtomicValue,

    /// Indicates transaction outputs which had an assigned inflation right and
    /// which spending produced this issue. Empty array signifies that the
    /// issue was produced by genesis (i.e. it is a primary issue)
    origin: Vec<OutPoint>,

    /// Seals controlling secondary (inflationary) issues, with corresponding
    /// maximum amount of the inflation allowed via spending that seal
    inflation_assignments: BTreeMap<OutPoint, AtomicValue>,
}

impl Issue {
    /// Constructor for structure initialization. Can not be used externally;
    /// the structure is always created from RGB contract data.
    pub(crate) fn with(
        id: NodeId,
        contract_id: ContractId,
        amount: AtomicValue,
        origin: Vec<OutPoint>,
        inflation_assignments: BTreeMap<OutPoint, AtomicValue>,
    ) -> Issue {
        Issue {
            id,
            contract_id,
            amount,
            origin,
            inflation_assignments,
        }
    }

    /// Detects if the issue is primary (i.e. defined as a part of genesis data)
    #[inline]
    pub fn is_primary(&self) -> bool {
        self.origin.is_empty()
    }

    /// Detects if the issue is secondary (i.e. created with inflation state
    /// transition)
    #[inline]
    pub fn is_secondary(&self) -> bool {
        !self.origin.is_empty()
    }
}

/// Data structure keeping information about asset burn & replace epoch
///
/// Structure fields are immutable since they are bound with
/// client-side-validation commitments and can't be changed.
#[derive(
    Getters,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
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
#[display("{id} -> {no}")]
pub struct Epoch {
    /// Unique primary key; equals to the state transition id that performs
    /// operation opening this epoch
    id: NodeId,

    /// Sequential number of the epoch
    ///
    /// NB: There is no zero epoch and the first is an epoch closing genesis
    /// epoch seal
    no: u16,

    /// Contract ID to which this epoch is related to
    contract_id: ContractId,

    /// Indicates transaction output/seal which had an assigned epoch right and
    /// which spending produced opened this epoch.
    closes: OutPoint,

    /// Seal controlling start of the next burn & replace epoch. This can be
    /// set to `None` in case if the epoch is the last epoch and closes
    /// availability of burn or replace operations for the future.
    epoch_seal: Option<OutPoint>,

    /// Initial seal controlling first burn or burn&replace operation.
    ///
    /// This can be set to `None` in case if the epoch closes availability of
    /// burn or replace operations for the future AND does not allow burn &
    /// replace operations within itself
    seal: Option<OutPoint>,

    /// Detects if the epoch is the final epoch, meaning that no other epoch
    /// can be opened after it
    is_final: bool,

    /// Detects if the epoch allows burn & replace operations to happen
    is_unlocked: bool,

    /// Sequence of known burn & replace operations
    known_operations: Vec<BurnReplace>,
}

impl Epoch {
    /// Constructor for structure initialization. Can not be used externally;
    /// the structure is always created from RGB contract data.
    #[allow(unused)]
    pub(crate) fn with(
        id: NodeId,
        contract_id: ContractId,
        no: u16,
        closes: OutPoint,
        epoch_seal: Option<OutPoint>,
        seal: Option<OutPoint>,
        known_operations: Vec<BurnReplace>,
    ) -> Self {
        Epoch {
            id,
            no,
            contract_id,
            closes,
            epoch_seal,
            seal,
            is_final: epoch_seal.is_none(),
            is_unlocked: seal.is_some(),
            known_operations,
        }
    }
}

/// Data structure keeping information about asset burn & replace operation
///
/// Structure fields are immutable since they are bound with
/// client-side-validation commitments and can't be changed.
#[derive(
    Getters,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
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
#[display("{id} -> {no}")]
pub struct BurnReplace {
    /// Unique primary key; equals to the state transition id that performs
    /// burn & replace operation
    id: NodeId,

    /// Node ID of the state transition opening epoch under which this
    /// operation is performed
    epoch_id: ContractId,

    /// Sequential number of the operation within its epoch
    ///
    /// NB: There is no zero epoch and the first is an epoch closing genesis
    /// epoch seal
    no: u16,

    /// Contract ID to which this burn & replace operation is related to
    contract_id: ContractId,

    /// Indicates transaction output/seal which had an assigned burn & replace
    /// right and which spending produced opened this epoch.
    closes: OutPoint,

    /// Indicates whether this is operation performs at least partial
    /// replacement of the burned assets, or it is a pure burn operation
    does_replacement: bool,

    /// Amount of the asset which was burned with this operation.
    ///
    /// For burn & replace operations this does not means the amount of the
    /// asset that was removed from the circulation, since some of the burned
    /// assets may be replaced with newly issued.
    ///
    /// See also:
    /// - [`replaced_amount()`]
    /// - [`supply_change()`]
    burned_amount: AtomicValue,

    /// Amount of the asset which was replaced (i.e. re-issued) with this
    /// operation.
    ///
    /// For burn & replace operations this does not means the amount of the
    /// asset that was added from the circulation, since the same or more of
    /// the asset was burned.
    ///
    /// See also:
    /// - [`burned_amount()`]
    /// - [`supply_change()`]
    replaced_amount: AtomicValue,

    /// Net change to the supply of the circulating asset following this
    /// operation.
    ///
    /// Fur pure burn operations (without asset replacement) this equals to the
    /// [`burned_amount()`] (and [`replaced_amount()`] is set to `0`). For burn
    /// & replace operations this is equal to `burned_amount - replaced_amount`
    supply_change: AtomicValue,

    /// Detects if the operation is final for the epoch, meaning that no other
    /// burn or replacement can happen after it
    is_final: bool,

    /// Initial seal controlling next burn or burn & replace operation.
    ///
    /// This can be set to `None` in case if the epoch closes availability of
    /// burn or replace operations for the epoch, i.e. it is final. In this
    /// case [`is_final()`] will return `true`.
    seal: Option<OutPoint>,
}

impl BurnReplace {
    /// Constructor for structure initialization. Can not be used externally;
    /// the structure is always created from RGB contract data.
    #[allow(unused)]
    pub(crate) fn with(
        id: NodeId,
        epoch_id: ContractId,
        no: u16,
        contract_id: ContractId,
        closes: OutPoint,
        does_replacement: bool,
        burned_amount: AtomicValue,
        replaced_amount: AtomicValue,
        seal: Option<OutPoint>,
    ) -> Self {
        BurnReplace {
            id,
            epoch_id,
            no,
            contract_id,
            closes,
            does_replacement,
            burned_amount,
            replaced_amount,
            supply_change: burned_amount - replaced_amount,
            is_final: seal.is_none(),
            seal,
        }
    }
}

// TODO: Define consistancy trait with operations like `is_consistent` and
//       `make_consistent`, checking internal consistency of the denormalized
//       data within each type of the RGB20 structures
