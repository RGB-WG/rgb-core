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
use std::ops::{Add, AddAssign};

use rgb::AtomicValue;

pub type FractionalAmount = f64;

/// Accounting amount keeps track of the asset precision
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
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
    serde(crate = "serde_crate")
)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{0}~{1}")]
pub struct PreciseAmount(AtomicValue, u8);

impl PreciseAmount {
    const DIVIDER: [u64; 20] = [
        1,
        10,
        100,
        1_000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
        10_000_000_000,
        100_000_000_000,
        1_000_000_000_000,
        10_000_000_000_000,
        100_000_000_000_000,
        1_000_000_000_000_000,
        10_000_000_000_000_000,
        100_000_000_000_000_000,
        1_000_000_000_000_000_000,
        10_000_000_000_000_000_000,
    ];

    #[inline]
    pub fn transmutate_from(
        fractional_amount: FractionalAmount,
        decimal_precision: u8,
    ) -> AtomicValue {
        PreciseAmount::from_fractional_amount(
            fractional_amount,
            decimal_precision,
        )
        .atomic_value()
    }

    #[inline]
    pub fn transmutate_into(
        atomic_value: AtomicValue,
        decimal_precision: u8,
    ) -> FractionalAmount {
        PreciseAmount::from_atomic_value(atomic_value, decimal_precision)
            .fractional_amount()
    }

    #[inline]
    pub fn from_atomic_value(
        atomic_value: AtomicValue,
        decimal_precision: u8,
    ) -> Self {
        Self(atomic_value, decimal_precision)
    }

    #[inline]
    pub fn from_fractional_amount(
        fractional_amount: FractionalAmount,
        decimal_precision: u8,
    ) -> Self {
        let full = (fractional_amount.trunc() as u64)
            * Self::DIVIDER[decimal_precision as usize];
        let fract = fractional_amount.fract() as u64;
        Self(full + fract, decimal_precision)
    }

    #[inline]
    pub fn fractional_amount(&self) -> FractionalAmount {
        self.0 as f64 / Self::DIVIDER[self.1 as usize] as f64
    }

    #[inline]
    pub fn atomic_value(&self) -> AtomicValue {
        self.0
    }

    #[inline]
    pub fn decimal_precision(&self) -> u8 {
        self.1
    }
}

impl Add for PreciseAmount {
    type Output = PreciseAmount;
    fn add(self, rhs: Self) -> Self::Output {
        if self.decimal_precision() != rhs.decimal_precision() {
            panic!("Addition of amounts with different fractional bits")
        } else {
            PreciseAmount::from_atomic_value(
                self.atomic_value() + rhs.atomic_value(),
                self.decimal_precision(),
            )
        }
    }
}

impl AddAssign for PreciseAmount {
    fn add_assign(&mut self, rhs: Self) {
        if self.decimal_precision() != rhs.decimal_precision() {
            panic!("Addition of amounts with different fractional bits")
        } else {
            self.0 += rhs.0
        }
    }
}
