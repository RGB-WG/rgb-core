// LNP/BP Rust Library
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

use std::{
    fmt::Debug,
    convert::{TryFrom, TryInto}
};
use bitcoin::{Txid, BlockHash};


#[derive(Copy, Clone, Debug, Display, PartialEq, Eq)]
#[display_from(Debug)]
pub enum Error {
    BlockHeightOutOfRange,
    InputIndexOutOfRange,
    OutputIndexOutOfRange,
    ChecksumOutOfRange,
}


#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord)]
#[display_from(Debug)]
pub struct BlockChecksum(u8);

impl BlockChecksum {
    pub fn into_u64(self) -> u64 {
        self.0 as u64
    }
}

impl From<BlockHash> for BlockChecksum {
    fn from(block_hash: BlockHash) -> Self {
        let mut xor: u8 = 0;
        for byte in block_hash.to_vec() {
            xor ^= byte;
        }
        Self(xor)
    }
}


#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord)]
#[display_from(Debug)]
pub struct TxChecksum(u64);

impl TxChecksum {
    pub fn into_u64(self) -> u64 {
        self.0
    }
}

impl From<Txid> for TxChecksum {
    fn from(txid: Txid) -> Self {
        let mut checksum: u64 = 0;
        for (shift, byte) in txid.to_vec()[0..5].iter().enumerate() {
           checksum ^= (*byte as u64) << (shift * 8);
        }
        Self(checksum)
    }
}


#[derive(Copy, Clone, Debug, Display)]
#[display_from(Debug)]
pub enum Descriptor {
    OnchainBlock { height: u32 },
    OnchainTransaction { block_height: u32, block_checksum: BlockChecksum, tx_index: u16 },
    OnchainTxInput { block_height: u32, block_checksum: BlockChecksum, tx_index: u16, input_index: u16 },
    OnchainTxOutput { block_height: u32, block_checksum: BlockChecksum, tx_index: u16, output_index: u16 },
    OffchainTransaction { tx_checksum: TxChecksum },
    OffchainTxInput { tx_checksum: TxChecksum, input_index: u16 },
    OffchainTxOutput { tx_checksum: TxChecksum, output_index: u16 },
}

impl Descriptor {
    pub fn try_validity(&self) -> Result<(), Error> {
        use Descriptor::*;
        use Error::*;

        match *self {
            OnchainTransaction { block_height, .. } |
            OnchainTxInput { block_height, .. } |
            OnchainTxOutput { block_height, .. }
            if block_height >= (2u32 << 22) =>
                Err(BlockHeightOutOfRange),
            OnchainTxInput { input_index, .. } |
            OffchainTxInput { input_index, .. }
            if input_index + 1 >= (2u16 << 14) =>
                Err(InputIndexOutOfRange),
            OnchainTxOutput { output_index, .. } |
            OffchainTxOutput { output_index, .. }
            if output_index + 1 >= (2u16 << 14) =>
                Err(OutputIndexOutOfRange),
            OffchainTransaction { tx_checksum, .. } |
            OffchainTxInput { tx_checksum, .. } |
            OffchainTxOutput { tx_checksum, .. }
            if tx_checksum.into_u64() >= (2u64 << 46) =>
                Err(ChecksumOutOfRange),
            _ => Ok(())
        }
    }

    pub fn is_onchain(&self) -> bool {
        use Descriptor::*;
        match self {
            OnchainBlock {..} | OnchainTransaction {..} | OnchainTxInput {..} | OnchainTxOutput {..} => true,
            _ => false,
        }
    }

    pub fn is_offchain(&self) -> bool {
        !self.is_onchain()
    }


    pub fn try_into_u64(self) -> Result<u64, Error> {
        ShortId::try_from(self).map(ShortId::into_u64)
    }
}


#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct ShortId(u64);

impl ShortId {
    pub const FLAG_OFFCHAIN: u64    = 0x8000_0000_0000_0000;
    pub const MASK_BLOCK: u64       = 0x7FFF_FF00_0000_0000;
    pub const MASK_BLOCKCHECK: u64  = 0x0000_00FF_0000_0000;
    pub const MASK_TXIDX: u64       = 0x0000_0000_FFFF_0000;
    pub const MASK_TXCHECK: u64     = 0x7FFF_FFFF_FFFF_0000;
    pub const FLAG_INOUT: u64       = 0x0000_0000_0000_8000;
    pub const MASK_INOUT: u64       = 0x0000_0000_0000_7FFF;

    pub const SHIFT_BLOCK: u64 = 40;
    pub const SHIFT_BLOCKCHECK: u64 = 32;
    pub const SHIFT_TXIDX: u64 = 16;

    pub fn is_onchain(&self) -> bool {
        self.0 & Self::FLAG_OFFCHAIN != Self::FLAG_OFFCHAIN
    }

    pub fn is_offchain(&self) -> bool {
        self.0 & Self::FLAG_OFFCHAIN == Self::FLAG_OFFCHAIN
    }

    pub fn get_descriptor(&self) -> Descriptor {
        #[inline]
        fn iconv<T>(val: u64) -> T where T: TryFrom<u64>, <T as TryFrom<u64>>::Error: Debug {
            val.try_into().expect("Conversion from existing ShortId can't fail")
        }

        let index: u16 = iconv(self.0 & Self::MASK_INOUT);

        if self.is_onchain() {
            let block_height: u32 = iconv((self.0 & Self::MASK_BLOCK) >> Self::SHIFT_BLOCK);
            if (self.0 & (!Self::MASK_BLOCK)) == 0 {
                return Descriptor::OnchainBlock { height: block_height }
            }
            let block_checksum = BlockChecksum(iconv((self.0 & Self::MASK_BLOCKCHECK) >> Self::SHIFT_BLOCKCHECK));
            let tx_index: u16 = iconv((self.0 & Self::MASK_TXIDX) >> Self::SHIFT_TXIDX);
            if (self.0 & (!Self::MASK_INOUT)) == 0 {
                return Descriptor::OnchainTransaction { block_height, block_checksum, tx_index }
            }
            if (self.0 & Self::FLAG_INOUT) == 0 {
                Descriptor::OnchainTxInput { block_height, block_checksum, tx_index, input_index: index - 1 }
            } else {
                Descriptor::OnchainTxOutput { block_height, block_checksum, tx_index, output_index: index - 1 }
            }
        } else {
            let tx_checksum = TxChecksum((self.0 & Self::MASK_TXCHECK) >> Self::SHIFT_TXIDX);
            if (self.0 & (!Self::MASK_INOUT)) == 0 {
                return Descriptor::OffchainTransaction { tx_checksum }
            }
            if (self.0 & Self::FLAG_INOUT) == 0 {
                Descriptor::OffchainTxInput { tx_checksum, input_index: index - 1 }
            } else {
                Descriptor::OffchainTxOutput { tx_checksum, output_index: index - 1 }
            }
        }
    }

    pub fn into_u64(self) -> u64 {
        self.into()
    }
}

impl From<ShortId> for Descriptor {
    fn from(short_id: ShortId) -> Self {
        short_id.get_descriptor()
    }
}

impl TryFrom<Descriptor> for ShortId {
    type Error = self::Error;

    fn try_from(descriptor: Descriptor) -> Result<Self, Self::Error> {
        use Descriptor::*;

        descriptor.try_validity()?;

        let block_height: u64 = match descriptor {
            OnchainBlock { height } => height,
            OnchainTransaction { block_height, .. } => block_height,
            OnchainTxInput { block_height, .. } => block_height,
            OnchainTxOutput { block_height, .. } => block_height,
            _ => 0,
        } as u64;
        let (block_checksum, tx_index) = match descriptor {
            OnchainTransaction { block_checksum, tx_index, .. } => (block_checksum, tx_index as u64),
            OnchainTxInput { block_checksum, tx_index, .. } => (block_checksum, tx_index as u64),
            OnchainTxOutput { block_checksum, tx_index, .. } => (block_checksum, tx_index as u64),
            _ => (BlockChecksum(0), 0),
        };
        let tx_checksum = match descriptor {
            OffchainTransaction { tx_checksum } => tx_checksum,
            OffchainTxInput { tx_checksum, .. } => tx_checksum,
            OffchainTxOutput { tx_checksum, .. } => tx_checksum,
            _ => TxChecksum(0),
        };
        let inout_index: u64 = match descriptor {
            OnchainTxInput { input_index, .. } => input_index + 1,
            OnchainTxOutput { output_index, .. } => output_index + 1,
            OffchainTxInput { input_index, .. } => input_index + 1,
            OffchainTxOutput { output_index, .. } => output_index + 1,
            _ => 0,
        } as u64;

        let mut short_id = 0u64;
        short_id |= inout_index;
        if descriptor.is_offchain() {
            short_id |= Self::FLAG_OFFCHAIN;
            short_id |= ((tx_checksum.into_u64() << Self::SHIFT_TXIDX) & Self::MASK_TXCHECK) as u64;
        } else {
            short_id |= (block_height << 40) & Self::MASK_BLOCK;
            short_id |= ((block_checksum.into_u64() << Self::SHIFT_BLOCKCHECK) & Self::MASK_BLOCKCHECK) as u64;
            short_id |= (tx_index << 16) & Self::MASK_TXIDX;
        }

        match descriptor {
            OnchainTxOutput {..} | OffchainTxOutput {..} => short_id |= Self::FLAG_INOUT << Self::SHIFT_TXIDX,
            _ => (),
        }

        Ok(Self(short_id))
    }
}

impl From<u64> for ShortId {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<ShortId> for u64 {
    fn from(short_id: ShortId) -> Self {
        short_id.0
    }
}
