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

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::hash::Hash;

use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut};

use super::extension::{self, ChannelExtension, Extension};
use super::Messages;

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    Error,
    From,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(doc_comments)]
pub enum Error {
    /// Extension-specific error: {0}
    Extension(String),
}

/// Marker trait for any data that can be used as a part of the channel state
pub trait State
/*where
Self: Clone
    + Debug
    + StrictEncode<Error = strict_encoding::Error>
    + StrictDecode<Error = strict_encoding::Error>,*/
{
}

/// Channel data in fact is a data of all it's extensions
pub type ChannelData<N> = BTreeMap<N, Box<dyn State>>;
impl<N> State for ChannelData<N> where N: extension::Nomenclature {}

/// Channel operates as a three sets of extensions, where each set is applied
/// to construct the transaction graph and the state in a strict order one after
/// other. The order of the extensions within each set is defined by the
/// concrete type implementing `extension::Nomenclature` marker trait, provided
/// as a type parameter `N`
pub struct Channel<N>
where
    N: extension::Nomenclature,
{
    /// Constructor extensions constructs base transaction graph. There could
    /// be only a single extension of this type
    constructor: Box<
        dyn ChannelExtension<
            ExtensionState = ChannelData<N>,
            ChannelState = ChannelData<N>,
        >,
    >,

    /// Extender extensions adds additional outputs to the transaction graph
    /// and the state data associated with these outputs, like HTLCs, PTLCs,
    /// anchored outputs, DLC-specific outs etc
    extenders: BTreeMap<
        N,
        Box<
            dyn ChannelExtension<
                ExtensionState = ChannelData<N>,
                ChannelState = ChannelData<N>,
            >,
        >,
    >,

    /// Modifier extensions do not change number of outputs, but may change
    /// their ordering or tweak individual inputs, outputs and public keys.
    /// These extensions may include: BIP96 lexicographic ordering, RGB, Liquid
    modifiers: BTreeMap<
        N,
        Box<
            dyn ChannelExtension<
                ExtensionState = ChannelData<N>,
                ChannelState = ChannelData<N>,
            >,
        >,
    >,
}

/// Channel is the extension to itself :) so it receives the same input as any
/// other extension and just forwards it to them
impl<N> Extension for Channel<N>
where
    N: extension::Nomenclature,
{
    type ExtensionState = ChannelData<N>;

    fn update_from_peer(&mut self, data: Messages) -> Result<(), Error> {
        unimplemented!()
    }

    fn extension_state(&self) -> Self::ExtensionState {
        unimplemented!()
    }
}

/// Channel is the extension to itself :) so it receives the same input as any
/// other extension and just forwards it to them
impl<N> ChannelExtension for Channel<N>
where
    N: extension::Nomenclature,
{
    type ChannelState = ChannelData<N>;

    fn channel_state(&self) -> Self::ChannelState {
        unimplemented!()
    }

    fn apply(&mut self, tx_graph: &mut TxGraph) -> Result<(), Error> {
        unimplemented!()
    }
}

pub trait TxRole: Clone + From<u16> + Into<u16> {}
pub trait TxIndex: Clone + From<u64> + Into<u64> {}

#[derive(Getters, Clone, PartialEq, StrictEncode, StrictDecode)]
#[lnpbp_crate(crate)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct TxGraph {
    funding_parties: u8,
    funding_threshold: u8,
    funding_tx: Psbt,
    funding_outpoint: OutPoint,
    pub cmt_version: i32,
    pub cmt_locktime: u32,
    pub cmt_sequence: u32,
    pub cmt_outs: Vec<TxOut>,
    graph: BTreeMap<u16, BTreeMap<u64, Psbt>>,
}

impl TxGraph {
    pub fn tx<R, I>(&self, role: R, index: I) -> Option<&Psbt>
    where
        R: TxRole,
        I: TxIndex,
    {
        self.graph
            .get(&role.into())
            .and_then(|v| v.get(&index.into()))
    }

    pub fn tx_mut<R, I>(&mut self, role: R, index: I) -> Option<&mut Psbt>
    where
        R: TxRole,
        I: TxIndex,
    {
        self.graph
            .get_mut(&role.into())
            .and_then(|v| v.get_mut(&index.into()))
    }

    pub fn len(&self) -> usize {
        self.graph
            .iter()
            .fold(0usize, |sum, (_, map)| sum + map.len())
    }

    pub fn render(&self) -> Vec<Psbt> {
        let mut txes = Vec::with_capacity(self.len());
        let cmt_tx = self.render_cmt();
        txes.push(cmt_tx);
        txes.extend(self.graph.values().flat_map(|v| v.values().cloned()));
        txes
    }

    pub fn render_cmt(&self) -> Psbt {
        let cmt_tx = Transaction {
            version: self.cmt_version,
            lock_time: self.cmt_locktime,
            input: vec![TxIn {
                previous_output: self.funding_outpoint,
                script_sig: empty!(),
                sequence: self.cmt_sequence,
                witness: empty!(),
            }],
            output: self.cmt_outs.clone(),
        };
        Psbt::from_unsigned_tx(cmt_tx).expect(
            "PSBT construction fails only if script_sig and witness are not \
                empty; which is not the case here",
        )
    }
}

pub trait History {
    type State;
    type Error: std::error::Error;

    fn height(&self) -> usize;
    fn get(&self, height: usize) -> Result<Self::State, Self::Error>;
    fn top(&self) -> Result<Self::State, Self::Error>;
    fn bottom(&self) -> Result<Self::State, Self::Error>;
    fn dig(&self) -> Result<Self::State, Self::Error>;
    fn push(&mut self, state: Self::State) -> Result<&mut Self, Self::Error>;
}
