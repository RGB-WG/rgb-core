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

message!(Init, 16, {
    global_features: [u8; u16],
    local_features: [u8; u16],
}, {
    1: networks => [ChainCode]
});

pub enum LnMessages {
    Init {
        global_features: Features,
        local_features: Features,
        networks: Vec<ChainCode>,
    },
}

pub struct Message<T> {
    pub type_id: T,
    pub payload: Vec<Arc<dyn Value<T::ValueTypes>>>,
    pub tlvs: BTreeMap<u64, Vec<u8>>,
}

pub trait Value<VT>: lnp::Encode + lnp::Decode
where
    VT: From<u64> + Into<u64>,
{
}

pub struct Init {
    pub global_features: Features,
    pub local_features: Features,
    pub networks: Vec<ChainCode>,
    pub unknown_tlvs: BTreeMap<u64, Vec<u8>>,
}

impl Message for Init {
    fn msg_type() -> u64 {
        16u64
    }
}

fn some() {}
