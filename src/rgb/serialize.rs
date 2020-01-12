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


pub trait Commitment {
    fn commitment_serialize(&self) -> Vec<u8>;
}

pub trait Network {
    fn network_serialize(&self) -> Vec<u8>;
}

pub trait Storage {
    fn storage_serialize(&self) -> Vec<u8>;
}

pub trait CommitmentNetwork: Commitment + Network {

}

pub trait CommitmentNetworkStorage: Commitment + Network + Storage {

}

impl dyn CommitmentNetwork {
    fn network_serialize(&self) -> Vec<u8> {
        self.commitment_serialize()
    }
}

impl dyn CommitmentNetworkStorage {
    fn storage_serialize(&self) -> Vec<u8> {
        self.network_serialize()
    }
}
