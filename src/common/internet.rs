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

///! Universal addresses that support IPv4, IPv6 and Tor

pub enum AddressFormat {
    IPv4,
    IPv6,
    Tor
}

/// A universal address covering IPv4, IPv6 and Tor in a single byte sequence
/// of 32 bytes
///
/// Holds either:
/// * IPv4-to-IPv6 address
/// * IPv6 address
/// * Tor address
///
/// Tor addresses are distinguished by the fact that last 16 bits
/// must be set to 0
pub union AddressData {
    ipv4: [u8; 4],
    ipv6: [u16; 8],
    tor: [u8; 32],
}

pub enum Transport {
    TCP,
    UDP,
    MultipathTCP,
    QUIC,
    UDPLite,
    SCTP,
    DCCP,
    RUDP,
}

pub struct Address {
    format: AddressFormat,
    data: AddressData,
}

pub struct Socket {
    pub transport: Transport,
    pub address: Address,
    pub port: u16,
}
