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

use std::fmt;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(feature="use-tor")]
use torut::onion::{TorPublicKeyV3, OnionAddressV3, TORV3_PUBLIC_KEY_LENGTH};


/// A universal address covering IPv4, IPv6 and Tor in a single byte sequence
/// of 32 bytes.
///
/// Holds either:
/// * IPv4-to-IPv6 address
/// * IPv6 address
/// * Tor address (only 3rd version is supported)
///
/// NB: we are using `TorPublicKeyV3` instead of `OnionAddressV3`, since
/// `OnionAddressV3` keeps cehcksum and other information wich can be
/// reconstructed from `TorPublicKeyV3`. The 2-byte checksum in `OnionAddressV3`
/// is designed for human-readable part that checks that the address was typed
/// in correctly. In computer-stored digital data it may be deterministically
/// regenerated and does not add any additional security.
///
/// Tor addresses are distinguished by the fact that last 16 bits
/// must be set to 0
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InetAddr {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    #[cfg(feature="use-tor")]
    Tor(TorPublicKeyV3),
}

impl InetAddr {
    pub fn get_ip6(&self) -> Option<Ipv6Addr> {
        match self {
            InetAddr::IPv4(ipv4_addr) => Some(ipv4_addr.to_ipv6_mapped()),
            InetAddr::IPv6(ipv6_addr) => Some(*ipv6_addr),
            #[cfg(feature="use-tor")]
            _ => None,
        }
    }

    pub fn from_32bit_encoding(data: [u8; TORV3_PUBLIC_KEY_LENGTH]) -> Option<Self> {
        match data {
            d if d[0..28] == [0u8; 28] => {
                let mut a = [0u8; 4];
                a.clone_from_slice(&d[28..]);
                Some(InetAddr::IPv4(Ipv4Addr::from(a)))
            },
            d if d[0..24] == [0u8; 16] => {
                let mut a = [0u8; 16];
                a.clone_from_slice(&d[16..]);
                Some(InetAddr::IPv6(Ipv6Addr::from(a)))
            },
            #[cfg(feature="use-tor")]
            d  => TorPublicKeyV3::from_bytes(&d).map(|pk| InetAddr::Tor(pk)).ok(),
        }
    }

    pub fn get_32bit_encoding(&self) -> [u8; TORV3_PUBLIC_KEY_LENGTH] {
        let mut buf = [0u8; 32];
        match self {
            InetAddr::IPv4(ipv4_addr) => buf[24..].copy_from_slice(&ipv4_addr.octets()),
            InetAddr::IPv6(ipv6_addr) => buf[16..].copy_from_slice(&ipv6_addr.octets()),
            #[cfg(feature="use-tor")]
            InetAddr::Tor(tor_addr) => buf = tor_addr.to_bytes(),
        }
        buf
    }
}

impl fmt::Display for InetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // TODO:
            InetAddr::IPv4(addr) => write!(f, "{}", addr),
            InetAddr::IPv6(addr) => write!(f, "{}", addr),
            #[cfg(feature="use-tor")]
            InetAddr::Tor(addr) => write!(f, "{}", addr),
        }
    }
}

#[cfg(feature="use-tor")]
impl TryFrom<InetAddr> for IpAddr {
    type Error = ();
    #[inline]
    fn try_from(addr: InetAddr) -> Result<Self, Self::Error> {
        Ok(match addr {
            InetAddr::IPv4(addr) => IpAddr::V4(addr),
            InetAddr::IPv6(addr) => IpAddr::V6(addr),
            InetAddr::Tor(addr) => Err(())?,
        })
    }
}

#[cfg(not(feature="use-tor"))]
impl From<InetAddr> for IpAddr {
    #[inline]
    fn from(addr: InetAddr) -> Self {
        match addr {
            InetAddr::IPv4(addr) => IpAddr::V4(addr),
            InetAddr::IPv6(addr) => IpAddr::V6(addr),
        }
    }
}

impl From<IpAddr> for InetAddr {
    #[inline]
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(v4) => InetAddr::from(v4),
            IpAddr::V6(v6) => InetAddr::from(v6),
        }
    }
}

impl From<Ipv4Addr> for InetAddr {
    fn from(addr: Ipv4Addr) -> Self { InetAddr::IPv4(addr) }
}

impl From<Ipv6Addr> for InetAddr {
    fn from(addr: Ipv6Addr) -> Self { InetAddr::IPv6(addr) }
}

#[cfg(feature="use-tor")]
impl From<TorPublicKeyV3> for InetAddr {
    fn from(value: TorPublicKeyV3) -> Self {
        InetAddr::Tor(value)
    }
}

#[cfg(feature="use-tor")]
impl From<OnionAddressV3> for InetAddr {
    fn from(addr: OnionAddressV3) -> Self { InetAddr::Tor(addr.get_public_key()) }
}

impl TryFrom<String> for InetAddr {
    type Error = ();
    fn try_from(value: String) -> Result<Self, Self::Error> {
        InetAddr::try_from(value.as_str())
    }
}

impl TryFrom<&str> for InetAddr {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl TryFrom<Vec<u8>> for InetAddr {
    type Error = ();
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        InetAddr::try_from(&value[..])
    }
}

impl TryFrom<&[u8]> for InetAddr {
    type Error = ();
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            4 => {
                let mut buf = [0u8; 4];
                buf.clone_from_slice(value);
                Ok(InetAddr::from(buf))
            },
            16 => {
                let mut buf = [0u8; 16];
                buf.clone_from_slice(value);
                Ok(InetAddr::from(buf))
            },
            #[cfg(feature="use-tor")]
            32 => {
                let mut buf = [0u8; 32];
                buf.clone_from_slice(value);
                InetAddr::try_from(buf)
            }
            _ => Err(())
        }
    }
}

impl From<[u8; 4]> for InetAddr {
    fn from(value: [u8; 4]) -> Self {
        InetAddr::from(Ipv4Addr::from(value))
    }
}

impl From<[u8; 16]> for InetAddr {
    fn from(value: [u8; 16]) -> Self {
        InetAddr::from(Ipv6Addr::from(value))
    }
}

impl From<[u16; 8]> for InetAddr {
    fn from(value: [u16; 8]) -> Self {
        InetAddr::from(Ipv6Addr::from(value))
    }
}

#[cfg(feature="use-tor")]
impl TryFrom<[u8; TORV3_PUBLIC_KEY_LENGTH]> for InetAddr {
    type Error = ();
    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Self::from_32bit_encoding(value).ok_or(())
    }
}

/// Transport protocols that may be part of `TransportAddr`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Normal TCP
    TCP,

    /// Normal UDP
    UDP,

    /// Multipath TCP version
    MTCP,

    /// More efficient UDP version under developent by Google and consortium of
    /// other internet companies
    QUIC,

    // There are other rarely used protocols. Do not see any reason to add
    // them to the LNP/BP stack for now, but it may appear in the future,
    // so keeping them for referencing purposes:
    /*
    UDPLite,
    SCTP,
    DCCP,
    RUDP,
    */
}

impl TryFrom<String> for Transport {
    type Error = ();
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut val = value.to_lowercase();
        val.push(':');
        Ok(match &val[..4] {
            "tcp:" => Transport::TCP,
            "udp:" => Transport::UDP,
            "mtcp" => Transport::MTCP,
            "quic" => Transport::QUIC,
            _ => Err(())?
        })
    }
}

impl TryFrom<&str> for Transport {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_string())
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", match self {
            Transport::TCP => "tcp",
            Transport::UDP => "udp",
            Transport::MTCP => "mtcp",
            Transport::QUIC => "quic",
        })
    }
}



// TODO: Implement `PartialEq` and `Eq` for `internet::Socket` when
//       `internet::Address` will support them
#[derive(Clone, Copy, Debug, Display)]
#[display_from(Debug)]
pub struct InetSocketAddr {
    pub transport: Transport,
    pub address: InetAddr,
    pub port: u16,
}

#[cfg(feature="use-tor")]
impl TryFrom<InetSocketAddr> for std::net::SocketAddr {
    type Error = ();
    fn try_from(socket_addr: InetSocketAddr) -> Result<Self, Self::Error> {
        Ok(Self::new(IpAddr::try_from(socket_addr.address)?, socket_addr.port))
    }
}

#[cfg(not(feature="use-tor"))]
impl From<InetSocketAddr> for std::net::SocketAddr {
    fn from(socket_addr: InetSocketAddr) -> Self {
        Self::new(IpAddr::from(socket_addr.address), socket_addr.port)
    }
}
