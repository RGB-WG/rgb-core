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

use std::convert::TryFrom;
///! Universal addresses that support IPv4, IPv6 and Tor
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
#[cfg(feature = "tor")]
use torut::onion::{OnionAddressV3, TorPublicKeyV3, TORV3_PUBLIC_KEY_LENGTH};

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
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        try_from = "amplify::CowHelper",
        into = "String",
        crate = "serde_crate"
    )
)]
pub enum InetAddr {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    #[cfg(feature = "tor")]
    Tor(TorPublicKeyV3),
}

impl InetAddr {
    #[cfg(feature = "tor")]
    pub const UNIFORM_ADDR_LEN: usize = TORV3_PUBLIC_KEY_LENGTH;
    #[cfg(not(feature = "tor"))]
    pub const UNIFORM_ADDR_LEN: usize = 32;

    #[inline]
    pub fn get_ip6(&self) -> Option<Ipv6Addr> {
        match self {
            InetAddr::IPv4(ipv4_addr) => Some(ipv4_addr.to_ipv6_mapped()),
            InetAddr::IPv6(ipv6_addr) => Some(*ipv6_addr),
            #[cfg(feature = "tor")]
            _ => None,
        }
    }

    #[cfg(not(feature = "tor"))]
    #[inline]
    pub fn is_tor(&self) -> bool {
        false
    }

    #[cfg(feature = "tor")]
    #[inline]
    pub fn is_tor(&self) -> bool {
        if let InetAddr::Tor(_) = self {
            true
        } else {
            false
        }
    }

    pub fn from_uniform_encoding(data: &[u8]) -> Option<Self> {
        if data.len() != Self::UNIFORM_ADDR_LEN {
            None?
        }

        let mut slice = [0u8; Self::UNIFORM_ADDR_LEN];
        slice.clone_from_slice(data);

        match slice {
            d if d[0..28] == [0u8; 28] => {
                let mut a = [0u8; 4];
                a.clone_from_slice(&d[28..]);
                Some(InetAddr::IPv4(Ipv4Addr::from(a)))
            }
            d if d[0..16] == [0u8; 16] => {
                let mut a = [0u8; 16];
                a.clone_from_slice(&d[16..]);
                Some(InetAddr::IPv6(Ipv6Addr::from(a)))
            }
            #[cfg(feature = "tor")]
            d => TorPublicKeyV3::from_bytes(&d).map(InetAddr::Tor).ok(),
            #[cfg(not(feature = "tor"))]
            _ => None,
        }
    }

    pub fn to_uniform_encoding(&self) -> [u8; Self::UNIFORM_ADDR_LEN] {
        let mut buf = [0u8; Self::UNIFORM_ADDR_LEN];
        match self {
            InetAddr::IPv4(ipv4_addr) => buf[28..].copy_from_slice(&ipv4_addr.octets()),
            InetAddr::IPv6(ipv6_addr) => buf[16..].copy_from_slice(&ipv6_addr.octets()),
            #[cfg(feature = "tor")]
            InetAddr::Tor(tor_addr) => buf = tor_addr.to_bytes(),
        }
        buf
    }
}

impl Default for InetAddr {
    #[inline]
    fn default() -> Self {
        InetAddr::IPv4(Ipv4Addr::from(0))
    }
}

impl fmt::Display for InetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // TODO:
            InetAddr::IPv4(addr) => write!(f, "{}", addr),
            InetAddr::IPv6(addr) => write!(f, "{}", addr),
            #[cfg(feature = "tor")]
            InetAddr::Tor(addr) => write!(f, "{}", addr),
        }
    }
}

impl TryFrom<InetAddr> for IpAddr {
    type Error = String;
    #[inline]
    fn try_from(addr: InetAddr) -> Result<Self, Self::Error> {
        Ok(match addr {
            InetAddr::IPv4(addr) => IpAddr::V4(addr),
            InetAddr::IPv6(addr) => IpAddr::V6(addr),
            #[cfg(feature = "tor")]
            InetAddr::Tor(_) => Err(String::from("IpAddr can't be used to store Tor address"))?,
        })
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
    #[inline]
    fn from(addr: Ipv4Addr) -> Self {
        InetAddr::IPv4(addr)
    }
}

impl From<Ipv6Addr> for InetAddr {
    #[inline]
    fn from(addr: Ipv6Addr) -> Self {
        InetAddr::IPv6(addr)
    }
}

#[cfg(feature = "tor")]
impl From<TorPublicKeyV3> for InetAddr {
    #[inline]
    fn from(value: TorPublicKeyV3) -> Self {
        InetAddr::Tor(value)
    }
}

#[cfg(feature = "tor")]
impl From<OnionAddressV3> for InetAddr {
    #[inline]
    fn from(addr: OnionAddressV3) -> Self {
        InetAddr::Tor(addr.get_public_key())
    }
}

impl_try_from_stringly_standard!(InetAddr);
impl_into_stringly_standard!(InetAddr);

impl FromStr for InetAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match IpAddr::from_str(s) {
            Ok(ip_addr) => Ok(Self::from(ip_addr)),
            #[cfg(feature = "tor")]
            Err(_) => Ok(Self::from(
                OnionAddressV3::from_str(s)
                    .map(Self::from)
                    .map_err(|_| String::from("Wrong onion address string"))?,
            )),
            #[cfg(not(feature = "tor"))]
            Err(_) => Err(String::from(
                "Tor addresses are not supported; consider compiling with 'use-tor' feature",
            )),
        }
    }
}

impl TryFrom<Vec<u8>> for InetAddr {
    type Error = String;
    #[inline]
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        InetAddr::try_from(&value[..])
    }
}

// Yes, I checked that onion addresses don't need to optimize ownership of input String.
#[cfg(feature = "parse_arg")]
impl parse_arg::ParseArgFromStr for InetAddr {
    fn describe_type<W: std::fmt::Write>(mut writer: W) -> std::fmt::Result {
        #[cfg(not(feature = "tor"))]
        {
            write!(writer, "IPv4 or IPv6 address")
        }
        #[cfg(feature = "tor")]
        {
            write!(writer, "IPv4, IPv6, or Tor (onion) address")
        }
    }
}

impl TryFrom<&[u8]> for InetAddr {
    type Error = String;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            4 => {
                let mut buf = [0u8; 4];
                buf.clone_from_slice(value);
                Ok(InetAddr::from(buf))
            }
            16 => {
                let mut buf = [0u8; 16];
                buf.clone_from_slice(value);
                Ok(InetAddr::from(buf))
            }
            #[cfg(feature = "tor")]
            32 => {
                let mut buf = [0u8; 32];
                buf.clone_from_slice(value);
                InetAddr::try_from(buf)
            }
            _ => Err(String::from(
                "Unsupported length of the byte string to read `InetAddr` from",
            )),
        }
    }
}

impl From<[u8; 4]> for InetAddr {
    #[inline]
    fn from(value: [u8; 4]) -> Self {
        InetAddr::from(Ipv4Addr::from(value))
    }
}

impl From<[u8; 16]> for InetAddr {
    #[inline]
    fn from(value: [u8; 16]) -> Self {
        InetAddr::from(Ipv6Addr::from(value))
    }
}

impl From<[u16; 8]> for InetAddr {
    #[inline]
    fn from(value: [u16; 8]) -> Self {
        InetAddr::from(Ipv6Addr::from(value))
    }
}

#[cfg(feature = "tor")]
impl TryFrom<[u8; InetAddr::UNIFORM_ADDR_LEN]> for InetAddr {
    type Error = String;
    #[inline]
    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Self::from_uniform_encoding(&value).ok_or(String::from("Wrong `InetAddr` binary encoding"))
    }
}

/// Transport protocols that may be part of `TransportAddr`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Transport {
    /// Normal TCP
    TCP = 1,

    /// Normal UDP
    UDP = 2,

    /// Multipath TCP version
    MTCP = 3,

    /// More efficient UDP version under developent by Google and consortium of
    /// other internet companies
    QUIC = 4,
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

impl Transport {
    #[inline]
    pub fn from_uniform_encoding(data: u8) -> Option<Self> {
        use Transport::*;
        Some(match data {
            a if a == TCP as u8 => TCP,
            a if a == UDP as u8 => UDP,
            a if a == MTCP as u8 => MTCP,
            a if a == QUIC as u8 => QUIC,
            _ => None?,
        })
    }

    #[inline]
    pub fn to_uniform_encoding(&self) -> u8 {
        *self as u8
    }
}

impl Default for Transport {
    #[inline]
    fn default() -> Self {
        Transport::TCP
    }
}

impl FromStr for Transport {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "tcp" => Transport::TCP,
            "udp" => Transport::UDP,
            "mtcp" => Transport::MTCP,
            "quic" => Transport::QUIC,
            _ => Err(String::from("Unknown transport"))?,
        })
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Transport::TCP => "tcp",
                Transport::UDP => "udp",
                Transport::MTCP => "mtcp",
                Transport::QUIC => "quic",
            }
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct InetSocketAddr {
    pub address: InetAddr,
    pub port: u16,
}

impl InetSocketAddr {
    #[inline]
    pub fn new(address: InetAddr, port: u16) -> Self {
        Self { address, port }
    }

    #[inline]
    pub fn is_tor(&self) -> bool {
        self.address.is_tor()
    }
}

impl InetSocketAddr {
    pub const UNIFORM_ADDR_LEN: usize = InetAddr::UNIFORM_ADDR_LEN + 2;

    #[inline]
    pub fn from_uniform_encoding(data: &[u8]) -> Option<Self> {
        if data.len() != Self::UNIFORM_ADDR_LEN {
            None?
        }

        Some(Self {
            address: {
                let mut buf = [0u8; InetAddr::UNIFORM_ADDR_LEN];
                buf.clone_from_slice(&data[..InetAddr::UNIFORM_ADDR_LEN]);
                InetAddr::from_uniform_encoding(&buf)?
            },
            port: {
                let mut buf = [0u8; 2];
                buf.clone_from_slice(&data[InetAddr::UNIFORM_ADDR_LEN..]);
                u16::from_be_bytes(buf)
            },
        })
    }

    #[inline]
    pub fn to_uniform_encoding(&self) -> [u8; Self::UNIFORM_ADDR_LEN] {
        let mut buf = [0u8; Self::UNIFORM_ADDR_LEN];
        buf[..InetAddr::UNIFORM_ADDR_LEN].copy_from_slice(&self.address.to_uniform_encoding());
        buf[InetAddr::UNIFORM_ADDR_LEN..].copy_from_slice(&self.port.to_be_bytes());
        buf
    }
}

impl fmt::Display for InetSocketAddr {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

impl FromStr for InetSocketAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut vals = s.split(':');
        let err_msg =
            String::from("Wrong format of socket address string; use <inet_address>[:<port>]");
        let em = |_| String::from(err_msg.clone());
        let emi = |_| String::from(err_msg.clone());
        match (vals.next(), vals.next(), vals.next()) {
            (Some(addr), Some(port), None) => Ok(Self {
                address: addr.parse().map_err(em)?,
                port: port.parse().map_err(emi)?,
            }),
            (Some(addr), None, _) => Ok(Self {
                address: addr.parse().map_err(em)?,
                port: 0,
            }),
            _ => Err(err_msg),
        }
    }
}

impl TryFrom<InetSocketAddr> for std::net::SocketAddr {
    type Error = String;
    #[inline]
    fn try_from(socket_addr: InetSocketAddr) -> Result<Self, Self::Error> {
        Ok(Self::new(
            IpAddr::try_from(socket_addr.address)?,
            socket_addr.port,
        ))
    }
}

impl From<std::net::SocketAddr> for InetSocketAddr {
    #[inline]
    fn from(addr: SocketAddr) -> Self {
        Self::new(addr.ip().into(), addr.port())
    }
}

pub struct InetSocketAddrExt(pub Transport, pub InetSocketAddr);

impl InetSocketAddrExt {
    pub const UNIFORM_ADDR_LEN: usize = InetSocketAddr::UNIFORM_ADDR_LEN + 1;

    #[inline]
    pub fn tcp(address: InetAddr, port: u16) -> Self {
        Self(Transport::TCP, InetSocketAddr::new(address, port))
    }

    #[inline]
    pub fn udp(address: InetAddr, port: u16) -> Self {
        Self(Transport::UDP, InetSocketAddr::new(address, port))
    }

    #[inline]
    pub fn from_uniform_encoding(data: &[u8]) -> Option<Self> {
        if data.len() != Self::UNIFORM_ADDR_LEN {
            None?
        }
        let mut buf = [0u8; InetSocketAddr::UNIFORM_ADDR_LEN];
        buf.copy_from_slice(&data[1..]);
        Some(Self(
            Transport::from_uniform_encoding(data[0])?,
            InetSocketAddr::from_uniform_encoding(&buf)?,
        ))
    }

    #[inline]
    pub fn to_uniform_encoding(&self) -> [u8; Self::UNIFORM_ADDR_LEN] {
        let mut buf = [0u8; Self::UNIFORM_ADDR_LEN];
        buf[..1].copy_from_slice(&[self.0.to_uniform_encoding()]);
        buf[1..].copy_from_slice(&self.1.to_uniform_encoding());
        buf
    }
}

impl fmt::Display for InetSocketAddrExt {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.0, self.1)
    }
}

impl FromStr for InetSocketAddrExt {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut vals = s.split("://");
        let err_msg = String::from("Wrong format of extended socket address string; use <transport>://<inet_address>[:<port>]");
        let em = |_| String::from(err_msg.clone());
        if let (Some(transport), Some(addr), None) = (vals.next(), vals.next(), vals.next()) {
            Ok(Self(
                transport.parse().map_err(em)?,
                addr.parse().map_err(em)?,
            ))
        } else {
            Err(err_msg)
        }
    }
}
