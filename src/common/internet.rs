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
use torut::onion::{TorPublicKeyV3, OnionAddressV3};

#[derive(Clone, Copy, Debug, Display, PartialEq, Eq)]
#[display_from(Debug)]
pub enum AddressFormat {
    IPv4,
    IPv6,
    #[cfg(feature="use-tor")]
    Tor
}

/// A universal address covering IPv4, IPv6 and Tor in a single byte sequence
/// of 32 bytes.
///
/// NB: we are not including 2-byte checksum for Tor addresses, since it
/// is designed for human-readable part that checks that the address was typed
/// in correctly. In computer-stored digital data it may be deterministically
/// regenerated and does not add any additional security.
///
/// Holds either:
/// * IPv4-to-IPv6 address
/// * IPv6 address
/// * Tor address
///
/// Tor addresses are distinguished by the fact that last 16 bits
/// must be set to 0
#[derive(Clone, Copy)]
pub union AddressData {
    ipv4: [u8; 4],
    ipv6: [u16; 8],
    tor: [u8; 32],
}

impl Default for AddressData {
    fn default() -> Self {
        Self { tor: [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ] }
    }
}

impl fmt::Debug for AddressData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            if cfg!(feature="use-tor") {
                write!(f, "{:X?}", self.tor)
            } else {
                write!(f, "{:X?}", self.ipv6)
            }
        }
    }
}


// Instead of using `From<..>` we use explicit function names to avoid possible
// bugs with array length confusion for V4 and V6 addresses
impl AddressData {
    pub(self) fn from_ipv4(addr: [u8; 4]) -> Self {
        let mut me = Self::default();
        me.ipv4 = addr;
        me
    }

    pub(self) fn from_ipv6(addr: [u16; 8]) -> Self {
        let mut me = Self::default();
        me.ipv6 = addr;
        me
    }

    #[cfg(feature="use-tor")]
    pub(self) fn from_tor(addr: OnionAddressV3) -> Self {
        unimplemented!()
        /*
        let mut me = Self::default();
        me.ipv6 = addr.get_public_key().as_bytes();
        me
        */
    }
}


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


// TODO: Add `PartialEq`, `Eq` to `internet::Address` type
#[derive(Clone, Copy, Debug)]
pub struct Address {
    // Keeping the fields private since they maintain low-level raw data which
    // shouldn't be access from outside of the structure methods.
    format: AddressFormat,
    pub(self) data: AddressData,
}

impl Address {
    pub fn try_get_ip4(&self) -> Result<Ipv4Addr, ()> {
        if self.format != AddressFormat::IPv4 { return Err(()) }
        Ok(Ipv4Addr::from(unsafe { self.data.ipv4 }))
    }

    pub fn try_get_ip6(&self) -> Result<Ipv6Addr, ()> {
        if self.format != AddressFormat::IPv6 { return Err(()) }
        Ok(Ipv6Addr::from(unsafe { self.data.ipv6 }))
    }

    #[cfg(feature="use-tor")]
    pub fn try_get_tor(&self) -> Result<OnionAddressV3, ()> {
        unimplemented!()
        /*
        if self.format != AddressFormat::IPv4 { return Err(()) }
        Ok(OnionAddressV3::from(&TorPublicKeyV3(unsafe { self.data.tor })))
        */
    }

    #[cfg(feature="use-tor")]
    pub fn is_tor(&self) -> bool {
        return false;
    }

    #[cfg(not(feature="use-tor"))]
    pub fn is_tor(&self) -> bool {
        self.format == AddressFormat::Tor
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transport = format!("{}://", self.format);
        let formatted = match self.format {
            // TODO:
            AddressFormat::IPv4 => format!("{}", self.try_get_ip4().expect("Rust compiler failure")),
            AddressFormat::IPv6 => format!("{}", self.try_get_ip6().expect("Rust compiler failure")),
            #[cfg(feature="use-tor")]
            AddressFormat::Tor => format!("{}", self.try_get_tor().expect("Rust compiler failure")),
        };
        write!(f, "{}", formatted)
    }
}

#[cfg(feature="use-tor")]
impl TryFrom<Address> for IpAddr {
    type Error = ();
    #[inline]
    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        Ok(match addr.format {
            AddressFormat::IPv4 => IpAddr::V4(Ipv4Addr::from(unsafe { addr.data.ipv4 })),
            AddressFormat::IPv6 => IpAddr::V6(Ipv6Addr::from(unsafe { addr.data.ipv6 })),
            AddressFormat::Tor => Err(())?,
        })
    }
}

#[cfg(not(feature="use-tor"))]
impl From<Address> for IpAddr {
    #[inline]
    fn from(addr: Address) -> Self {
        match addr.format {
            AddressFormat::IPv4 => IpAddr::V4(Ipv4Addr::from(unsafe { addr.data.ipv4 })),
            AddressFormat::IPv6 => IpAddr::V6(Ipv6Addr::from(unsafe { addr.data.ipv6 })),
        }
    }
}

impl From<IpAddr> for Address {
    #[inline]
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(v4) => Address::from(v4),
            IpAddr::V6(v6) => Address::from(v6),
        }
    }
}

impl From<Ipv4Addr> for Address {
    fn from(addr: Ipv4Addr) -> Self {
        Self {
            format: AddressFormat::IPv4,
            data: AddressData::from_ipv4(addr.octets())
        }
    }
}

impl From<Ipv6Addr> for Address {
    fn from(addr: Ipv6Addr) -> Self {
        Self {
            format: AddressFormat::IPv6,
            data: AddressData::from_ipv6(addr.segments())
        }
    }
}

#[cfg(feature="use-tor")]
impl From<OnionAddressV3> for Address {
    fn from(addr: OnionAddressV3) -> Self {
        Self {
            format: AddressFormat::Tor,
            data: AddressData::from_tor(addr)
        }
    }
}

impl TryFrom<String> for Address {
    type Error = ();
    fn try_from(value: String) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl TryFrom<&str> for Address {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl TryFrom<Vec<u8>> for Address {
    type Error = ();
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Address::try_from(&value[..])
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = ();
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl From<[u8; 4]> for Address {
    fn from(value: [u8; 4]) -> Self {
        Address::from(Ipv4Addr::from(value))
    }
}

impl From<[u16; 8]> for Address {
    fn from(value: [u16; 8]) -> Self {
        Address::from(Ipv6Addr::from(value))
    }
}

#[cfg(feature="use-tor")]
impl From<TorPublicKeyV3> for Address {
    fn from(value: TorPublicKeyV3) -> Self {
        unimplemented!()
        /*
        Self {
            format: AddressFormat::Tor,
            data: AddressData { tor: value.as_bytes() }
        }
        */
    }
}

#[cfg(feature="use-tor")]
impl TryFrom<[u8; 32]> for Address {
    type Error = ();
    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}


// TODO: Implement `PartialEq` and `Eq` for `internet::Socket` when
//       `internet::Address` will support them
#[derive(Clone, Copy, Debug, Display)]
#[display_from(Debug)]
pub struct SocketAddress {
    pub transport: Transport,
    pub address: Address,
    pub port: u16,
}

#[cfg(feature="use-tor")]
impl TryFrom<SocketAddress> for std::net::SocketAddr {
    type Error = ();
    fn try_from(socket_addr: SocketAddress) -> Result<Self, Self::Error> {
        Ok(Self::new(IpAddr::try_from(socket_addr.address)?, socket_addr.port))
    }
}

#[cfg(not(feature="use-tor"))]
impl From<SocketAddress> for std::net::SocketAddr {
    fn from(socket_addr: SocketAddress) -> Self {
        Self::new(IpAddr::from(socket_addr.address), socket_addr.port)
    }
}

