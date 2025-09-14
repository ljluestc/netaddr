//! IP Address implementation

use crate::error::{AddrFormatError, AddrResult};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// IP address types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPAddressType {
    IPv4,
    IPv6,
}

/// Represents either an IPv4 or IPv6 address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IPAddress {
    addr: IpAddr,
}

impl IPAddress {
    /// Create a new IP address from an IpAddr
    pub fn new(addr: IpAddr) -> Self {
        Self { addr }
    }

    /// Create a new IPv4 address
    pub fn new_v4(addr: Ipv4Addr) -> Self {
        Self {
            addr: IpAddr::V4(addr),
        }
    }

    /// Create a new IPv6 address
    pub fn new_v6(addr: Ipv6Addr) -> Self {
        Self {
            addr: IpAddr::V6(addr),
        }
    }

    /// Get the IP address type
    pub fn ip_type(&self) -> IPAddressType {
        match self.addr {
            IpAddr::V4(_) => IPAddressType::IPv4,
            IpAddr::V6(_) => IPAddressType::IPv6,
        }
    }

    /// Get the version number (4 or 6)
    pub fn version(&self) -> u8 {
        match self.addr {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        }
    }

    /// Check if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self.addr, IpAddr::V4(_))
    }

    /// Check if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self.addr, IpAddr::V6(_))
    }

    /// Get the underlying IpAddr
    pub fn as_ip_addr(&self) -> &IpAddr {
        &self.addr
    }

    /// Get the IPv4 address if this is IPv4
    pub fn as_ipv4(&self) -> Option<&Ipv4Addr> {
        match &self.addr {
            IpAddr::V4(addr) => Some(addr),
            IpAddr::V6(_) => None,
        }
    }

    /// Get the IPv6 address if this is IPv6
    pub fn as_ipv6(&self) -> Option<&Ipv6Addr> {
        match &self.addr {
            IpAddr::V4(_) => None,
            IpAddr::V6(addr) => Some(addr),
        }
    }

    /// Check if the address is a loopback address
    pub fn is_loopback(&self) -> bool {
        match self.addr {
            IpAddr::V4(addr) => addr.is_loopback(),
            IpAddr::V6(addr) => addr.is_loopback(),
        }
    }

    /// Check if the address is a private address
    pub fn is_private(&self) -> bool {
        match self.addr {
            IpAddr::V4(addr) => addr.is_private(),
            IpAddr::V6(addr) => {
                // IPv6 private addresses (unique local addresses)
                let segments = addr.segments();
                (segments[0] & 0xfe00) == 0xfc00
            }
        }
    }

    /// Check if the address is a multicast address
    pub fn is_multicast(&self) -> bool {
        match self.addr {
            IpAddr::V4(addr) => addr.is_multicast(),
            IpAddr::V6(addr) => addr.is_multicast(),
        }
    }

    /// Check if the address is a link-local address
    pub fn is_link_local(&self) -> bool {
        match self.addr {
            IpAddr::V4(addr) => addr.is_link_local(),
            IpAddr::V6(_) => false, // IPv6 link-local checking would need more complex logic
        }
    }

    /// Check if the address is unspecified (0.0.0.0 or ::)
    pub fn is_unspecified(&self) -> bool {
        match self.addr {
            IpAddr::V4(addr) => addr.is_unspecified(),
            IpAddr::V6(addr) => addr.is_unspecified(),
        }
    }

    /// Convert to binary representation
    pub fn to_binary(&self) -> Vec<u8> {
        match self.addr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        }
    }

    /// Convert to hexadecimal representation
    pub fn to_hex(&self) -> String {
        match self.addr {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                format!("{:02x}{:02x}{:02x}{:02x}", octets[0], octets[1], octets[2], octets[3])
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                octets.iter().map(|b| format!("{:02x}", b)).collect::<String>()
            }
        }
    }

    /// Get the reverse DNS pointer name
    pub fn reverse_dns(&self) -> String {
        match self.addr {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0])
            }
            IpAddr::V6(addr) => {
                let hex_str = self.to_hex();
                let reversed: String = hex_str
                    .chars()
                    .rev()
                    .enumerate()
                    .map(|(i, c)| if i > 0 && i % 1 == 0 { format!(".{}", c) } else { c.to_string() })
                    .collect();
                format!("{}.ip6.arpa", reversed)
            }
        }
    }

    /// Get the next IP address in sequence
    pub fn next(&self) -> Option<IPAddress> {
        match self.addr {
            IpAddr::V4(addr) => {
                let int_addr = u32::from(addr);
                if int_addr == u32::MAX {
                    None
                } else {
                    Some(IPAddress::new_v4(Ipv4Addr::from(int_addr + 1)))
                }
            }
            IpAddr::V6(addr) => {
                let int_addr = u128::from(addr);
                if int_addr == u128::MAX {
                    None
                } else {
                    Some(IPAddress::new_v6(Ipv6Addr::from(int_addr + 1)))
                }
            }
        }
    }

    /// Get the previous IP address in sequence
    pub fn prev(&self) -> Option<IPAddress> {
        match self.addr {
            IpAddr::V4(addr) => {
                let int_addr = u32::from(addr);
                if int_addr == 0 {
                    None
                } else {
                    Some(IPAddress::new_v4(Ipv4Addr::from(int_addr - 1)))
                }
            }
            IpAddr::V6(addr) => {
                let int_addr = u128::from(addr);
                if int_addr == 0 {
                    None
                } else {
                    Some(IPAddress::new_v6(Ipv6Addr::from(int_addr - 1)))
                }
            }
        }
    }
}

impl FromStr for IPAddress {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        IpAddr::from_str(s)
            .map(IPAddress::new)
            .map_err(|e| AddrFormatError::new(format!("Invalid IP address '{}': {}", s, e)))
    }
}

impl fmt::Display for IPAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl From<IpAddr> for IPAddress {
    fn from(addr: IpAddr) -> Self {
        IPAddress::new(addr)
    }
}

impl From<Ipv4Addr> for IPAddress {
    fn from(addr: Ipv4Addr) -> Self {
        IPAddress::new_v4(addr)
    }
}

impl From<Ipv6Addr> for IPAddress {
    fn from(addr: Ipv6Addr) -> Self {
        IPAddress::new_v6(addr)
    }
}

impl From<IPAddress> for IpAddr {
    fn from(addr: IPAddress) -> Self {
        addr.addr
    }
}

impl PartialOrd for IPAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IPAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare version first
        match (self.version(), other.version()) {
            (4, 6) => std::cmp::Ordering::Less,
            (6, 4) => std::cmp::Ordering::Greater,
            _ => {
                // Same version, compare addresses
                match (self.addr, other.addr) {
                    (IpAddr::V4(a), IpAddr::V4(b)) => u32::from(a).cmp(&u32::from(b)),
                    (IpAddr::V6(a), IpAddr::V6(b)) => u128::from(a).cmp(&u128::from(b)),
                    _ => unreachable!(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_creation() {
        let addr = IPAddress::from_str("192.168.1.1").unwrap();
        assert!(addr.is_ipv4());
        assert_eq!(addr.version(), 4);
        assert_eq!(addr.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_ipv6_creation() {
        let addr = IPAddress::from_str("2001:db8::1").unwrap();
        assert!(addr.is_ipv6());
        assert_eq!(addr.version(), 6);
    }

    #[test]
    fn test_properties() {
        let loopback = IPAddress::from_str("127.0.0.1").unwrap();
        assert!(loopback.is_loopback());

        let private = IPAddress::from_str("192.168.1.1").unwrap();
        assert!(private.is_private());

        let multicast = IPAddress::from_str("224.0.0.1").unwrap();
        assert!(multicast.is_multicast());
    }

    #[test]
    fn test_next_prev() {
        let addr = IPAddress::from_str("192.168.1.1").unwrap();
        let next = addr.next().unwrap();
        assert_eq!(next.to_string(), "192.168.1.2");

        let prev = next.prev().unwrap();
        assert_eq!(prev.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_reverse_dns() {
        let addr = IPAddress::from_str("192.168.1.1").unwrap();
        assert_eq!(addr.reverse_dns(), "1.1.168.192.in-addr.arpa");
    }

    #[test]
    fn test_ordering() {
        let addr1 = IPAddress::from_str("192.168.1.1").unwrap();
        let addr2 = IPAddress::from_str("192.168.1.2").unwrap();
        let addr6 = IPAddress::from_str("2001:db8::1").unwrap();

        assert!(addr1 < addr2);
        assert!(addr1 < addr6); // IPv4 < IPv6
    }

    #[test]
    fn test_binary_hex() {
        let addr = IPAddress::from_str("192.168.1.1").unwrap();
        assert_eq!(addr.to_binary(), vec![192, 168, 1, 1]);
        assert_eq!(addr.to_hex(), "c0a80101");
    }
}