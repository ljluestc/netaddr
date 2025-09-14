//! IPv6 specific functionality

use crate::error::{AddrFormatError, AddrResult};
use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

/// IPv6 address with extended functionality
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IPv6 {
    addr: Ipv6Addr,
}

impl IPv6 {
    /// Create a new IPv6 address from segments
    pub fn new(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Self {
        Self {
            addr: Ipv6Addr::new(a, b, c, d, e, f, g, h),
        }
    }

    /// Create from a u128 representation
    pub fn from_u128(addr: u128) -> Self {
        Self {
            addr: Ipv6Addr::from(addr),
        }
    }

    /// Get the segments
    pub fn segments(&self) -> [u16; 8] {
        self.addr.segments()
    }

    /// Convert to u128
    pub fn to_u128(&self) -> u128 {
        u128::from(self.addr)
    }

    /// Get the underlying Ipv6Addr
    pub fn as_ipv6_addr(&self) -> &Ipv6Addr {
        &self.addr
    }

    /// Get the octets
    pub fn octets(&self) -> [u8; 16] {
        self.addr.octets()
    }

    /// Check if this is a unique local address (fc00::/7)
    pub fn is_unique_local(&self) -> bool {
        let segments = self.segments();
        (segments[0] & 0xfe00) == 0xfc00
    }

    /// Check if this is a global unicast address
    pub fn is_global_unicast(&self) -> bool {
        let segments = self.segments();
        let first_segment = segments[0];

        // Not loopback, not multicast, not link-local, not unique local
        !self.addr.is_loopback()
            && !self.addr.is_multicast()
            && (first_segment & 0xffc0) != 0xfe80  // not link-local
            && (first_segment & 0xfe00) != 0xfc00  // not unique local
            && first_segment != 0                   // not unspecified
    }

    /// Check if this is a documentation address (2001:db8::/32)
    pub fn is_documentation(&self) -> bool {
        let segments = self.segments();
        segments[0] == 0x2001 && segments[1] == 0x0db8
    }

    /// Check if this is a benchmarking address (2001:2::/48)
    pub fn is_benchmarking(&self) -> bool {
        let segments = self.segments();
        segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0x0000
    }

    /// Format in compact form (with :: compression)
    pub fn compact(&self) -> String {
        self.addr.to_string()
    }

    /// Format in full form (no compression)
    pub fn full(&self) -> String {
        let segments = self.segments();
        format!(
            "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
            segments[0], segments[1], segments[2], segments[3],
            segments[4], segments[5], segments[6], segments[7]
        )
    }

    /// Format in verbose form (with leading zeros)
    pub fn verbose(&self) -> String {
        self.full()
    }

    /// Convert to IPv4 if this is an IPv4-mapped address
    pub fn to_ipv4(&self) -> Option<crate::ip::ipv4::IPv4> {
        self.addr.to_ipv4().map(|ipv4| crate::ip::ipv4::IPv4::from(ipv4))
    }

    /// Check if this is an IPv4-mapped address (::ffff:0:0/96)
    pub fn is_ipv4_mapped(&self) -> bool {
        let segments = self.segments();
        segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff
    }

    /// Check if this is an IPv4-compatible address (deprecated)
    pub fn is_ipv4_compatible(&self) -> bool {
        let segments = self.segments();
        segments[0..6] == [0, 0, 0, 0, 0, 0] && segments[6] != 0 && segments[7] != 0
    }

    /// Check if this is a 6to4 address (2002::/16)
    pub fn is_6to4(&self) -> bool {
        let segments = self.segments();
        segments[0] == 0x2002
    }

    /// Check if this is a Teredo address (2001::/32)
    pub fn is_teredo(&self) -> bool {
        let segments = self.segments();
        segments[0] == 0x2001 && segments[1] == 0x0000
    }

    /// Get the interface identifier (last 64 bits)
    pub fn interface_id(&self) -> u64 {
        let segments = self.segments();
        ((segments[4] as u64) << 48)
            | ((segments[5] as u64) << 32)
            | ((segments[6] as u64) << 16)
            | (segments[7] as u64)
    }

    /// Get the network prefix (first 64 bits)
    pub fn network_prefix(&self) -> u64 {
        let segments = self.segments();
        ((segments[0] as u64) << 48)
            | ((segments[1] as u64) << 32)
            | ((segments[2] as u64) << 16)
            | (segments[3] as u64)
    }

    /// Create from network prefix and interface ID
    pub fn from_parts(network_prefix: u64, interface_id: u64) -> Self {
        let a = (network_prefix >> 48) as u16;
        let b = (network_prefix >> 32) as u16;
        let c = (network_prefix >> 16) as u16;
        let d = network_prefix as u16;
        let e = (interface_id >> 48) as u16;
        let f = (interface_id >> 32) as u16;
        let g = (interface_id >> 16) as u16;
        let h = interface_id as u16;

        Self::new(a, b, c, d, e, f, g, h)
    }

    /// Check if this address is in the given network
    pub fn is_in_network(&self, network: &IPv6, prefix_len: u8) -> bool {
        if prefix_len > 128 {
            return false;
        }

        if prefix_len == 0 {
            return true;
        }

        let self_u128 = self.to_u128();
        let network_u128 = network.to_u128();

        // Create mask
        let shift = 128 - prefix_len;
        let mask = if shift >= 128 { 0 } else { !((1u128 << shift) - 1) };

        (self_u128 & mask) == (network_u128 & mask)
    }

    /// Generate the network address given a prefix length
    pub fn network_address(&self, prefix_len: u8) -> Self {
        if prefix_len >= 128 {
            return *self;
        }

        let shift = 128 - prefix_len;
        let mask = if shift >= 128 { 0 } else { !((1u128 << shift) - 1) };
        let network_u128 = self.to_u128() & mask;

        Self::from_u128(network_u128)
    }

    /// Check if this is a solicited-node multicast address
    pub fn is_solicited_node_multicast(&self) -> bool {
        let segments = self.segments();
        segments[0] == 0xff02
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 1
            && (segments[6] & 0xff00) == 0xff00
    }
}

impl FromStr for IPv6 {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        Ipv6Addr::from_str(s)
            .map(|addr| IPv6 { addr })
            .map_err(|e| AddrFormatError::new(format!("Invalid IPv6 address '{}': {}", s, e)))
    }
}

impl fmt::Display for IPv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl From<Ipv6Addr> for IPv6 {
    fn from(addr: Ipv6Addr) -> Self {
        Self { addr }
    }
}

impl From<IPv6> for Ipv6Addr {
    fn from(ipv6: IPv6) -> Self {
        ipv6.addr
    }
}

impl From<[u16; 8]> for IPv6 {
    fn from(segments: [u16; 8]) -> Self {
        Self {
            addr: Ipv6Addr::new(
                segments[0], segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7],
            ),
        }
    }
}

impl From<u128> for IPv6 {
    fn from(addr: u128) -> Self {
        Self::from_u128(addr)
    }
}

/// RFC 1924 Base85 encoding for IPv6 addresses
pub struct Base85;

impl Base85 {
    const CHARSET: &'static [u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

    /// Convert IPv6 address to Base85 representation
    pub fn encode(addr: &IPv6) -> String {
        let mut num = addr.to_u128();
        let mut result = Vec::new();

        if num == 0 {
            return "0".to_string();
        }

        while num > 0 {
            let remainder = (num % 85) as usize;
            result.push(Self::CHARSET[remainder] as char);
            num /= 85;
        }

        result.reverse();
        result.into_iter().collect()
    }

    /// Convert Base85 representation to IPv6 address
    pub fn decode(s: &str) -> AddrResult<IPv6> {
        if s.is_empty() {
            return Err(AddrFormatError::new("Empty Base85 string"));
        }

        let mut num = 0u128;

        for ch in s.chars() {
            let byte = ch as u8;
            let pos = Self::CHARSET.iter().position(|&x| x == byte)
                .ok_or_else(|| AddrFormatError::new(format!("Invalid Base85 character: {}", ch)))?;

            num = num.checked_mul(85)
                .and_then(|n| n.checked_add(pos as u128))
                .ok_or_else(|| AddrFormatError::new("Base85 number too large for IPv6"))?;
        }

        Ok(IPv6::from_u128(num))
    }
}

/// Subnet mask utilities for IPv6
pub struct IPv6SubnetMask;

impl IPv6SubnetMask {
    /// Create a subnet mask from prefix length
    pub fn from_prefix_length(prefix_len: u8) -> AddrResult<IPv6> {
        if prefix_len > 128 {
            return Err(AddrFormatError::new("Invalid prefix length for IPv6"));
        }

        if prefix_len == 0 {
            return Ok(IPv6::from_u128(0));
        }

        let shift = 128 - prefix_len;
        let mask = if shift >= 128 { 0 } else { !((1u128 << shift) - 1) };
        Ok(IPv6::from_u128(mask))
    }

    /// Get the prefix length from a subnet mask
    pub fn to_prefix_length(mask: &IPv6) -> u8 {
        let mask_u128 = mask.to_u128();
        mask_u128.count_ones() as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_creation() {
        let addr = IPv6::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        assert_eq!(addr.segments(), [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_u128_conversion() {
        let addr = IPv6::from_str("2001:db8::1").unwrap();
        let u128_addr = addr.to_u128();
        let back = IPv6::from_u128(u128_addr);
        assert_eq!(addr, back);
    }

    #[test]
    fn test_formatting() {
        let addr = IPv6::from_str("2001:db8::1").unwrap();
        assert_eq!(addr.compact(), "2001:db8::1");
        assert_eq!(addr.full(), "2001:0db8:0000:0000:0000:0000:0000:0001");
    }

    #[test]
    fn test_address_types() {
        let loopback = IPv6::from_str("::1").unwrap();
        assert!(loopback.as_ipv6_addr().is_loopback());

        let multicast = IPv6::from_str("ff02::1").unwrap();
        assert!(multicast.as_ipv6_addr().is_multicast());

        let unique_local = IPv6::from_str("fc00::1").unwrap();
        assert!(unique_local.is_unique_local());

        let doc = IPv6::from_str("2001:db8::1").unwrap();
        assert!(doc.is_documentation());
    }

    #[test]
    fn test_network_operations() {
        let addr = IPv6::from_str("2001:db8:1234:5678::1").unwrap();
        let network = addr.network_address(64);
        assert_eq!(network, IPv6::from_str("2001:db8:1234:5678::").unwrap());

        assert!(addr.is_in_network(&network, 64));
        assert!(!addr.is_in_network(&network, 128));
    }

    #[test]
    fn test_interface_parts() {
        let addr = IPv6::from_str("2001:db8:1234:5678:abcd:ef01:2345:6789").unwrap();
        let network_prefix = addr.network_prefix();
        let interface_id = addr.interface_id();

        let reconstructed = IPv6::from_parts(network_prefix, interface_id);
        assert_eq!(addr, reconstructed);
    }

    #[test]
    fn test_base85_encoding() {
        let addr = IPv6::from_str("2001:db8::1").unwrap();
        let encoded = Base85::encode(&addr);
        let decoded = Base85::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_subnet_mask_utils() {
        let mask = IPv6SubnetMask::from_prefix_length(64).unwrap();
        let prefix_len = IPv6SubnetMask::to_prefix_length(&mask);
        assert_eq!(prefix_len, 64);
    }

    #[test]
    fn test_ipv4_mapping() {
        let mapped = IPv6::from_str("::ffff:192.168.1.1").unwrap();
        assert!(mapped.is_ipv4_mapped());

        let ipv4 = mapped.to_ipv4().unwrap();
        assert_eq!(ipv4.to_string(), "192.168.1.1");
    }
}