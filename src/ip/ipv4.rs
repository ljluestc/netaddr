//! IPv4 specific functionality

use crate::error::{AddrFormatError, AddrResult};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// IPv4 address with extended functionality
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IPv4 {
    addr: Ipv4Addr,
}

impl IPv4 {
    /// Create a new IPv4 address from octets
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self {
            addr: Ipv4Addr::new(a, b, c, d),
        }
    }

    /// Create from a u32 representation
    pub fn from_u32(addr: u32) -> Self {
        Self {
            addr: Ipv4Addr::from(addr),
        }
    }

    /// Get the octets
    pub fn octets(&self) -> [u8; 4] {
        self.addr.octets()
    }

    /// Convert to u32
    pub fn to_u32(&self) -> u32 {
        u32::from(self.addr)
    }

    /// Get the underlying Ipv4Addr
    pub fn as_ipv4_addr(&self) -> &Ipv4Addr {
        &self.addr
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        self.addr.is_broadcast()
    }

    /// Check if this is a documentation address (TEST-NET)
    pub fn is_documentation(&self) -> bool {
        self.addr.is_documentation()
    }

    /// Check if this is a benchmarking address
    pub fn is_benchmarking(&self) -> bool {
        // IPv4 benchmarking addresses: 198.18.0.0/15 (RFC 2544)
        let octets = self.octets();
        octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
    }

    /// Check if this is an IANA reserved address
    pub fn is_reserved(&self) -> bool {
        // Check for various reserved ranges
        let octets = self.octets();

        // 0.0.0.0/8 - "This" Network
        if octets[0] == 0 {
            return true;
        }

        // 240.0.0.0/4 - Reserved for future use
        if octets[0] >= 240 {
            return true;
        }

        false
    }

    /// Check if this is a Class A address (1.0.0.0 to 126.255.255.255)
    pub fn is_class_a(&self) -> bool {
        let octets = self.octets();
        octets[0] >= 1 && octets[0] <= 126
    }

    /// Check if this is a Class B address (128.0.0.0 to 191.255.255.255)
    pub fn is_class_b(&self) -> bool {
        let octets = self.octets();
        octets[0] >= 128 && octets[0] <= 191
    }

    /// Check if this is a Class C address (192.0.0.0 to 223.255.255.255)
    pub fn is_class_c(&self) -> bool {
        let octets = self.octets();
        octets[0] >= 192 && octets[0] <= 223
    }

    /// Check if this is a Class D address (224.0.0.0 to 239.255.255.255) - Multicast
    pub fn is_class_d(&self) -> bool {
        let octets = self.octets();
        octets[0] >= 224 && octets[0] <= 239
    }

    /// Check if this is a Class E address (240.0.0.0 to 255.255.255.255) - Reserved
    pub fn is_class_e(&self) -> bool {
        let octets = self.octets();
        octets[0] >= 240
    }

    /// Get the default subnet mask for classful addressing
    pub fn default_mask(&self) -> Option<IPv4> {
        let octets = self.octets();
        match octets[0] {
            1..=126 => Some(IPv4::new(255, 0, 0, 0)),      // Class A
            128..=191 => Some(IPv4::new(255, 255, 0, 0)),   // Class B
            192..=223 => Some(IPv4::new(255, 255, 255, 0)), // Class C
            _ => None, // Class D and E don't have default masks
        }
    }

    /// Check if this address is in the given network
    pub fn is_in_network(&self, network: &IPv4, mask: &IPv4) -> bool {
        let addr_masked = self.to_u32() & mask.to_u32();
        let net_masked = network.to_u32() & mask.to_u32();
        addr_masked == net_masked
    }

    /// Generate the network address given a subnet mask
    pub fn network_address(&self, mask: &IPv4) -> IPv4 {
        IPv4::from_u32(self.to_u32() & mask.to_u32())
    }

    /// Generate the broadcast address given a subnet mask
    pub fn broadcast_address(&self, mask: &IPv4) -> IPv4 {
        let inverted_mask = !mask.to_u32();
        IPv4::from_u32(self.to_u32() | inverted_mask)
    }

    /// Parse with zero-fill handling for inet_aton compatibility
    pub fn parse_with_zerofill(s: &str) -> AddrResult<Self> {
        // Handle zero-filled octets like "010.020.030.040"
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err(AddrFormatError::new("IPv4 address must have 4 octets"));
        }

        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return Err(AddrFormatError::new("Empty octet in IPv4 address"));
            }

            // Remove leading zeros for proper parsing
            let clean_part = part.trim_start_matches('0');
            let clean_part = if clean_part.is_empty() { "0" } else { clean_part };

            octets[i] = clean_part.parse::<u8>()
                .map_err(|_| AddrFormatError::new(format!("Invalid octet: {}", part)))?;
        }

        Ok(IPv4::new(octets[0], octets[1], octets[2], octets[3]))
    }

    /// Expand partial IPv4 addresses (e.g., "192.168.1" -> "192.168.1.0")
    pub fn expand_partial(s: &str) -> AddrResult<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.is_empty() || parts.len() > 4 {
            return Err(AddrFormatError::new("Invalid IPv4 address format"));
        }

        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            octets[i] = part.parse::<u8>()
                .map_err(|_| AddrFormatError::new(format!("Invalid octet: {}", part)))?;
        }

        Ok(IPv4::new(octets[0], octets[1], octets[2], octets[3]))
    }
}

impl FromStr for IPv4 {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        Ipv4Addr::from_str(s)
            .map(|addr| IPv4 { addr })
            .map_err(|e| AddrFormatError::new(format!("Invalid IPv4 address '{}': {}", s, e)))
    }
}

impl fmt::Display for IPv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl From<Ipv4Addr> for IPv4 {
    fn from(addr: Ipv4Addr) -> Self {
        Self { addr }
    }
}

impl From<IPv4> for Ipv4Addr {
    fn from(ipv4: IPv4) -> Self {
        ipv4.addr
    }
}

impl From<[u8; 4]> for IPv4 {
    fn from(octets: [u8; 4]) -> Self {
        Self {
            addr: Ipv4Addr::from(octets),
        }
    }
}

impl From<u32> for IPv4 {
    fn from(addr: u32) -> Self {
        Self::from_u32(addr)
    }
}

/// Subnet mask utilities
pub struct SubnetMask;

impl SubnetMask {
    /// Create a subnet mask from prefix length (CIDR notation)
    pub fn from_prefix_length(prefix_len: u8) -> AddrResult<IPv4> {
        if prefix_len > 32 {
            return Err(AddrFormatError::new("Invalid prefix length for IPv4"));
        }

        if prefix_len == 0 {
            return Ok(IPv4::from_u32(0));
        }

        let mask = (!0u32) << (32 - prefix_len);
        Ok(IPv4::from_u32(mask))
    }

    /// Get the prefix length from a subnet mask
    pub fn to_prefix_length(mask: &IPv4) -> u8 {
        let mask_u32 = mask.to_u32();
        mask_u32.count_ones() as u8
    }

    /// Check if a mask is valid (contiguous 1s followed by contiguous 0s)
    pub fn is_valid_mask(mask: &IPv4) -> bool {
        let mask_u32 = mask.to_u32();
        let inverted = !mask_u32;

        // Check if inverted mask + 1 is a power of 2 (or 0)
        inverted == 0 || (inverted & (inverted + 1)) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_creation() {
        let addr = IPv4::new(192, 168, 1, 1);
        assert_eq!(addr.octets(), [192, 168, 1, 1]);
        assert_eq!(addr.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_u32_conversion() {
        let addr = IPv4::new(192, 168, 1, 1);
        let u32_addr = addr.to_u32();
        let back = IPv4::from_u32(u32_addr);
        assert_eq!(addr, back);
    }

    #[test]
    fn test_class_detection() {
        assert!(IPv4::new(10, 0, 0, 1).is_class_a());
        assert!(IPv4::new(172, 16, 0, 1).is_class_b());
        assert!(IPv4::new(192, 168, 1, 1).is_class_c());
        assert!(IPv4::new(224, 0, 0, 1).is_class_d());
        assert!(IPv4::new(240, 0, 0, 1).is_class_e());
    }

    #[test]
    fn test_default_masks() {
        assert_eq!(IPv4::new(10, 0, 0, 1).default_mask().unwrap(), IPv4::new(255, 0, 0, 0));
        assert_eq!(IPv4::new(172, 16, 0, 1).default_mask().unwrap(), IPv4::new(255, 255, 0, 0));
        assert_eq!(IPv4::new(192, 168, 1, 1).default_mask().unwrap(), IPv4::new(255, 255, 255, 0));
    }

    #[test]
    fn test_subnet_operations() {
        let addr = IPv4::new(192, 168, 1, 100);
        let mask = IPv4::new(255, 255, 255, 0);

        let network = addr.network_address(&mask);
        assert_eq!(network, IPv4::new(192, 168, 1, 0));

        let broadcast = addr.broadcast_address(&mask);
        assert_eq!(broadcast, IPv4::new(192, 168, 1, 255));

        assert!(addr.is_in_network(&network, &mask));
    }

    #[test]
    fn test_subnet_mask_utils() {
        let mask = SubnetMask::from_prefix_length(24).unwrap();
        assert_eq!(mask, IPv4::new(255, 255, 255, 0));

        let prefix_len = SubnetMask::to_prefix_length(&mask);
        assert_eq!(prefix_len, 24);

        assert!(SubnetMask::is_valid_mask(&mask));
        assert!(!SubnetMask::is_valid_mask(&IPv4::new(255, 255, 254, 1))); // Invalid mask
    }

    #[test]
    fn test_partial_expansion() {
        let addr = IPv4::expand_partial("192.168.1").unwrap();
        assert_eq!(addr, IPv4::new(192, 168, 1, 0));

        let addr = IPv4::expand_partial("10").unwrap();
        assert_eq!(addr, IPv4::new(10, 0, 0, 0));
    }

    #[test]
    fn test_zerofill_parsing() {
        let addr = IPv4::parse_with_zerofill("010.020.030.040").unwrap();
        assert_eq!(addr, IPv4::new(10, 20, 30, 40));
    }
}