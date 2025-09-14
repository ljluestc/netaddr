//! MAC address (EUI-48) implementation

use crate::error::{AddrFormatError, AddrResult};
use crate::ip::IPAddress;
use std::fmt;
use std::str::FromStr;

/// MAC address (EUI-48) representation
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MAC {
    bytes: [u8; 6],
}

impl MAC {
    /// Create a new MAC address from 6 bytes
    pub fn new(bytes: [u8; 6]) -> Self {
        Self { bytes }
    }

    /// Create from individual octets
    pub fn from_octets(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self {
            bytes: [a, b, c, d, e, f],
        }
    }

    /// Create from bytes slice
    pub fn from_bytes(bytes: &[u8]) -> AddrResult<Self> {
        if bytes.len() != 6 {
            return Err(AddrFormatError::new(
                "MAC address must be exactly 6 bytes"
            ));
        }

        let mut mac_bytes = [0u8; 6];
        mac_bytes.copy_from_slice(bytes);
        Ok(Self::new(mac_bytes))
    }

    /// Get the bytes
    pub fn bytes(&self) -> &[u8; 6] {
        &self.bytes
    }

    /// Get the OUI (first 3 bytes)
    pub fn oui(&self) -> &[u8] {
        &self.bytes[0..3]
    }

    /// Get the NIC specific part (last 3 bytes)
    pub fn nic(&self) -> &[u8] {
        &self.bytes[3..6]
    }

    /// Get the organizational identifier as u32
    pub fn organizational_identifier(&self) -> u32 {
        ((self.bytes[0] as u32) << 16) | ((self.bytes[1] as u32) << 8) | (self.bytes[2] as u32)
    }

    /// Check if this is a unicast address (LSB of first octet is 0)
    pub fn is_unicast(&self) -> bool {
        (self.bytes[0] & 0x01) == 0
    }

    /// Check if this is a multicast address (LSB of first octet is 1)
    pub fn is_multicast(&self) -> bool {
        (self.bytes[0] & 0x01) != 0
    }

    /// Check if this is a broadcast address (all bits set)
    pub fn is_broadcast(&self) -> bool {
        self.bytes == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    }

    /// Check if this is a locally administered address (second LSB of first octet is 1)
    pub fn is_local(&self) -> bool {
        (self.bytes[0] & 0x02) != 0
    }

    /// Check if this is a universally administered address (second LSB of first octet is 0)
    pub fn is_universal(&self) -> bool {
        (self.bytes[0] & 0x02) == 0
    }

    /// Convert to EUI-64 format by inserting FFFE
    pub fn to_eui64(&self) -> AddrResult<super::eui64::EUI64> {
        let eui64_bytes = [
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            0xff,
            0xfe,
            self.bytes[3],
            self.bytes[4],
            self.bytes[5],
        ];
        super::eui64::EUI64::from_bytes(&eui64_bytes)
    }

    /// Generate a modified EUI-64 identifier for IPv6 address generation
    pub fn to_modified_eui64(&self) -> AddrResult<super::eui64::EUI64> {
        let mut eui64_bytes = [
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            0xff,
            0xfe,
            self.bytes[3],
            self.bytes[4],
            self.bytes[5],
        ];

        // Flip the Universal/Local bit (second LSB of first octet)
        eui64_bytes[0] ^= 0x02;

        super::eui64::EUI64::from_bytes(&eui64_bytes)
    }

    /// Convert to link-local IPv6 address (fe80::/64 + modified EUI-64)
    pub fn to_link_local_ipv6(&self) -> AddrResult<IPAddress> {
        let modified_eui64 = self.to_modified_eui64()?;
        let eui64_bytes = modified_eui64.bytes();

        // Create IPv6 address: fe80:: prefix + modified EUI-64
        let ipv6_bytes = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            eui64_bytes[0], eui64_bytes[1], eui64_bytes[2], eui64_bytes[3],
            eui64_bytes[4], eui64_bytes[5], eui64_bytes[6], eui64_bytes[7],
        ];

        let ipv6_addr = std::net::Ipv6Addr::from(ipv6_bytes);
        Ok(IPAddress::new_v6(ipv6_addr))
    }

    /// Format MAC address in different notations
    pub fn format(&self, format: MacFormat) -> String {
        match format {
            MacFormat::Colon => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2],
                self.bytes[3], self.bytes[4], self.bytes[5]
            ),
            MacFormat::Hyphen => format!(
                "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2],
                self.bytes[3], self.bytes[4], self.bytes[5]
            ),
            MacFormat::Cisco => format!(
                "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2],
                self.bytes[3], self.bytes[4], self.bytes[5]
            ),
            MacFormat::Bare => format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2],
                self.bytes[3], self.bytes[4], self.bytes[5]
            ),
            MacFormat::PostgreSQL => format!(
                "{{{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}}}",
                self.bytes[0], self.bytes[1], self.bytes[2],
                self.bytes[3], self.bytes[4], self.bytes[5]
            ),
            MacFormat::Unix => format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                self.bytes[0], self.bytes[1], self.bytes[2],
                self.bytes[3], self.bytes[4], self.bytes[5]
            ),
            MacFormat::UnixExpanded => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2],
                self.bytes[3], self.bytes[4], self.bytes[5]
            ),
        }
    }

    /// Parse MAC address from various string formats
    pub fn parse_flexible(s: &str) -> AddrResult<Self> {
        let clean = s.trim();

        // Remove common separators and convert to lowercase
        let normalized = clean
            .replace([':', '-', '.', ' '], "")
            .to_lowercase();

        // Remove curly braces if present (PostgreSQL format)
        let normalized = normalized.trim_matches(['{', '}']);

        if normalized.len() != 12 {
            return Err(AddrFormatError::new(format!(
                "Invalid MAC address length: {} (expected 12 hex characters)",
                normalized.len()
            )));
        }

        let mut bytes = [0u8; 6];
        for i in 0..6 {
            let start = i * 2;
            let end = start + 2;
            let hex_str = &normalized[start..end];
            bytes[i] = u8::from_str_radix(hex_str, 16)
                .map_err(|_| AddrFormatError::new(format!("Invalid hex characters: {}", hex_str)))?;
        }

        Ok(Self::new(bytes))
    }
}

impl FromStr for MAC {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        Self::parse_flexible(s)
    }
}

impl fmt::Display for MAC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format(MacFormat::Colon))
    }
}

impl From<[u8; 6]> for MAC {
    fn from(bytes: [u8; 6]) -> Self {
        Self::new(bytes)
    }
}

impl From<MAC> for [u8; 6] {
    fn from(mac: MAC) -> Self {
        mac.bytes
    }
}

/// MAC address formatting options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacFormat {
    /// Colon-separated format (00:11:22:33:44:55)
    Colon,
    /// Hyphen-separated format (00-11-22-33-44-55)
    Hyphen,
    /// Cisco format (0011.2233.4455)
    Cisco,
    /// Bare format with no separators (001122334455)
    Bare,
    /// PostgreSQL format ({00:11:22:33:44:55})
    PostgreSQL,
    /// Unix format (0:11:22:33:44:55) - no leading zeros
    Unix,
    /// Unix expanded format (00:11:22:33:44:55) - with leading zeros
    UnixExpanded,
}

/// Validation functions
pub fn valid_mac(s: &str) -> bool {
    MAC::from_str(s).is_ok()
}

pub fn mac_eui48(mac: &MAC) -> String {
    mac.format(MacFormat::Colon)
}

pub fn mac_unix(mac: &MAC) -> String {
    mac.format(MacFormat::Unix)
}

pub fn mac_unix_expanded(mac: &MAC) -> String {
    mac.format(MacFormat::UnixExpanded)
}

pub fn mac_cisco(mac: &MAC) -> String {
    mac.format(MacFormat::Cisco)
}

pub fn mac_bare(mac: &MAC) -> String {
    mac.format(MacFormat::Bare)
}

pub fn mac_pgsql(mac: &MAC) -> String {
    mac.format(MacFormat::PostgreSQL)
}

/// Common MAC address constants
impl MAC {
    /// Broadcast MAC address (ff:ff:ff:ff:ff:ff)
    pub const BROADCAST: MAC = MAC {
        bytes: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    };

    /// Null MAC address (00:00:00:00:00:00)
    pub const NULL: MAC = MAC {
        bytes: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    };

    /// Generate a random MAC address with specified OUI
    pub fn random_with_oui(oui: &[u8; 3]) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut hasher);
        let hash = hasher.finish();

        let mut bytes = [0u8; 6];
        bytes[0..3].copy_from_slice(oui);
        bytes[3] = (hash >> 16) as u8;
        bytes[4] = (hash >> 8) as u8;
        bytes[5] = hash as u8;

        // Ensure it's unicast and locally administered
        bytes[0] &= 0xfc; // Clear multicast and universal bits
        bytes[0] |= 0x02; // Set local bit

        Self::new(bytes)
    }

    /// Generate a random locally administered MAC address
    pub fn random_local() -> Self {
        let oui = [0x02, 0x00, 0x00]; // Locally administered OUI
        Self::random_with_oui(&oui)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_creation() {
        let mac = MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(mac.bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let mac2 = MAC::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        assert_eq!(mac, mac2);
    }

    #[test]
    fn test_mac_properties() {
        let unicast = MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(unicast.is_unicast());
        assert!(!unicast.is_multicast());
        assert!(unicast.is_universal());
        assert!(!unicast.is_local());

        let multicast = MAC::new([0x01, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!multicast.is_unicast());
        assert!(multicast.is_multicast());

        let local = MAC::new([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!local.is_universal());
        assert!(local.is_local());

        let broadcast = MAC::BROADCAST;
        assert!(broadcast.is_broadcast());
        assert!(broadcast.is_multicast());
    }

    #[test]
    fn test_mac_parsing() {
        let test_cases = vec![
            "00:11:22:33:44:55",
            "00-11-22-33-44-55",
            "0011.2233.4455",
            "001122334455",
            "{00:11:22:33:44:55}",
        ];

        for case in test_cases {
            let mac = MAC::from_str(case).unwrap();
            assert_eq!(mac.bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        }
    }

    #[test]
    fn test_mac_formatting() {
        let mac = MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        assert_eq!(mac.format(MacFormat::Colon), "00:11:22:33:44:55");
        assert_eq!(mac.format(MacFormat::Hyphen), "00-11-22-33-44-55");
        assert_eq!(mac.format(MacFormat::Cisco), "0011.2233.4455");
        assert_eq!(mac.format(MacFormat::Bare), "001122334455");
        assert_eq!(mac.format(MacFormat::PostgreSQL), "{00:11:22:33:44:55}");
        assert_eq!(mac.format(MacFormat::Unix), "0:11:22:33:44:55");
        assert_eq!(mac.format(MacFormat::UnixExpanded), "00:11:22:33:44:55");
    }

    #[test]
    fn test_oui_nic() {
        let mac = MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(mac.oui(), &[0x00, 0x11, 0x22]);
        assert_eq!(mac.nic(), &[0x33, 0x44, 0x55]);
        assert_eq!(mac.organizational_identifier(), 0x001122);
    }

    #[test]
    fn test_eui64_conversion() {
        let mac = MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let eui64 = mac.to_eui64().unwrap();
        assert_eq!(
            eui64.bytes(),
            &[0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]
        );

        let modified = mac.to_modified_eui64().unwrap();
        assert_eq!(
            modified.bytes(),
            &[0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]
        );
    }

    #[test]
    fn test_ipv6_conversion() {
        let mac = MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ipv6 = mac.to_link_local_ipv6().unwrap();
        // fe80::0211:22ff:fe33:4455
        assert_eq!(ipv6.to_string(), "fe80::211:22ff:fe33:4455");
    }

    #[test]
    fn test_validation_functions() {
        assert!(valid_mac("00:11:22:33:44:55"));
        assert!(!valid_mac("invalid"));

        let mac = MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(mac_eui48(&mac), "00:11:22:33:44:55");
        assert_eq!(mac_cisco(&mac), "0011.2233.4455");
        assert_eq!(mac_bare(&mac), "001122334455");
    }

    #[test]
    fn test_random_mac() {
        let mac1 = MAC::random_local();
        let mac2 = MAC::random_local();

        // Should be different
        assert_ne!(mac1, mac2);

        // Should be locally administered
        assert!(mac1.is_local());
        assert!(mac2.is_local());

        // Should be unicast
        assert!(mac1.is_unicast());
        assert!(mac2.is_unicast());
    }

    #[test]
    fn test_constants() {
        assert!(MAC::BROADCAST.is_broadcast());
        assert_eq!(MAC::NULL.bytes(), &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
}