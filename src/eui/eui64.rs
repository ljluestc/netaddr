//! EUI-64 identifier implementation

use crate::error::{AddrFormatError, AddrResult};
use crate::ip::IPAddress;
use std::fmt;
use std::str::FromStr;

/// EUI-64 identifier representation
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EUI64 {
    bytes: [u8; 8],
}

impl EUI64 {
    /// Create a new EUI-64 from 8 bytes
    pub fn new(bytes: [u8; 8]) -> Self {
        Self { bytes }
    }

    /// Create from individual octets
    pub fn from_octets(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8) -> Self {
        Self {
            bytes: [a, b, c, d, e, f, g, h],
        }
    }

    /// Create from bytes slice
    pub fn from_bytes(bytes: &[u8]) -> AddrResult<Self> {
        if bytes.len() != 8 {
            return Err(AddrFormatError::new(
                "EUI-64 identifier must be exactly 8 bytes"
            ));
        }

        let mut eui64_bytes = [0u8; 8];
        eui64_bytes.copy_from_slice(bytes);
        Ok(Self::new(eui64_bytes))
    }

    /// Get the bytes
    pub fn bytes(&self) -> &[u8; 8] {
        &self.bytes
    }

    /// Get the OUI (first 3 bytes)
    pub fn oui(&self) -> &[u8] {
        &self.bytes[0..3]
    }

    /// Get the extension identifier (bytes 3-7)
    pub fn extension_identifier(&self) -> &[u8] {
        &self.bytes[3..8]
    }

    /// Get the organizational identifier as u32 (first 24 bits)
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

    /// Check if this is a locally administered address (second LSB of first octet is 1)
    pub fn is_local(&self) -> bool {
        (self.bytes[0] & 0x02) != 0
    }

    /// Check if this is a universally administered address (second LSB of first octet is 0)
    pub fn is_universal(&self) -> bool {
        (self.bytes[0] & 0x02) == 0
    }

    /// Check if this was derived from a MAC-48 address (contains FF-FE in the middle)
    pub fn is_mac48_derived(&self) -> bool {
        self.bytes[3] == 0xff && self.bytes[4] == 0xfe
    }

    /// Extract MAC-48 address if this EUI-64 was derived from one
    pub fn to_mac48(&self) -> Option<super::mac::MAC> {
        if !self.is_mac48_derived() {
            return None;
        }

        let mac_bytes = [
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[5],
            self.bytes[6],
            self.bytes[7],
        ];

        Some(super::mac::MAC::new(mac_bytes))
    }

    /// Generate a modified EUI-64 identifier for IPv6 address generation
    pub fn to_modified_eui64(&self) -> AddrResult<EUI64> {
        let mut modified_bytes = self.bytes;
        // Flip the Universal/Local bit (second LSB of first octet)
        modified_bytes[0] ^= 0x02;
        Ok(EUI64::new(modified_bytes))
    }

    /// Convert to link-local IPv6 address (fe80::/64 + modified EUI-64)
    pub fn to_link_local_ipv6(&self) -> AddrResult<IPAddress> {
        let modified = self.to_modified_eui64()?;
        let eui64_bytes = modified.bytes();

        // Create IPv6 address: fe80:: prefix + modified EUI-64
        let ipv6_bytes = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            eui64_bytes[0], eui64_bytes[1], eui64_bytes[2], eui64_bytes[3],
            eui64_bytes[4], eui64_bytes[5], eui64_bytes[6], eui64_bytes[7],
        ];

        let ipv6_addr = std::net::Ipv6Addr::from(ipv6_bytes);
        Ok(IPAddress::new_v6(ipv6_addr))
    }

    /// Format EUI-64 in different notations
    pub fn format(&self, format: EUI64Format) -> String {
        match format {
            EUI64Format::Colon => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]
            ),
            EUI64Format::Hyphen => format!(
                "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]
            ),
            EUI64Format::Cisco => format!(
                "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]
            ),
            EUI64Format::Bare => format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]
            ),
            EUI64Format::PostgreSQL => format!(
                "{{{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}}}",
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]
            ),
            EUI64Format::Unix => format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]
            ),
            EUI64Format::UnixExpanded => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]
            ),
        }
    }

    /// Parse EUI-64 from various string formats
    pub fn parse_flexible(s: &str) -> AddrResult<Self> {
        let clean = s.trim();

        // Remove common separators and convert to lowercase
        let normalized = clean
            .replace([':', '-', '.', ' '], "")
            .to_lowercase();

        // Remove curly braces if present (PostgreSQL format)
        let normalized = normalized.trim_matches(['{', '}']);

        if normalized.len() != 16 {
            return Err(AddrFormatError::new(format!(
                "Invalid EUI-64 length: {} (expected 16 hex characters)",
                normalized.len()
            )));
        }

        let mut bytes = [0u8; 8];
        for i in 0..8 {
            let start = i * 2;
            let end = start + 2;
            let hex_str = &normalized[start..end];
            bytes[i] = u8::from_str_radix(hex_str, 16)
                .map_err(|_| AddrFormatError::new(format!("Invalid hex characters: {}", hex_str)))?;
        }

        Ok(Self::new(bytes))
    }

    /// Convert to u64 representation
    pub fn to_u64(&self) -> u64 {
        u64::from_be_bytes(self.bytes)
    }

    /// Create from u64 representation
    pub fn from_u64(value: u64) -> Self {
        Self::new(value.to_be_bytes())
    }

    /// Get the interface identifier portion (last 64 bits for IPv6)
    pub fn interface_identifier(&self) -> u64 {
        self.to_u64()
    }
}

impl FromStr for EUI64 {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        Self::parse_flexible(s)
    }
}

impl fmt::Display for EUI64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format(EUI64Format::Colon))
    }
}

impl From<[u8; 8]> for EUI64 {
    fn from(bytes: [u8; 8]) -> Self {
        Self::new(bytes)
    }
}

impl From<EUI64> for [u8; 8] {
    fn from(eui64: EUI64) -> Self {
        eui64.bytes
    }
}

impl From<u64> for EUI64 {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<EUI64> for u64 {
    fn from(eui64: EUI64) -> Self {
        eui64.to_u64()
    }
}

/// EUI-64 formatting options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EUI64Format {
    /// Colon-separated format (00:11:22:33:44:55:66:77)
    Colon,
    /// Hyphen-separated format (00-11-22-33-44-55-66-77)
    Hyphen,
    /// Cisco format (0011.2233.4455.6677)
    Cisco,
    /// Bare format with no separators (0011223344556677)
    Bare,
    /// PostgreSQL format ({00:11:22:33:44:55:66:77})
    PostgreSQL,
    /// Unix format (0:11:22:33:44:55:66:77) - no leading zeros
    Unix,
    /// Unix expanded format (00:11:22:33:44:55:66:77) - with leading zeros
    UnixExpanded,
}

/// Validation functions
pub fn valid_eui64(s: &str) -> bool {
    EUI64::from_str(s).is_ok()
}

pub fn eui64_base(eui64: &EUI64) -> String {
    eui64.format(EUI64Format::Colon)
}

pub fn eui64_unix(eui64: &EUI64) -> String {
    eui64.format(EUI64Format::Unix)
}

pub fn eui64_unix_expanded(eui64: &EUI64) -> String {
    eui64.format(EUI64Format::UnixExpanded)
}

pub fn eui64_cisco(eui64: &EUI64) -> String {
    eui64.format(EUI64Format::Cisco)
}

pub fn eui64_bare(eui64: &EUI64) -> String {
    eui64.format(EUI64Format::Bare)
}

/// Common EUI-64 constants
impl EUI64 {
    /// Null EUI-64 (00:00:00:00:00:00:00:00)
    pub const NULL: EUI64 = EUI64 {
        bytes: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    };

    /// Generate a random EUI-64 with specified OUI
    pub fn random_with_oui(oui: &[u8; 3]) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut hasher);
        let hash = hasher.finish();

        let mut bytes = [0u8; 8];
        bytes[0..3].copy_from_slice(oui);
        bytes[3] = (hash >> 32) as u8;
        bytes[4] = (hash >> 24) as u8;
        bytes[5] = (hash >> 16) as u8;
        bytes[6] = (hash >> 8) as u8;
        bytes[7] = hash as u8;

        // Ensure it's unicast and locally administered
        bytes[0] &= 0xfc; // Clear multicast and universal bits
        bytes[0] |= 0x02; // Set local bit

        Self::new(bytes)
    }

    /// Generate a random locally administered EUI-64
    pub fn random_local() -> Self {
        let oui = [0x02, 0x00, 0x00]; // Locally administered OUI
        Self::random_with_oui(&oui)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eui64_creation() {
        let eui64 = EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert_eq!(
            eui64.bytes(),
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );

        let eui64_2 = EUI64::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77);
        assert_eq!(eui64, eui64_2);
    }

    #[test]
    fn test_eui64_properties() {
        let unicast = EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert!(unicast.is_unicast());
        assert!(!unicast.is_multicast());
        assert!(unicast.is_universal());
        assert!(!unicast.is_local());

        let multicast = EUI64::new([0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert!(!multicast.is_unicast());
        assert!(multicast.is_multicast());

        let local = EUI64::new([0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert!(!local.is_universal());
        assert!(local.is_local());
    }

    #[test]
    fn test_eui64_parsing() {
        let test_cases = vec![
            "00:11:22:33:44:55:66:77",
            "00-11-22-33-44-55-66-77",
            "0011.2233.4455.6677",
            "0011223344556677",
            "{00:11:22:33:44:55:66:77}",
        ];

        for case in test_cases {
            let eui64 = EUI64::from_str(case).unwrap();
            assert_eq!(
                eui64.bytes(),
                &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
            );
        }
    }

    #[test]
    fn test_eui64_formatting() {
        let eui64 = EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);

        assert_eq!(eui64.format(EUI64Format::Colon), "00:11:22:33:44:55:66:77");
        assert_eq!(eui64.format(EUI64Format::Hyphen), "00-11-22-33-44-55-66-77");
        assert_eq!(eui64.format(EUI64Format::Cisco), "0011.2233.4455.6677");
        assert_eq!(eui64.format(EUI64Format::Bare), "0011223344556677");
        assert_eq!(
            eui64.format(EUI64Format::PostgreSQL),
            "{00:11:22:33:44:55:66:77}"
        );
        assert_eq!(eui64.format(EUI64Format::Unix), "0:11:22:33:44:55:66:77");
        assert_eq!(
            eui64.format(EUI64Format::UnixExpanded),
            "00:11:22:33:44:55:66:77"
        );
    }

    #[test]
    fn test_oui_extension() {
        let eui64 = EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert_eq!(eui64.oui(), &[0x00, 0x11, 0x22]);
        assert_eq!(eui64.extension_identifier(), &[0x33, 0x44, 0x55, 0x66, 0x77]);
        assert_eq!(eui64.organizational_identifier(), 0x001122);
    }

    #[test]
    fn test_mac48_derivation() {
        let mac_derived = EUI64::new([0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]);
        assert!(mac_derived.is_mac48_derived());

        let mac = mac_derived.to_mac48().unwrap();
        assert_eq!(mac.bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let not_mac_derived = EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert!(!not_mac_derived.is_mac48_derived());
        assert!(not_mac_derived.to_mac48().is_none());
    }

    #[test]
    fn test_ipv6_conversion() {
        let eui64 = EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        let ipv6 = eui64.to_link_local_ipv6().unwrap();
        // fe80::0211:2233:4455:6677 (with U/L bit flipped)
        assert_eq!(ipv6.to_string(), "fe80::211:2233:4455:6677");
    }

    #[test]
    fn test_u64_conversion() {
        let eui64 = EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        let u64_val = eui64.to_u64();
        let back = EUI64::from_u64(u64_val);
        assert_eq!(eui64, back);
    }

    #[test]
    fn test_modified_eui64() {
        let eui64 = EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        let modified = eui64.to_modified_eui64().unwrap();
        assert_eq!(
            modified.bytes(),
            &[0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
    }

    #[test]
    fn test_validation_functions() {
        assert!(valid_eui64("00:11:22:33:44:55:66:77"));
        assert!(!valid_eui64("invalid"));

        let eui64 = EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert_eq!(eui64_base(&eui64), "00:11:22:33:44:55:66:77");
        assert_eq!(eui64_cisco(&eui64), "0011.2233.4455.6677");
        assert_eq!(eui64_bare(&eui64), "0011223344556677");
    }

    #[test]
    fn test_random_eui64() {
        let eui64_1 = EUI64::random_local();
        let eui64_2 = EUI64::random_local();

        // Should be different
        assert_ne!(eui64_1, eui64_2);

        // Should be locally administered
        assert!(eui64_1.is_local());
        assert!(eui64_2.is_local());

        // Should be unicast
        assert!(eui64_1.is_unicast());
        assert!(eui64_2.is_unicast());
    }

    #[test]
    fn test_constants() {
        assert_eq!(
            EUI64::NULL.bytes(),
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_interface_identifier() {
        let eui64 = EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        let interface_id = eui64.interface_identifier();
        assert_eq!(interface_id, 0x0011223344556677);
    }
}