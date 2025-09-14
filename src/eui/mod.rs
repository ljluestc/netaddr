//! EUI (Extended Unique Identifier) module for MAC addresses and EUI-64 identifiers

pub mod mac;
pub mod eui64;
pub mod ieee;

pub use mac::{MAC, MacFormat};
pub use eui64::EUI64;

use crate::error::{AddrFormatError, AddrResult};
use std::fmt;
use std::str::FromStr;

/// Generic EUI type that can represent both MAC-48 and EUI-64 addresses
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EUI {
    MAC48(MAC),
    EUI64(EUI64),
}

impl EUI {
    /// Create a new EUI from bytes
    pub fn from_bytes(bytes: &[u8]) -> AddrResult<Self> {
        match bytes.len() {
            6 => Ok(EUI::MAC48(MAC::from_bytes(bytes)?)),
            8 => Ok(EUI::EUI64(EUI64::from_bytes(bytes)?)),
            _ => Err(AddrFormatError::new(format!(
                "Invalid EUI length: {} (expected 6 or 8 bytes)",
                bytes.len()
            ))),
        }
    }

    /// Get the bytes representation
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            EUI::MAC48(mac) => mac.bytes().to_vec(),
            EUI::EUI64(eui64) => eui64.bytes().to_vec(),
        }
    }

    /// Get the length in bytes
    pub fn len(&self) -> usize {
        match self {
            EUI::MAC48(_) => 6,
            EUI::EUI64(_) => 8,
        }
    }

    /// Check if this is a MAC-48 address
    pub fn is_mac48(&self) -> bool {
        matches!(self, EUI::MAC48(_))
    }

    /// Check if this is an EUI-64 identifier
    pub fn is_eui64(&self) -> bool {
        matches!(self, EUI::EUI64(_))
    }

    /// Get the MAC-48 address if this is one
    pub fn as_mac48(&self) -> Option<&MAC> {
        match self {
            EUI::MAC48(mac) => Some(mac),
            _ => None,
        }
    }

    /// Get the EUI-64 identifier if this is one
    pub fn as_eui64(&self) -> Option<&EUI64> {
        match self {
            EUI::EUI64(eui64) => Some(eui64),
            _ => None,
        }
    }

    /// Get the OUI (Organizationally Unique Identifier)
    pub fn oui(&self) -> &[u8] {
        match self {
            EUI::MAC48(mac) => mac.oui(),
            EUI::EUI64(eui64) => eui64.oui(),
        }
    }

    /// Get the organizational identifier (24 bits for MAC-48, 24 bits for EUI-64)
    pub fn organizational_identifier(&self) -> u32 {
        match self {
            EUI::MAC48(mac) => mac.organizational_identifier(),
            EUI::EUI64(eui64) => eui64.organizational_identifier(),
        }
    }

    /// Check if this is a unicast address
    pub fn is_unicast(&self) -> bool {
        match self {
            EUI::MAC48(mac) => mac.is_unicast(),
            EUI::EUI64(eui64) => eui64.is_unicast(),
        }
    }

    /// Check if this is a multicast address
    pub fn is_multicast(&self) -> bool {
        match self {
            EUI::MAC48(mac) => mac.is_multicast(),
            EUI::EUI64(eui64) => eui64.is_multicast(),
        }
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        match self {
            EUI::MAC48(mac) => mac.is_broadcast(),
            EUI::EUI64(_) => false, // EUI-64 doesn't have broadcast
        }
    }

    /// Check if this is a locally administered address
    pub fn is_local(&self) -> bool {
        match self {
            EUI::MAC48(mac) => mac.is_local(),
            EUI::EUI64(eui64) => eui64.is_local(),
        }
    }

    /// Check if this is a universally administered address
    pub fn is_universal(&self) -> bool {
        match self {
            EUI::MAC48(mac) => mac.is_universal(),
            EUI::EUI64(eui64) => eui64.is_universal(),
        }
    }

    /// Convert MAC-48 to EUI-64 format
    pub fn to_eui64(&self) -> AddrResult<EUI64> {
        match self {
            EUI::MAC48(mac) => mac.to_eui64(),
            EUI::EUI64(eui64) => Ok(eui64.clone()),
        }
    }

    /// Convert to link-local IPv6 address
    pub fn to_link_local_ipv6(&self) -> AddrResult<crate::ip::IPAddress> {
        match self {
            EUI::MAC48(mac) => mac.to_link_local_ipv6(),
            EUI::EUI64(eui64) => eui64.to_link_local_ipv6(),
        }
    }

    /// Generate a modified EUI-64 for IPv6 address generation
    pub fn to_modified_eui64(&self) -> AddrResult<EUI64> {
        match self {
            EUI::MAC48(mac) => mac.to_modified_eui64(),
            EUI::EUI64(eui64) => eui64.to_modified_eui64(),
        }
    }

    /// Format in different notations
    pub fn format(&self, format: EUIFormat) -> String {
        match self {
            EUI::MAC48(mac) => mac.format(format.into()),
            EUI::EUI64(eui64) => eui64.format(format.into()),
        }
    }
}

impl FromStr for EUI {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        // Try MAC-48 first (more common)
        if let Ok(mac) = MAC::from_str(s) {
            return Ok(EUI::MAC48(mac));
        }

        // Try EUI-64
        if let Ok(eui64) = EUI64::from_str(s) {
            return Ok(EUI::EUI64(eui64));
        }

        Err(AddrFormatError::new(format!(
            "Invalid EUI format: {}",
            s
        )))
    }
}

impl fmt::Display for EUI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EUI::MAC48(mac) => write!(f, "{}", mac),
            EUI::EUI64(eui64) => write!(f, "{}", eui64),
        }
    }
}

impl From<MAC> for EUI {
    fn from(mac: MAC) -> Self {
        EUI::MAC48(mac)
    }
}

impl From<EUI64> for EUI {
    fn from(eui64: EUI64) -> Self {
        EUI::EUI64(eui64)
    }
}

/// EUI formatting options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EUIFormat {
    /// Standard IEEE format with colons (01:23:45:67:89:ab)
    Colon,
    /// Hyphen-separated format (01-23-45-67-89-ab)
    Hyphen,
    /// Cisco format (0123.4567.89ab)
    Cisco,
    /// Bare format with no separators (0123456789ab)
    Bare,
    /// PostgreSQL format ({01:23:45:67:89:ab})
    PostgreSQL,
    /// Unix format (1:23:45:67:89:ab) - no leading zeros
    Unix,
    /// Unix expanded format (01:23:45:67:89:ab) - with leading zeros
    UnixExpanded,
}

impl From<EUIFormat> for mac::MacFormat {
    fn from(format: EUIFormat) -> Self {
        match format {
            EUIFormat::Colon => mac::MacFormat::Colon,
            EUIFormat::Hyphen => mac::MacFormat::Hyphen,
            EUIFormat::Cisco => mac::MacFormat::Cisco,
            EUIFormat::Bare => mac::MacFormat::Bare,
            EUIFormat::PostgreSQL => mac::MacFormat::PostgreSQL,
            EUIFormat::Unix => mac::MacFormat::Unix,
            EUIFormat::UnixExpanded => mac::MacFormat::UnixExpanded,
        }
    }
}

impl From<EUIFormat> for eui64::EUI64Format {
    fn from(format: EUIFormat) -> Self {
        match format {
            EUIFormat::Colon => eui64::EUI64Format::Colon,
            EUIFormat::Hyphen => eui64::EUI64Format::Hyphen,
            EUIFormat::Cisco => eui64::EUI64Format::Cisco,
            EUIFormat::Bare => eui64::EUI64Format::Bare,
            EUIFormat::PostgreSQL => eui64::EUI64Format::PostgreSQL,
            EUIFormat::Unix => eui64::EUI64Format::Unix,
            EUIFormat::UnixExpanded => eui64::EUI64Format::UnixExpanded,
        }
    }
}

/// IEEE OUI (Organizationally Unique Identifier)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OUI {
    bytes: [u8; 3],
}

impl OUI {
    /// Create a new OUI from bytes
    pub fn new(bytes: [u8; 3]) -> Self {
        Self { bytes }
    }

    /// Create from a u32 (using lower 24 bits)
    pub fn from_u32(value: u32) -> Self {
        Self {
            bytes: [
                ((value >> 16) & 0xff) as u8,
                ((value >> 8) & 0xff) as u8,
                (value & 0xff) as u8,
            ],
        }
    }

    /// Get the bytes
    pub fn bytes(&self) -> &[u8; 3] {
        &self.bytes
    }

    /// Convert to u32
    pub fn to_u32(&self) -> u32 {
        ((self.bytes[0] as u32) << 16) | ((self.bytes[1] as u32) << 8) | (self.bytes[2] as u32)
    }

    /// Get the registry information for this OUI
    pub fn registry_info(&self) -> Option<ieee::OUIRegistryInfo> {
        ieee::OUI_REGISTRY.lookup_oui(self)
    }
}

impl FromStr for OUI {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        // Remove common separators
        let clean = s.replace([':', '-', '.'], "");

        if clean.len() != 6 {
            return Err(AddrFormatError::new("OUI must be 6 hex characters"));
        }

        let mut bytes = [0u8; 3];
        for (i, chunk) in clean.as_bytes().chunks(2).enumerate() {
            if i >= 3 {
                break;
            }
            let hex_str = std::str::from_utf8(chunk)
                .map_err(|_| AddrFormatError::new("Invalid hex characters"))?;
            bytes[i] = u8::from_str_radix(hex_str, 16)
                .map_err(|_| AddrFormatError::new("Invalid hex characters"))?;
        }

        Ok(OUI::new(bytes))
    }
}

impl fmt::Display for OUI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}",
            self.bytes[0], self.bytes[1], self.bytes[2]
        )
    }
}

/// IEEE IAB (Individual Address Block)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IAB {
    oui: OUI,
    extension: u8,
}

impl IAB {
    /// Create a new IAB
    pub fn new(oui: OUI, extension: u8) -> Self {
        Self { oui, extension }
    }

    /// Get the OUI portion
    pub fn oui(&self) -> &OUI {
        &self.oui
    }

    /// Get the extension byte
    pub fn extension(&self) -> u8 {
        self.extension
    }

    /// Get the registry information for this IAB
    pub fn registry_info(&self) -> Option<ieee::IABRegistryInfo> {
        ieee::IAB_REGISTRY.lookup_iab(self)
    }
}

impl fmt::Display for IAB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{:02x}", self.oui, self.extension)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eui_creation() {
        let mac_bytes = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let eui = EUI::from_bytes(&mac_bytes).unwrap();
        assert!(eui.is_mac48());
        assert_eq!(eui.len(), 6);

        let eui64_bytes = [0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55];
        let eui = EUI::from_bytes(&eui64_bytes).unwrap();
        assert!(eui.is_eui64());
        assert_eq!(eui.len(), 8);
    }

    #[test]
    fn test_eui_from_string() {
        let eui = EUI::from_str("00:11:22:33:44:55").unwrap();
        assert!(eui.is_mac48());

        let eui = EUI::from_str("00:11:22:ff:fe:33:44:55").unwrap();
        assert!(eui.is_eui64());
    }

    #[test]
    fn test_oui() {
        let oui = OUI::from_str("00:11:22").unwrap();
        assert_eq!(oui.to_u32(), 0x001122);
        assert_eq!(oui.to_string(), "00:11:22");

        let oui2 = OUI::from_u32(0x001122);
        assert_eq!(oui, oui2);
    }

    #[test]
    fn test_iab() {
        let oui = OUI::from_str("00:50:c2").unwrap();
        let iab = IAB::new(oui, 0x12);
        assert_eq!(iab.extension(), 0x12);
        assert_eq!(iab.to_string(), "00:50:c2-12");
    }

    #[test]
    fn test_eui_properties() {
        let unicast_mac = EUI::from_str("00:11:22:33:44:55").unwrap();
        assert!(unicast_mac.is_unicast());
        assert!(!unicast_mac.is_multicast());

        let multicast_mac = EUI::from_str("01:11:22:33:44:55").unwrap();
        assert!(!multicast_mac.is_unicast());
        assert!(multicast_mac.is_multicast());

        let broadcast_mac = EUI::from_str("ff:ff:ff:ff:ff:ff").unwrap();
        assert!(broadcast_mac.is_broadcast());
        assert!(broadcast_mac.is_multicast());
    }

    #[test]
    fn test_eui_conversion() {
        let mac = EUI::from_str("00:11:22:33:44:55").unwrap();
        let eui64 = mac.to_eui64().unwrap();
        assert_eq!(eui64.to_string(), "00:11:22:ff:fe:33:44:55");
    }

    #[test]
    fn test_formatting() {
        let eui = EUI::from_str("00:11:22:33:44:55").unwrap();

        assert_eq!(eui.format(EUIFormat::Colon), "00:11:22:33:44:55");
        assert_eq!(eui.format(EUIFormat::Hyphen), "00-11-22-33-44-55");
        assert_eq!(eui.format(EUIFormat::Cisco), "0011.2233.4455");
        assert_eq!(eui.format(EUIFormat::Bare), "001122334455");
    }
}