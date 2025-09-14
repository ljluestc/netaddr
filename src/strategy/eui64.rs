//! EUI-64 parsing and formatting strategies

use crate::error::AddrResult;
use std::str::FromStr;

/// EUI-64 identifier parsing and formatting strategy
pub struct EUI64Strategy;

impl EUI64Strategy {
    /// Validate EUI-64 string format
    pub fn valid_str(s: &str) -> bool {
        crate::eui::eui64::EUI64::from_str(s).is_ok()
    }

    /// Format in standard colon-separated notation
    pub fn eui64_base(eui64: &crate::eui::eui64::EUI64) -> String {
        eui64.format(crate::eui::eui64::EUI64Format::Colon)
    }

    /// Format in Unix notation (no leading zeros)
    pub fn eui64_unix(eui64: &crate::eui::eui64::EUI64) -> String {
        eui64.format(crate::eui::eui64::EUI64Format::Unix)
    }

    /// Format in Unix expanded notation (with leading zeros)
    pub fn eui64_unix_expanded(eui64: &crate::eui::eui64::EUI64) -> String {
        eui64.format(crate::eui::eui64::EUI64Format::UnixExpanded)
    }

    /// Format in Cisco notation (dotted groups of 4 hex digits)
    pub fn eui64_cisco(eui64: &crate::eui::eui64::EUI64) -> String {
        eui64.format(crate::eui::eui64::EUI64Format::Cisco)
    }

    /// Format as bare hex string (no separators)
    pub fn eui64_bare(eui64: &crate::eui::eui64::EUI64) -> String {
        eui64.format(crate::eui::eui64::EUI64Format::Bare)
    }

    /// Format in PostgreSQL notation (with curly braces)
    pub fn eui64_pgsql(eui64: &crate::eui::eui64::EUI64) -> String {
        eui64.format(crate::eui::eui64::EUI64Format::PostgreSQL)
    }

    /// Parse EUI-64 from various formats
    pub fn parse_flexible(s: &str) -> AddrResult<crate::eui::eui64::EUI64> {
        crate::eui::eui64::EUI64::parse_flexible(s)
    }

    /// Check if EUI-64 is unicast
    pub fn is_unicast(eui64: &crate::eui::eui64::EUI64) -> bool {
        eui64.is_unicast()
    }

    /// Check if EUI-64 is multicast
    pub fn is_multicast(eui64: &crate::eui::eui64::EUI64) -> bool {
        eui64.is_multicast()
    }

    /// Check if EUI-64 is locally administered
    pub fn is_local(eui64: &crate::eui::eui64::EUI64) -> bool {
        eui64.is_local()
    }

    /// Check if EUI-64 is universally administered
    pub fn is_universal(eui64: &crate::eui::eui64::EUI64) -> bool {
        eui64.is_universal()
    }

    /// Check if EUI-64 was derived from MAC-48
    pub fn is_mac48_derived(eui64: &crate::eui::eui64::EUI64) -> bool {
        eui64.is_mac48_derived()
    }

    /// Get the OUI (first 3 bytes)
    pub fn get_oui(eui64: &crate::eui::eui64::EUI64) -> &[u8] {
        eui64.oui()
    }

    /// Get the extension identifier (bytes 3-7)
    pub fn get_extension_identifier(eui64: &crate::eui::eui64::EUI64) -> &[u8] {
        eui64.extension_identifier()
    }

    /// Extract MAC-48 if derived from one
    pub fn to_mac48(eui64: &crate::eui::eui64::EUI64) -> Option<crate::eui::mac::MAC> {
        eui64.to_mac48()
    }

    /// Generate modified EUI-64 for IPv6
    pub fn to_modified_eui64(eui64: &crate::eui::eui64::EUI64) -> AddrResult<crate::eui::eui64::EUI64> {
        eui64.to_modified_eui64()
    }

    /// Convert to link-local IPv6 address
    pub fn to_link_local_ipv6(eui64: &crate::eui::eui64::EUI64) -> AddrResult<crate::ip::IPAddress> {
        eui64.to_link_local_ipv6()
    }

    /// Get vendor name by OUI lookup
    pub fn get_vendor(eui64: &crate::eui::eui64::EUI64) -> Option<&'static str> {
        let oui = crate::eui::OUI::new([eui64.oui()[0], eui64.oui()[1], eui64.oui()[2]]);
        crate::eui::ieee::vendors::get_vendor_name(&oui)
    }

    /// Generate random EUI-64 with specific OUI
    pub fn random_with_oui(oui: &[u8; 3]) -> crate::eui::eui64::EUI64 {
        crate::eui::eui64::EUI64::random_with_oui(oui)
    }

    /// Generate random locally administered EUI-64
    pub fn random_local() -> crate::eui::eui64::EUI64 {
        crate::eui::eui64::EUI64::random_local()
    }

    /// Get EUI-64 category
    pub fn get_category(eui64: &crate::eui::eui64::EUI64) -> &'static str {
        if eui64.is_multicast() {
            if eui64.is_mac48_derived() {
                "MAC-48 Derived Multicast"
            } else {
                "Multicast"
            }
        } else if eui64.is_local() {
            if eui64.is_mac48_derived() {
                "MAC-48 Derived Locally Administered"
            } else {
                "Locally Administered Unicast"
            }
        } else {
            if eui64.is_mac48_derived() {
                "MAC-48 Derived Universally Administered"
            } else {
                "Universally Administered Unicast"
            }
        }
    }

    /// Convert to integer representation
    pub fn to_int(eui64: &crate::eui::eui64::EUI64) -> u64 {
        eui64.to_u64()
    }

    /// Convert from integer representation
    pub fn from_int(value: u64) -> crate::eui::eui64::EUI64 {
        crate::eui::eui64::EUI64::from_u64(value)
    }

    /// Get interface identifier for IPv6 use
    pub fn interface_identifier(eui64: &crate::eui::eui64::EUI64) -> u64 {
        eui64.interface_identifier()
    }

    /// Create EUI-64 from MAC-48 with FF-FE insertion
    pub fn from_mac48(mac: &crate::eui::mac::MAC) -> AddrResult<crate::eui::eui64::EUI64> {
        mac.to_eui64()
    }

    /// Split into two 32-bit parts
    pub fn split_parts(eui64: &crate::eui::eui64::EUI64) -> (u32, u32) {
        let bytes = eui64.bytes();
        let high = ((bytes[0] as u32) << 24)
            | ((bytes[1] as u32) << 16)
            | ((bytes[2] as u32) << 8)
            | (bytes[3] as u32);
        let low = ((bytes[4] as u32) << 24)
            | ((bytes[5] as u32) << 16)
            | ((bytes[6] as u32) << 8)
            | (bytes[7] as u32);
        (high, low)
    }

    /// Create from two 32-bit parts
    pub fn from_parts(high: u32, low: u32) -> crate::eui::eui64::EUI64 {
        let bytes = [
            (high >> 24) as u8,
            (high >> 16) as u8,
            (high >> 8) as u8,
            high as u8,
            (low >> 24) as u8,
            (low >> 16) as u8,
            (low >> 8) as u8,
            low as u8,
        ];
        crate::eui::eui64::EUI64::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_validation() {
        assert!(EUI64Strategy::valid_str("00:11:22:33:44:55:66:77"));
        assert!(!EUI64Strategy::valid_str("invalid"));
    }

    #[test]
    fn test_formatting() {
        let eui64 = crate::eui::eui64::EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);

        assert_eq!(EUI64Strategy::eui64_base(&eui64), "00:11:22:33:44:55:66:77");
        assert_eq!(EUI64Strategy::eui64_unix(&eui64), "0:11:22:33:44:55:66:77");
        assert_eq!(EUI64Strategy::eui64_unix_expanded(&eui64), "00:11:22:33:44:55:66:77");
        assert_eq!(EUI64Strategy::eui64_cisco(&eui64), "0011.2233.4455.6677");
        assert_eq!(EUI64Strategy::eui64_bare(&eui64), "0011223344556677");
        assert_eq!(EUI64Strategy::eui64_pgsql(&eui64), "{00:11:22:33:44:55:66:77}");
    }

    #[test]
    fn test_properties() {
        let unicast = crate::eui::eui64::EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert!(EUI64Strategy::is_unicast(&unicast));
        assert!(EUI64Strategy::is_universal(&unicast));
        assert_eq!(EUI64Strategy::get_category(&unicast), "Universally Administered Unicast");

        let multicast = crate::eui::eui64::EUI64::new([0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert!(EUI64Strategy::is_multicast(&multicast));
        assert_eq!(EUI64Strategy::get_category(&multicast), "Multicast");

        let local = crate::eui::eui64::EUI64::new([0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert!(EUI64Strategy::is_local(&local));
        assert_eq!(EUI64Strategy::get_category(&local), "Locally Administered Unicast");
    }

    #[test]
    fn test_mac48_derivation() {
        let mac_derived = crate::eui::eui64::EUI64::new([0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]);
        assert!(EUI64Strategy::is_mac48_derived(&mac_derived));
        assert_eq!(EUI64Strategy::get_category(&mac_derived), "MAC-48 Derived Universally Administered");

        let mac = EUI64Strategy::to_mac48(&mac_derived).unwrap();
        assert_eq!(mac.bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let not_mac_derived = crate::eui::eui64::EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert!(!EUI64Strategy::is_mac48_derived(&not_mac_derived));
        assert!(EUI64Strategy::to_mac48(&not_mac_derived).is_none());
    }

    #[test]
    fn test_parts() {
        let eui64 = crate::eui::eui64::EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);

        let oui = EUI64Strategy::get_oui(&eui64);
        assert_eq!(oui, &[0x00, 0x11, 0x22]);

        let ext = EUI64Strategy::get_extension_identifier(&eui64);
        assert_eq!(ext, &[0x33, 0x44, 0x55, 0x66, 0x77]);
    }

    #[test]
    fn test_conversions() {
        let mac = crate::eui::mac::MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let eui64 = EUI64Strategy::from_mac48(&mac).unwrap();
        assert_eq!(eui64.bytes(), &[0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]);

        let back_to_mac = EUI64Strategy::to_mac48(&eui64).unwrap();
        assert_eq!(mac, back_to_mac);

        let modified = EUI64Strategy::to_modified_eui64(&eui64).unwrap();
        assert_eq!(modified.bytes(), &[0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]);

        let ipv6 = EUI64Strategy::to_link_local_ipv6(&eui64).unwrap();
        assert_eq!(ipv6.to_string(), "fe80::211:22ff:fe33:4455");
    }

    #[test]
    fn test_integer_conversion() {
        let eui64 = crate::eui::eui64::EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        let int_val = EUI64Strategy::to_int(&eui64);
        let back = EUI64Strategy::from_int(int_val);
        assert_eq!(eui64, back);

        let interface_id = EUI64Strategy::interface_identifier(&eui64);
        assert_eq!(interface_id, int_val);
    }

    #[test]
    fn test_parts_split() {
        let eui64 = crate::eui::eui64::EUI64::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        let (high, low) = EUI64Strategy::split_parts(&eui64);
        let reconstructed = EUI64Strategy::from_parts(high, low);
        assert_eq!(eui64, reconstructed);
    }

    #[test]
    fn test_random_generation() {
        let eui64_1 = EUI64Strategy::random_local();
        let eui64_2 = EUI64Strategy::random_local();

        assert_ne!(eui64_1, eui64_2);
        assert!(EUI64Strategy::is_local(&eui64_1));
        assert!(EUI64Strategy::is_local(&eui64_2));
        assert!(EUI64Strategy::is_unicast(&eui64_1));
        assert!(EUI64Strategy::is_unicast(&eui64_2));

        let oui = [0x00, 0x11, 0x22];
        let with_oui = EUI64Strategy::random_with_oui(&oui);
        assert_eq!(EUI64Strategy::get_oui(&with_oui)[0..3], oui);
    }

    #[test]
    fn test_vendor_lookup() {
        let apple_eui64 = crate::eui::eui64::EUI64::new([0x00, 0x1B, 0x63, 0x12, 0x34, 0x56, 0x78, 0x9A]);
        assert_eq!(EUI64Strategy::get_vendor(&apple_eui64), Some("Apple"));

        let intel_eui64 = crate::eui::eui64::EUI64::new([0x00, 0x1B, 0x21, 0x12, 0x34, 0x56, 0x78, 0x9A]);
        assert_eq!(EUI64Strategy::get_vendor(&intel_eui64), Some("Intel"));

        let cisco_eui64 = crate::eui::eui64::EUI64::new([0x00, 0x1F, 0x9E, 0x12, 0x34, 0x56, 0x78, 0x9A]);
        assert_eq!(EUI64Strategy::get_vendor(&cisco_eui64), Some("Cisco"));

        let unknown_eui64 = crate::eui::eui64::EUI64::new([0xAA, 0xBB, 0xCC, 0x12, 0x34, 0x56, 0x78, 0x9A]);
        assert_eq!(EUI64Strategy::get_vendor(&unknown_eui64), None);
    }
}