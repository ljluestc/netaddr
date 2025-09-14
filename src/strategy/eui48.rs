//! EUI-48 (MAC) parsing and formatting strategies

use crate::error::AddrResult;
use std::str::FromStr;

/// EUI-48 (MAC address) parsing and formatting strategy
pub struct EUI48Strategy;

impl EUI48Strategy {
    /// Validate EUI-48 string format
    pub fn valid_str(s: &str) -> bool {
        crate::eui::mac::MAC::from_str(s).is_ok()
    }

    /// Format in IEEE standard notation (colon-separated)
    pub fn mac_eui48(mac: &crate::eui::mac::MAC) -> String {
        mac.format(crate::eui::mac::MacFormat::Colon)
    }

    /// Format in Unix notation (no leading zeros)
    pub fn mac_unix(mac: &crate::eui::mac::MAC) -> String {
        mac.format(crate::eui::mac::MacFormat::Unix)
    }

    /// Format in Unix expanded notation (with leading zeros)
    pub fn mac_unix_expanded(mac: &crate::eui::mac::MAC) -> String {
        mac.format(crate::eui::mac::MacFormat::UnixExpanded)
    }

    /// Format in Cisco notation (dotted groups of 4 hex digits)
    pub fn mac_cisco(mac: &crate::eui::mac::MAC) -> String {
        mac.format(crate::eui::mac::MacFormat::Cisco)
    }

    /// Format as bare hex string (no separators)
    pub fn mac_bare(mac: &crate::eui::mac::MAC) -> String {
        mac.format(crate::eui::mac::MacFormat::Bare)
    }

    /// Format in PostgreSQL notation (with curly braces)
    pub fn mac_pgsql(mac: &crate::eui::mac::MAC) -> String {
        mac.format(crate::eui::mac::MacFormat::PostgreSQL)
    }

    /// Parse MAC address from various formats
    pub fn parse_flexible(s: &str) -> AddrResult<crate::eui::mac::MAC> {
        crate::eui::mac::MAC::parse_flexible(s)
    }

    /// Check if MAC is unicast
    pub fn is_unicast(mac: &crate::eui::mac::MAC) -> bool {
        mac.is_unicast()
    }

    /// Check if MAC is multicast
    pub fn is_multicast(mac: &crate::eui::mac::MAC) -> bool {
        mac.is_multicast()
    }

    /// Check if MAC is broadcast
    pub fn is_broadcast(mac: &crate::eui::mac::MAC) -> bool {
        mac.is_broadcast()
    }

    /// Check if MAC is locally administered
    pub fn is_local(mac: &crate::eui::mac::MAC) -> bool {
        mac.is_local()
    }

    /// Check if MAC is universally administered
    pub fn is_universal(mac: &crate::eui::mac::MAC) -> bool {
        mac.is_universal()
    }

    /// Get the OUI (Organizationally Unique Identifier)
    pub fn get_oui(mac: &crate::eui::mac::MAC) -> &[u8] {
        mac.oui()
    }

    /// Get the NIC-specific portion
    pub fn get_nic(mac: &crate::eui::mac::MAC) -> &[u8] {
        mac.nic()
    }

    /// Convert to EUI-64 format
    pub fn to_eui64(mac: &crate::eui::mac::MAC) -> AddrResult<crate::eui::eui64::EUI64> {
        mac.to_eui64()
    }

    /// Generate modified EUI-64 for IPv6
    pub fn to_modified_eui64(mac: &crate::eui::mac::MAC) -> AddrResult<crate::eui::eui64::EUI64> {
        mac.to_modified_eui64()
    }

    /// Convert to link-local IPv6 address
    pub fn to_link_local_ipv6(mac: &crate::eui::mac::MAC) -> AddrResult<crate::ip::IPAddress> {
        mac.to_link_local_ipv6()
    }

    /// Get vendor name by OUI lookup
    pub fn get_vendor(mac: &crate::eui::mac::MAC) -> Option<&'static str> {
        let oui = crate::eui::OUI::new([mac.oui()[0], mac.oui()[1], mac.oui()[2]]);
        crate::eui::ieee::vendors::get_vendor_name(&oui)
    }

    /// Generate random MAC with specific OUI
    pub fn random_with_oui(oui: &[u8; 3]) -> crate::eui::mac::MAC {
        crate::eui::mac::MAC::random_with_oui(oui)
    }

    /// Generate random locally administered MAC
    pub fn random_local() -> crate::eui::mac::MAC {
        crate::eui::mac::MAC::random_local()
    }

    /// Get MAC address category
    pub fn get_category(mac: &crate::eui::mac::MAC) -> &'static str {
        if mac.is_broadcast() {
            "Broadcast"
        } else if mac.is_multicast() {
            "Multicast"
        } else if mac.is_local() {
            "Locally Administered Unicast"
        } else {
            "Universally Administered Unicast"
        }
    }

    /// Convert to integer representation
    pub fn to_int(mac: &crate::eui::mac::MAC) -> u64 {
        let bytes = mac.bytes();
        ((bytes[0] as u64) << 40)
            | ((bytes[1] as u64) << 32)
            | ((bytes[2] as u64) << 24)
            | ((bytes[3] as u64) << 16)
            | ((bytes[4] as u64) << 8)
            | (bytes[5] as u64)
    }

    /// Convert from integer representation
    pub fn from_int(value: u64) -> crate::eui::mac::MAC {
        crate::eui::mac::MAC::new([
            (value >> 40) as u8,
            (value >> 32) as u8,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_validation() {
        assert!(EUI48Strategy::valid_str("00:11:22:33:44:55"));
        assert!(!EUI48Strategy::valid_str("invalid"));
    }

    #[test]
    fn test_formatting() {
        let mac = crate::eui::mac::MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        assert_eq!(EUI48Strategy::mac_eui48(&mac), "00:11:22:33:44:55");
        assert_eq!(EUI48Strategy::mac_unix(&mac), "0:11:22:33:44:55");
        assert_eq!(EUI48Strategy::mac_unix_expanded(&mac), "00:11:22:33:44:55");
        assert_eq!(EUI48Strategy::mac_cisco(&mac), "0011.2233.4455");
        assert_eq!(EUI48Strategy::mac_bare(&mac), "001122334455");
        assert_eq!(EUI48Strategy::mac_pgsql(&mac), "{00:11:22:33:44:55}");
    }

    #[test]
    fn test_properties() {
        let unicast = crate::eui::mac::MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(EUI48Strategy::is_unicast(&unicast));
        assert!(EUI48Strategy::is_universal(&unicast));
        assert_eq!(EUI48Strategy::get_category(&unicast), "Universally Administered Unicast");

        let multicast = crate::eui::mac::MAC::new([0x01, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(EUI48Strategy::is_multicast(&multicast));
        assert_eq!(EUI48Strategy::get_category(&multicast), "Multicast");

        let local = crate::eui::mac::MAC::new([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(EUI48Strategy::is_local(&local));
        assert_eq!(EUI48Strategy::get_category(&local), "Locally Administered Unicast");

        let broadcast = crate::eui::mac::MAC::BROADCAST;
        assert!(EUI48Strategy::is_broadcast(&broadcast));
        assert_eq!(EUI48Strategy::get_category(&broadcast), "Broadcast");
    }

    #[test]
    fn test_parts() {
        let mac = crate::eui::mac::MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let oui = EUI48Strategy::get_oui(&mac);
        assert_eq!(oui, &[0x00, 0x11, 0x22]);

        let nic = EUI48Strategy::get_nic(&mac);
        assert_eq!(nic, &[0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_conversions() {
        let mac = crate::eui::mac::MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let eui64 = EUI48Strategy::to_eui64(&mac).unwrap();
        assert_eq!(eui64.bytes(), &[0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]);

        let modified_eui64 = EUI48Strategy::to_modified_eui64(&mac).unwrap();
        assert_eq!(modified_eui64.bytes(), &[0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]);

        let ipv6 = EUI48Strategy::to_link_local_ipv6(&mac).unwrap();
        assert_eq!(ipv6.to_string(), "fe80::211:22ff:fe33:4455");
    }

    #[test]
    fn test_integer_conversion() {
        let mac = crate::eui::mac::MAC::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let int_val = EUI48Strategy::to_int(&mac);
        let back = EUI48Strategy::from_int(int_val);
        assert_eq!(mac, back);
    }

    #[test]
    fn test_random_generation() {
        let mac1 = EUI48Strategy::random_local();
        let mac2 = EUI48Strategy::random_local();

        assert_ne!(mac1, mac2);
        assert!(EUI48Strategy::is_local(&mac1));
        assert!(EUI48Strategy::is_local(&mac2));
        assert!(EUI48Strategy::is_unicast(&mac1));
        assert!(EUI48Strategy::is_unicast(&mac2));

        let oui = [0x00, 0x11, 0x22];
        let with_oui = EUI48Strategy::random_with_oui(&oui);
        assert_eq!(EUI48Strategy::get_oui(&with_oui)[0..3], oui);
    }

    #[test]
    fn test_vendor_lookup() {
        // Test with known vendor OUIs
        let apple_mac = crate::eui::mac::MAC::new([0x00, 0x1B, 0x63, 0x12, 0x34, 0x56]);
        assert_eq!(EUI48Strategy::get_vendor(&apple_mac), Some("Apple"));

        let intel_mac = crate::eui::mac::MAC::new([0x00, 0x1B, 0x21, 0x12, 0x34, 0x56]);
        assert_eq!(EUI48Strategy::get_vendor(&intel_mac), Some("Intel"));

        let cisco_mac = crate::eui::mac::MAC::new([0x00, 0x1F, 0x9E, 0x12, 0x34, 0x56]);
        assert_eq!(EUI48Strategy::get_vendor(&cisco_mac), Some("Cisco"));

        let unknown_mac = crate::eui::mac::MAC::new([0xAA, 0xBB, 0xCC, 0x12, 0x34, 0x56]);
        assert_eq!(EUI48Strategy::get_vendor(&unknown_mac), None);
    }
}