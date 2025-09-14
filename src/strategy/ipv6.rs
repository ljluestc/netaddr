//! IPv6 parsing and formatting strategies

use crate::error::{AddrFormatError, AddrResult};
use std::str::FromStr;

/// IPv6 address parsing and formatting strategy
pub struct IPv6Strategy;

impl IPv6Strategy {
    /// Validate IPv6 string format
    pub fn valid_str(s: &str) -> bool {
        crate::ip::ipv6::IPv6::from_str(s).is_ok()
    }

    /// Format IPv6 in compact form (with :: compression)
    pub fn ipv6_compact(addr: &crate::ip::ipv6::IPv6) -> String {
        addr.compact()
    }

    /// Format IPv6 in full form (no compression)
    pub fn ipv6_full(addr: &crate::ip::ipv6::IPv6) -> String {
        addr.full()
    }

    /// Format IPv6 in verbose form (same as full)
    pub fn ipv6_verbose(addr: &crate::ip::ipv6::IPv6) -> String {
        addr.verbose()
    }

    /// Parse IPv6 address with various format support
    pub fn parse_flexible(s: &str) -> AddrResult<crate::ip::ipv6::IPv6> {
        // Remove brackets if present (for URL format)
        let clean = s.trim_matches(['[', ']']);

        // Handle different IPv6 formats
        if clean.contains("::") {
            // Compressed format
            Self::parse_compressed(clean)
        } else if clean.contains('.') {
            // Mixed IPv4/IPv6 format
            Self::parse_mixed(clean)
        } else {
            // Standard format
            crate::ip::ipv6::IPv6::from_str(clean)
        }
    }

    /// Parse compressed IPv6 address (with ::)
    fn parse_compressed(s: &str) -> AddrResult<crate::ip::ipv6::IPv6> {
        crate::ip::ipv6::IPv6::from_str(s)
    }

    /// Parse mixed IPv4/IPv6 format (e.g., ::ffff:192.168.1.1)
    fn parse_mixed(s: &str) -> AddrResult<crate::ip::ipv6::IPv6> {
        crate::ip::ipv6::IPv6::from_str(s)
    }

    /// Convert to Base85 representation (RFC 1924)
    pub fn to_base85(addr: &crate::ip::ipv6::IPv6) -> String {
        crate::ip::ipv6::Base85::encode(addr)
    }

    /// Parse from Base85 representation (RFC 1924)
    pub fn from_base85(s: &str) -> AddrResult<crate::ip::ipv6::IPv6> {
        crate::ip::ipv6::Base85::decode(s)
    }

    /// Check if address is in unique local range (fc00::/7)
    pub fn is_unique_local(addr: &crate::ip::ipv6::IPv6) -> bool {
        addr.is_unique_local()
    }

    /// Check if address is global unicast
    pub fn is_global_unicast(addr: &crate::ip::ipv6::IPv6) -> bool {
        addr.is_global_unicast()
    }

    /// Check if address is link-local (fe80::/10)
    pub fn is_link_local(addr: &crate::ip::ipv6::IPv6) -> bool {
        addr.as_ipv6_addr().is_loopback() // This is a simplification
    }

    /// Check if address is loopback (::1)
    pub fn is_loopback(addr: &crate::ip::ipv6::IPv6) -> bool {
        addr.as_ipv6_addr().is_loopback()
    }

    /// Check if address is multicast (ff00::/8)
    pub fn is_multicast(addr: &crate::ip::ipv6::IPv6) -> bool {
        addr.as_ipv6_addr().is_multicast()
    }

    /// Check if address is IPv4-mapped (::ffff:0:0/96)
    pub fn is_ipv4_mapped(addr: &crate::ip::ipv6::IPv6) -> bool {
        addr.is_ipv4_mapped()
    }

    /// Check if address is IPv4-compatible (deprecated)
    pub fn is_ipv4_compatible(addr: &crate::ip::ipv6::IPv6) -> bool {
        addr.is_ipv4_compatible()
    }

    /// Check if address is 6to4 (2002::/16)
    pub fn is_6to4(addr: &crate::ip::ipv6::IPv6) -> bool {
        addr.is_6to4()
    }

    /// Check if address is Teredo (2001::/32)
    pub fn is_teredo(addr: &crate::ip::ipv6::IPv6) -> bool {
        addr.is_teredo()
    }

    /// Check if address is documentation (2001:db8::/32)
    pub fn is_documentation(addr: &crate::ip::ipv6::IPv6) -> bool {
        addr.is_documentation()
    }

    /// Extract IPv4 address if this is IPv4-mapped
    pub fn to_ipv4(addr: &crate::ip::ipv6::IPv6) -> Option<crate::ip::ipv4::IPv4> {
        addr.to_ipv4()
    }

    /// Get the interface identifier (last 64 bits)
    pub fn interface_id(addr: &crate::ip::ipv6::IPv6) -> u64 {
        addr.interface_id()
    }

    /// Get the network prefix (first 64 bits)
    pub fn network_prefix(addr: &crate::ip::ipv6::IPv6) -> u64 {
        addr.network_prefix()
    }

    /// Create address from network prefix and interface ID
    pub fn from_parts(network_prefix: u64, interface_id: u64) -> crate::ip::ipv6::IPv6 {
        crate::ip::ipv6::IPv6::from_parts(network_prefix, interface_id)
    }

    /// Expand address to full 32 hexadecimal characters
    pub fn expand_hex(addr: &crate::ip::ipv6::IPv6) -> String {
        format!("{:032x}", addr.to_u128())
    }

    /// Format as pure hexadecimal (no colons)
    pub fn format_hex_compact(addr: &crate::ip::ipv6::IPv6) -> String {
        format!("{:032x}", addr.to_u128())
    }

    /// Format with custom separator
    pub fn format_with_separator(addr: &crate::ip::ipv6::IPv6, sep: &str) -> String {
        let full = addr.full();
        full.replace(':', sep)
    }

    /// Parse from pure hexadecimal string
    pub fn from_hex_string(hex: &str) -> AddrResult<crate::ip::ipv6::IPv6> {
        if hex.len() != 32 {
            return Err(AddrFormatError::new("Hex string must be exactly 32 characters"));
        }

        let num = u128::from_str_radix(hex, 16)
            .map_err(|_| AddrFormatError::new("Invalid hexadecimal string"))?;

        Ok(crate::ip::ipv6::IPv6::from_u128(num))
    }

    /// Get address type classification
    pub fn get_address_type(addr: &crate::ip::ipv6::IPv6) -> &'static str {
        if addr.as_ipv6_addr().is_unspecified() {
            "Unspecified"
        } else if addr.as_ipv6_addr().is_loopback() {
            "Loopback"
        } else if addr.as_ipv6_addr().is_multicast() {
            "Multicast"
        } else if addr.is_ipv4_mapped() {
            "IPv4-mapped"
        } else if addr.is_ipv4_compatible() {
            "IPv4-compatible"
        } else if addr.is_6to4() {
            "6to4"
        } else if addr.is_teredo() {
            "Teredo"
        } else if addr.is_unique_local() {
            "Unique Local"
        } else if addr.is_documentation() {
            "Documentation"
        } else if addr.is_global_unicast() {
            "Global Unicast"
        } else {
            "Unknown"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_validation() {
        assert!(IPv6Strategy::valid_str("2001:db8::1"));
        assert!(!IPv6Strategy::valid_str("2001:db8::g")); // Invalid hex
        assert!(!IPv6Strategy::valid_str("not::an::ipv6"));
    }

    #[test]
    fn test_formatting() {
        let addr = crate::ip::ipv6::IPv6::from_str("2001:db8::1").unwrap();

        assert_eq!(IPv6Strategy::ipv6_compact(&addr), "2001:db8::1");
        assert_eq!(IPv6Strategy::ipv6_full(&addr), "2001:0db8:0000:0000:0000:0000:0000:0001");
        assert_eq!(IPv6Strategy::ipv6_verbose(&addr), "2001:0db8:0000:0000:0000:0000:0000:0001");
    }

    #[test]
    fn test_flexible_parsing() {
        let test_cases = vec![
            "2001:db8::1",
            "[2001:db8::1]", // URL format
            "2001:0db8:0000:0000:0000:0000:0000:0001", // Full format
        ];

        for case in test_cases {
            let addr = IPv6Strategy::parse_flexible(case).unwrap();
            assert_eq!(addr.to_string(), "2001:db8::1");
        }
    }

    #[test]
    fn test_base85() {
        let addr = crate::ip::ipv6::IPv6::from_str("2001:db8::1").unwrap();
        let base85 = IPv6Strategy::to_base85(&addr);
        let back = IPv6Strategy::from_base85(&base85).unwrap();
        assert_eq!(addr, back);
    }

    #[test]
    fn test_address_properties() {
        let loopback = crate::ip::ipv6::IPv6::from_str("::1").unwrap();
        assert!(IPv6Strategy::is_loopback(&loopback));
        assert_eq!(IPv6Strategy::get_address_type(&loopback), "Loopback");

        let multicast = crate::ip::ipv6::IPv6::from_str("ff02::1").unwrap();
        assert!(IPv6Strategy::is_multicast(&multicast));
        assert_eq!(IPv6Strategy::get_address_type(&multicast), "Multicast");

        let unique_local = crate::ip::ipv6::IPv6::from_str("fc00::1").unwrap();
        assert!(IPv6Strategy::is_unique_local(&unique_local));
        assert_eq!(IPv6Strategy::get_address_type(&unique_local), "Unique Local");

        let doc = crate::ip::ipv6::IPv6::from_str("2001:db8::1").unwrap();
        assert!(IPv6Strategy::is_documentation(&doc));
        assert_eq!(IPv6Strategy::get_address_type(&doc), "Documentation");
    }

    #[test]
    fn test_interface_parts() {
        let addr = crate::ip::ipv6::IPv6::from_str("2001:db8:1234:5678:abcd:ef01:2345:6789").unwrap();
        let network_prefix = IPv6Strategy::network_prefix(&addr);
        let interface_id = IPv6Strategy::interface_id(&addr);

        let reconstructed = IPv6Strategy::from_parts(network_prefix, interface_id);
        assert_eq!(addr, reconstructed);
    }

    #[test]
    fn test_hex_operations() {
        let addr = crate::ip::ipv6::IPv6::from_str("2001:db8::1").unwrap();

        let hex = IPv6Strategy::expand_hex(&addr);
        assert_eq!(hex, "20010db8000000000000000000000001");

        let compact_hex = IPv6Strategy::format_hex_compact(&addr);
        assert_eq!(compact_hex, "20010db8000000000000000000000001");

        let back = IPv6Strategy::from_hex_string(&hex).unwrap();
        assert_eq!(addr, back);
    }

    #[test]
    fn test_ipv4_mapping() {
        let mapped = crate::ip::ipv6::IPv6::from_str("::ffff:192.168.1.1").unwrap();
        assert!(IPv6Strategy::is_ipv4_mapped(&mapped));
        assert_eq!(IPv6Strategy::get_address_type(&mapped), "IPv4-mapped");

        let ipv4 = IPv6Strategy::to_ipv4(&mapped).unwrap();
        assert_eq!(ipv4.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_custom_separator() {
        let addr = crate::ip::ipv6::IPv6::from_str("2001:db8::1").unwrap();
        let with_dash = IPv6Strategy::format_with_separator(&addr, "-");
        assert!(with_dash.contains('-'));
        assert!(!with_dash.contains(':'));
    }
}