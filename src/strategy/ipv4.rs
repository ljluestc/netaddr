//! IPv4 parsing and formatting strategies

use crate::error::{AddrFormatError, AddrResult};
use std::str::FromStr;

/// IPv4 address parsing and formatting strategy
pub struct IPv4Strategy;

impl IPv4Strategy {
    /// Validate IPv4 string format
    pub fn valid_str(s: &str) -> bool {
        crate::ip::ipv4::IPv4::from_str(s).is_ok()
    }

    /// Expand partial IPv4 address
    pub fn expand_partial_address(s: &str) -> AddrResult<String> {
        let expanded = crate::ip::ipv4::IPv4::expand_partial(s)?;
        Ok(expanded.to_string())
    }

    /// Parse with inet_aton semantics (allowing octal and hex)
    pub fn parse_inet_aton(s: &str) -> AddrResult<crate::ip::ipv4::IPv4> {
        // Handle different formats supported by inet_aton
        if s.contains('.') {
            // Standard dotted decimal or partial
            crate::ip::ipv4::IPv4::expand_partial(s)
        } else {
            // Single number format
            let num = if s.starts_with("0x") || s.starts_with("0X") {
                // Hexadecimal
                u32::from_str_radix(&s[2..], 16)
                    .map_err(|_| AddrFormatError::new("Invalid hexadecimal number"))?
            } else if s.starts_with('0') && s.len() > 1 {
                // Octal
                u32::from_str_radix(s, 8)
                    .map_err(|_| AddrFormatError::new("Invalid octal number"))?
            } else {
                // Decimal
                s.parse::<u32>()
                    .map_err(|_| AddrFormatError::new("Invalid decimal number"))?
            };
            Ok(crate::ip::ipv4::IPv4::from_u32(num))
        }
    }

    /// Parse with inet_pton semantics (strict dotted decimal only)
    pub fn parse_inet_pton(s: &str) -> AddrResult<crate::ip::ipv4::IPv4> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err(AddrFormatError::new("IPv4 address must have exactly 4 octets"));
        }

        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            // inet_pton doesn't allow leading zeros (except for "0")
            if part.len() > 1 && part.starts_with('0') {
                return Err(AddrFormatError::new("Leading zeros not allowed in inet_pton mode"));
            }

            octets[i] = part.parse::<u8>()
                .map_err(|_| AddrFormatError::new("Invalid octet value"))?;
        }

        Ok(crate::ip::ipv4::IPv4::new(octets[0], octets[1], octets[2], octets[3]))
    }

    /// Parse with zero-fill handling
    pub fn parse_with_zerofill(s: &str) -> AddrResult<crate::ip::ipv4::IPv4> {
        crate::ip::ipv4::IPv4::parse_with_zerofill(s)
    }

    /// Format IPv4 address in dotted decimal notation
    pub fn format_dotted_decimal(addr: &crate::ip::ipv4::IPv4) -> String {
        addr.to_string()
    }

    /// Format IPv4 address as a 32-bit integer
    pub fn format_as_int(addr: &crate::ip::ipv4::IPv4) -> String {
        addr.to_u32().to_string()
    }

    /// Format IPv4 address as hexadecimal
    pub fn format_as_hex(addr: &crate::ip::ipv4::IPv4) -> String {
        format!("0x{:08x}", addr.to_u32())
    }

    /// Format IPv4 address as octal
    pub fn format_as_octal(addr: &crate::ip::ipv4::IPv4) -> String {
        format!("0{:o}", addr.to_u32())
    }

    /// Format IPv4 address as binary
    pub fn format_as_binary(addr: &crate::ip::ipv4::IPv4) -> String {
        format!("0b{:032b}", addr.to_u32())
    }

    /// Check if address is in private ranges
    pub fn is_private(addr: &crate::ip::ipv4::IPv4) -> bool {
        addr.as_ipv4_addr().is_private()
    }

    /// Check if address is in loopback range
    pub fn is_loopback(addr: &crate::ip::ipv4::IPv4) -> bool {
        addr.as_ipv4_addr().is_loopback()
    }

    /// Check if address is in link-local range
    pub fn is_link_local(addr: &crate::ip::ipv4::IPv4) -> bool {
        addr.as_ipv4_addr().is_link_local()
    }

    /// Check if address is in multicast range
    pub fn is_multicast(addr: &crate::ip::ipv4::IPv4) -> bool {
        addr.as_ipv4_addr().is_multicast()
    }

    /// Get the address class (A, B, C, D, or E)
    pub fn get_class(addr: &crate::ip::ipv4::IPv4) -> char {
        if addr.is_class_a() { 'A' }
        else if addr.is_class_b() { 'B' }
        else if addr.is_class_c() { 'C' }
        else if addr.is_class_d() { 'D' }
        else { 'E' }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation() {
        assert!(IPv4Strategy::valid_str("192.168.1.1"));
        assert!(!IPv4Strategy::valid_str("192.168.1.256"));
        assert!(!IPv4Strategy::valid_str("not.an.ip"));
    }

    #[test]
    fn test_partial_expansion() {
        assert_eq!(IPv4Strategy::expand_partial_address("192.168.1").unwrap(), "192.168.1.0");
        assert_eq!(IPv4Strategy::expand_partial_address("10").unwrap(), "10.0.0.0");
    }

    #[test]
    fn test_inet_aton_parsing() {
        let addr = IPv4Strategy::parse_inet_aton("192.168.1.1").unwrap();
        assert_eq!(addr.to_string(), "192.168.1.1");

        let addr = IPv4Strategy::parse_inet_aton("3232235777").unwrap(); // 192.168.1.1 as int
        assert_eq!(addr.to_string(), "192.168.1.1");

        let addr = IPv4Strategy::parse_inet_aton("0xC0A80101").unwrap(); // 192.168.1.1 as hex
        assert_eq!(addr.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_inet_pton_parsing() {
        let addr = IPv4Strategy::parse_inet_pton("192.168.1.1").unwrap();
        assert_eq!(addr.to_string(), "192.168.1.1");

        // Should fail with leading zeros
        assert!(IPv4Strategy::parse_inet_pton("192.168.01.1").is_err());
    }

    #[test]
    fn test_formatting() {
        let addr = crate::ip::ipv4::IPv4::new(192, 168, 1, 1);

        assert_eq!(IPv4Strategy::format_dotted_decimal(&addr), "192.168.1.1");
        assert_eq!(IPv4Strategy::format_as_int(&addr), "3232235777");
        assert_eq!(IPv4Strategy::format_as_hex(&addr), "0xc0a80101");
        assert_eq!(IPv4Strategy::format_as_octal(&addr), "030052000401");
        assert_eq!(IPv4Strategy::format_as_binary(&addr), "0b11000000101010000000000100000001");
    }

    #[test]
    fn test_properties() {
        let private_addr = crate::ip::ipv4::IPv4::new(192, 168, 1, 1);
        assert!(IPv4Strategy::is_private(&private_addr));
        assert_eq!(IPv4Strategy::get_class(&private_addr), 'C');

        let loopback_addr = crate::ip::ipv4::IPv4::new(127, 0, 0, 1);
        assert!(IPv4Strategy::is_loopback(&loopback_addr));
        assert_eq!(IPv4Strategy::get_class(&loopback_addr), 'A');

        let multicast_addr = crate::ip::ipv4::IPv4::new(224, 0, 0, 1);
        assert!(IPv4Strategy::is_multicast(&multicast_addr));
        assert_eq!(IPv4Strategy::get_class(&multicast_addr), 'D');
    }
}