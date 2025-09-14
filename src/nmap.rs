//! Nmap-style range parsing and iteration

use crate::error::{AddrFormatError, AddrResult};
use crate::ip::{IPAddress, IPRange};
use std::str::FromStr;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    /// Regex for validating nmap-style ranges
    static ref NMAP_RANGE_REGEX: Regex = Regex::new(
        r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}(?:-\d{1,3})?(?:,\d{1,3}(?:-\d{1,3})?)*)$"
    ).unwrap();

    /// Regex for parsing octet patterns
    static ref OCTET_PATTERN_REGEX: Regex = Regex::new(
        r"^(\d{1,3})(?:-(\d{1,3}))?$"
    ).unwrap();
}

/// Nmap-style range specification for IPv4 addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmapRange {
    pattern: String,
    octets: [Vec<u8>; 4],
}

impl NmapRange {
    /// Create a new Nmap range from a pattern string
    pub fn new(pattern: &str) -> AddrResult<Self> {
        let octets = Self::parse_pattern(pattern)?;
        Ok(Self {
            pattern: pattern.to_string(),
            octets,
        })
    }

    /// Get the original pattern string
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Get the total number of addresses in this range
    pub fn size(&self) -> u64 {
        self.octets.iter()
            .map(|octet_values| octet_values.len() as u64)
            .product()
    }

    /// Check if this range contains a specific IP address
    pub fn contains(&self, addr: &IPAddress) -> bool {
        if !addr.is_ipv4() {
            return false;
        }

        let ipv4 = addr.as_ipv4().unwrap();
        let octets = ipv4.octets();

        for (i, &octet) in octets.iter().enumerate() {
            if !self.octets[i].contains(&octet) {
                return false;
            }
        }

        true
    }

    /// Convert to a list of IP ranges
    pub fn to_ranges(&self) -> AddrResult<Vec<IPRange>> {
        let addresses: Vec<IPAddress> = self.addresses().collect();
        if addresses.is_empty() {
            return Ok(Vec::new());
        }

        // Group consecutive addresses into ranges
        let mut ranges = Vec::new();
        let mut range_start = addresses[0].clone();
        let mut range_end = addresses[0].clone();

        for addr in addresses.iter().skip(1) {
            if let Some(next_expected) = range_end.next() {
                if *addr == next_expected {
                    // Extend current range
                    range_end = addr.clone();
                } else {
                    // Start new range
                    ranges.push(IPRange::new(range_start.clone(), range_end.clone())?);
                    range_start = addr.clone();
                    range_end = addr.clone();
                }
            } else {
                // Start new range (shouldn't happen with IPv4)
                ranges.push(IPRange::new(range_start.clone(), range_end.clone())?);
                range_start = addr.clone();
                range_end = addr.clone();
            }
        }

        // Add the final range
        ranges.push(IPRange::new(range_start, range_end)?);

        Ok(ranges)
    }

    /// Get all IP addresses in this range
    pub fn addresses(&self) -> NmapRangeIterator {
        NmapRangeIterator::new(self)
    }

    /// Parse the nmap pattern into octet value lists
    fn parse_pattern(pattern: &str) -> AddrResult<[Vec<u8>; 4]> {
        if !NMAP_RANGE_REGEX.is_match(pattern) {
            return Err(AddrFormatError::new("Invalid nmap range pattern"));
        }

        let parts: Vec<&str> = pattern.split('.').collect();
        if parts.len() != 4 {
            return Err(AddrFormatError::new("IPv4 range must have 4 octets"));
        }

        let mut octets = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];

        for (i, part) in parts.iter().enumerate() {
            octets[i] = Self::parse_octet_pattern(part)?;
        }

        Ok(octets)
    }

    /// Parse a single octet pattern (e.g., "1", "1-5", "1,3,5-7")
    fn parse_octet_pattern(pattern: &str) -> AddrResult<Vec<u8>> {
        let mut values = Vec::new();

        // Split by commas to handle multiple values/ranges
        for segment in pattern.split(',') {
            if segment.contains('-') {
                // Range specification (e.g., "1-5")
                let range_parts: Vec<&str> = segment.split('-').collect();
                if range_parts.len() != 2 {
                    return Err(AddrFormatError::new("Invalid range specification"));
                }

                let start = range_parts[0].parse::<u8>()
                    .map_err(|_| AddrFormatError::new("Invalid octet start value"))?;
                let end = range_parts[1].parse::<u8>()
                    .map_err(|_| AddrFormatError::new("Invalid octet end value"))?;

                if start > end {
                    return Err(AddrFormatError::new("Range start must be <= end"));
                }

                for value in start..=end {
                    if !values.contains(&value) {
                        values.push(value);
                    }
                }
            } else {
                // Single value
                let value = segment.parse::<u8>()
                    .map_err(|_| AddrFormatError::new("Invalid octet value"))?;

                if !values.contains(&value) {
                    values.push(value);
                }
            }
        }

        values.sort_unstable();
        Ok(values)
    }

    /// Get the first IP address in this range
    pub fn first(&self) -> Option<IPAddress> {
        self.addresses().next()
    }

    /// Get the last IP address in this range
    pub fn last(&self) -> Option<IPAddress> {
        let mut last = None;
        for addr in self.addresses() {
            last = Some(addr);
        }
        last
    }
}

impl FromStr for NmapRange {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        Self::new(s)
    }
}

/// Iterator over addresses in an Nmap range
pub struct NmapRangeIterator<'a> {
    range: &'a NmapRange,
    indices: [usize; 4],
    finished: bool,
}

impl<'a> NmapRangeIterator<'a> {
    fn new(range: &'a NmapRange) -> Self {
        Self {
            range,
            indices: [0, 0, 0, 0],
            finished: range.octets.iter().any(|octets| octets.is_empty()),
        }
    }
}

impl<'a> Iterator for NmapRangeIterator<'a> {
    type Item = IPAddress;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        // Create current address
        let octets = [
            self.range.octets[0][self.indices[0]],
            self.range.octets[1][self.indices[1]],
            self.range.octets[2][self.indices[2]],
            self.range.octets[3][self.indices[3]],
        ];

        let addr = IPAddress::new_v4(std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));

        // Advance indices
        self.indices[3] += 1;

        // Handle carry-over
        for i in (0..4).rev() {
            if self.indices[i] >= self.range.octets[i].len() {
                if i == 0 {
                    // Finished
                    self.finished = true;
                    break;
                } else {
                    self.indices[i] = 0;
                    self.indices[i - 1] += 1;
                }
            } else {
                break;
            }
        }

        Some(addr)
    }
}

/// Validate if a string is a valid nmap range
pub fn valid_nmap_range(s: &str) -> bool {
    NmapRange::new(s).is_ok()
}

/// Create an iterator over addresses in an nmap range
pub fn iter_nmap_range(range_str: &str) -> AddrResult<impl Iterator<Item = IPAddress> + '_> {
    let range = NmapRange::new(range_str)?;
    Ok(NmapRangeAddressIterator {
        range,
        current_indices: [0, 0, 0, 0],
        finished: false
    })
}

/// Standalone iterator for nmap ranges that owns the range
pub struct NmapRangeAddressIterator {
    range: NmapRange,
    current_indices: [usize; 4],
    finished: bool,
}

impl Iterator for NmapRangeAddressIterator {
    type Item = IPAddress;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        // Check if any octet list is empty
        if self.range.octets.iter().any(|octets| octets.is_empty()) {
            self.finished = true;
            return None;
        }

        // Create current address
        let octets = [
            self.range.octets[0][self.current_indices[0]],
            self.range.octets[1][self.current_indices[1]],
            self.range.octets[2][self.current_indices[2]],
            self.range.octets[3][self.current_indices[3]],
        ];

        let addr = IPAddress::new_v4(std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));

        // Advance indices (rightmost first)
        self.current_indices[3] += 1;

        // Handle carry-over from right to left
        for i in (0..4).rev() {
            if self.current_indices[i] >= self.range.octets[i].len() {
                if i == 0 {
                    // Finished - carried over from leftmost octet
                    self.finished = true;
                    break;
                } else {
                    // Carry to next octet
                    self.current_indices[i] = 0;
                    self.current_indices[i - 1] += 1;
                }
            } else {
                // No carry needed
                break;
            }
        }

        Some(addr)
    }
}

/// Common nmap range patterns
pub fn common_nmap_patterns() -> Vec<(&'static str, &'static str)> {
    vec![
        ("192.168.1.1-254", "Class C private network range"),
        ("10.0.0.1-255", "Class A private network (single subnet)"),
        ("172.16.0.1-255", "Class B private network (single subnet)"),
        ("192.168.1.1,5,10-20", "Specific IPs and range in subnet"),
        ("127.0.0.1", "Localhost"),
        ("0.0.0.0", "Unspecified address"),
        ("255.255.255.255", "Broadcast address"),
        ("169.254.1.1-254", "Link-local address range"),
        ("224.0.0.1-10", "Multicast range"),
        ("192.168.0-255.1", "Multiple subnets, single host"),
    ]
}

/// Expand nmap range to individual addresses (use with caution for large ranges)
pub fn expand_nmap_range(range_str: &str) -> AddrResult<Vec<IPAddress>> {
    let range = NmapRange::new(range_str)?;
    Ok(range.addresses().collect())
}

/// Convert nmap range to CIDR blocks
pub fn nmap_range_to_cidrs(range_str: &str) -> AddrResult<Vec<crate::ip::IPNetwork>> {
    let range = NmapRange::new(range_str)?;
    let ip_ranges = range.to_ranges()?;

    let mut cidrs = Vec::new();
    for ip_range in ip_ranges {
        cidrs.extend(ip_range.to_cidrs()?);
    }

    Ok(cidrs)
}

/// Get statistics about an nmap range
pub fn nmap_range_stats(range_str: &str) -> AddrResult<(u64, IPAddress, IPAddress)> {
    let range = NmapRange::new(range_str)?;
    let first = range.first().ok_or_else(|| AddrFormatError::new("Empty range"))?;
    let last = range.last().ok_or_else(|| AddrFormatError::new("Empty range"))?;
    Ok((range.size(), first, last))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nmap_range_creation() {
        let range = NmapRange::new("192.168.1.1-10").unwrap();
        assert_eq!(range.pattern(), "192.168.1.1-10");
        assert_eq!(range.size(), 10);
    }

    #[test]
    fn test_single_address() {
        let range = NmapRange::new("192.168.1.1").unwrap();
        assert_eq!(range.size(), 1);

        let addr = IPAddress::from_str("192.168.1.1").unwrap();
        assert!(range.contains(&addr));

        let other_addr = IPAddress::from_str("192.168.1.2").unwrap();
        assert!(!range.contains(&other_addr));
    }

    #[test]
    fn test_simple_range() {
        let range = NmapRange::new("192.168.1.1-5").unwrap();
        assert_eq!(range.size(), 5);

        for i in 1..=5 {
            let addr = IPAddress::from_str(&format!("192.168.1.{}", i)).unwrap();
            assert!(range.contains(&addr), "Should contain 192.168.1.{}", i);
        }

        let addr = IPAddress::from_str("192.168.1.6").unwrap();
        assert!(!range.contains(&addr));
    }

    #[test]
    fn test_comma_separated() {
        let range = NmapRange::new("192.168.1.1,3,5").unwrap();
        assert_eq!(range.size(), 3);

        assert!(range.contains(&IPAddress::from_str("192.168.1.1").unwrap()));
        assert!(range.contains(&IPAddress::from_str("192.168.1.3").unwrap()));
        assert!(range.contains(&IPAddress::from_str("192.168.1.5").unwrap()));
        assert!(!range.contains(&IPAddress::from_str("192.168.1.2").unwrap()));
        assert!(!range.contains(&IPAddress::from_str("192.168.1.4").unwrap()));
    }

    #[test]
    fn test_mixed_pattern() {
        let range = NmapRange::new("192.168.1.1,3-5,10").unwrap();
        assert_eq!(range.size(), 5); // 1, 3, 4, 5, 10

        let expected = vec![1, 3, 4, 5, 10];
        for i in expected {
            let addr = IPAddress::from_str(&format!("192.168.1.{}", i)).unwrap();
            assert!(range.contains(&addr), "Should contain 192.168.1.{}", i);
        }

        assert!(!range.contains(&IPAddress::from_str("192.168.1.2").unwrap()));
        assert!(!range.contains(&IPAddress::from_str("192.168.1.6").unwrap()));
    }

    #[test]
    fn test_multiple_octet_ranges() {
        let range = NmapRange::new("192.168.1-2.1-2").unwrap();
        assert_eq!(range.size(), 4); // 2 * 2 = 4 combinations

        let expected_addresses = vec![
            "192.168.1.1",
            "192.168.1.2",
            "192.168.2.1",
            "192.168.2.2",
        ];

        for addr_str in expected_addresses {
            let addr = IPAddress::from_str(addr_str).unwrap();
            assert!(range.contains(&addr), "Should contain {}", addr_str);
        }
    }

    #[test]
    fn test_iterator() {
        let range = NmapRange::new("192.168.1.1-3").unwrap();
        let addresses: Vec<IPAddress> = range.addresses().collect();

        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0].to_string(), "192.168.1.1");
        assert_eq!(addresses[1].to_string(), "192.168.1.2");
        assert_eq!(addresses[2].to_string(), "192.168.1.3");
    }

    #[test]
    fn test_iter_nmap_range_function() {
        let addresses: Vec<IPAddress> = iter_nmap_range("192.168.1.1-3").unwrap().collect();

        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0].to_string(), "192.168.1.1");
        assert_eq!(addresses[1].to_string(), "192.168.1.2");
        assert_eq!(addresses[2].to_string(), "192.168.1.3");
    }

    #[test]
    fn test_to_ranges() {
        let nmap_range = NmapRange::new("192.168.1.1-5").unwrap();
        let ip_ranges = nmap_range.to_ranges().unwrap();

        assert_eq!(ip_ranges.len(), 1);
        assert_eq!(ip_ranges[0].start().to_string(), "192.168.1.1");
        assert_eq!(ip_ranges[0].end().to_string(), "192.168.1.5");
    }

    #[test]
    fn test_validation() {
        assert!(valid_nmap_range("192.168.1.1"));
        assert!(valid_nmap_range("192.168.1.1-10"));
        assert!(valid_nmap_range("192.168.1.1,3,5-7"));
        assert!(valid_nmap_range("10.0.0-255.1-254"));

        assert!(!valid_nmap_range(""));
        assert!(!valid_nmap_range("not.an.ip"));
        assert!(!valid_nmap_range("192.168.1.256"));
        assert!(!valid_nmap_range("192.168.1.1-"));
        assert!(!valid_nmap_range("192.168.1.5-1")); // Invalid range (start > end)
    }

    #[test]
    fn test_first_last() {
        let range = NmapRange::new("192.168.1.5-10").unwrap();

        assert_eq!(range.first().unwrap().to_string(), "192.168.1.5");
        assert_eq!(range.last().unwrap().to_string(), "192.168.1.10");
    }

    #[test]
    fn test_expand_nmap_range() {
        let addresses = expand_nmap_range("192.168.1.1-3").unwrap();
        assert_eq!(addresses.len(), 3);

        let expected = vec!["192.168.1.1", "192.168.1.2", "192.168.1.3"];
        for (i, addr) in addresses.iter().enumerate() {
            assert_eq!(addr.to_string(), expected[i]);
        }
    }

    #[test]
    fn test_nmap_range_to_cidrs() {
        let cidrs = nmap_range_to_cidrs("192.168.1.0-255").unwrap();
        assert!(!cidrs.is_empty());

        let total_addresses: u128 = cidrs.iter().map(|c| c.num_addresses()).sum();
        assert_eq!(total_addresses, 256);
    }

    #[test]
    fn test_stats() {
        let (size, first, last) = nmap_range_stats("192.168.1.10-20").unwrap();

        assert_eq!(size, 11);
        assert_eq!(first.to_string(), "192.168.1.10");
        assert_eq!(last.to_string(), "192.168.1.20");
    }

    #[test]
    fn test_complex_pattern() {
        let range = NmapRange::new("10.0-1.0-1.1,5,10-12").unwrap();
        assert_eq!(range.size(), 2 * 2 * 5); // 2 * 2 * (1 + 1 + 3) = 20

        // Test a few specific addresses
        assert!(range.contains(&IPAddress::from_str("10.0.0.1").unwrap()));
        assert!(range.contains(&IPAddress::from_str("10.1.1.12").unwrap()));
        assert!(!range.contains(&IPAddress::from_str("10.0.0.2").unwrap()));
        assert!(!range.contains(&IPAddress::from_str("10.2.0.1").unwrap()));
    }

    #[test]
    fn test_error_cases() {
        assert!(NmapRange::new("").is_err());
        assert!(NmapRange::new("192.168.1").is_err()); // Too few octets
        assert!(NmapRange::new("192.168.1.1.1").is_err()); // Too many octets
        assert!(NmapRange::new("192.168.1.256").is_err()); // Invalid octet value
        assert!(NmapRange::new("192.168.1.5-1").is_err()); // Invalid range
    }

    #[test]
    fn test_common_patterns() {
        let patterns = common_nmap_patterns();
        assert!(!patterns.is_empty());

        // Test that all patterns are valid
        for (pattern, _description) in patterns {
            assert!(valid_nmap_range(pattern), "Pattern {} should be valid", pattern);
        }
    }

    #[test]
    fn test_ipv6_rejection() {
        let ipv6_addr = IPAddress::from_str("2001:db8::1").unwrap();
        let range = NmapRange::new("192.168.1.1-10").unwrap();

        assert!(!range.contains(&ipv6_addr));
    }
}