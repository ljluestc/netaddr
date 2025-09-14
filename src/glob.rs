//! IP glob pattern matching functionality

use crate::error::{AddrFormatError, AddrResult};
use crate::ip::{IPAddress, IPNetwork, IPRange, IPAddressType};
use std::fmt;
use std::str::FromStr;
use regex::Regex;
use lazy_static::lazy_static;

/// IP address glob pattern for matching ranges of addresses
#[derive(Debug, Clone)]
pub struct IPGlob {
    pattern: String,
    regex: Regex,
    ip_type: IPAddressType,
}

impl IPGlob {
    /// Create a new IP glob pattern
    pub fn new(pattern: &str) -> AddrResult<Self> {
        Self::validate_pattern(pattern)?;

        let ip_type = Self::detect_ip_type(pattern)?;
        let regex = Self::pattern_to_regex(pattern, ip_type)?;

        Ok(Self {
            pattern: pattern.to_string(),
            regex,
            ip_type,
        })
    }

    /// Get the original pattern string
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Get the IP version this pattern matches
    pub fn ip_type(&self) -> IPAddressType {
        self.ip_type
    }

    /// Check if this pattern matches an IP address
    pub fn matches(&self, addr: &IPAddress) -> bool {
        if addr.ip_type() != self.ip_type {
            return false;
        }

        self.regex.is_match(&addr.to_string())
    }

    /// Convert this glob to a list of IP ranges
    pub fn to_ranges(&self) -> AddrResult<Vec<IPRange>> {
        match self.ip_type {
            IPAddressType::IPv4 => self.ipv4_glob_to_ranges(),
            IPAddressType::IPv6 => self.ipv6_glob_to_ranges(),
        }
    }

    /// Convert this glob to a list of CIDR networks
    pub fn to_cidrs(&self) -> AddrResult<Vec<IPNetwork>> {
        let ranges = self.to_ranges()?;
        let mut cidrs = Vec::new();
        for range in ranges {
            cidrs.extend(range.to_cidrs()?);
        }
        Ok(cidrs)
    }

    /// Get all IP addresses that match this pattern (use with care for large ranges)
    pub fn addresses(&self) -> AddrResult<impl Iterator<Item = IPAddress>> {
        let ranges = self.to_ranges()?;
        Ok(ranges.into_iter().flat_map(|range| range.hosts()))
    }

    /// Validate a glob pattern
    fn validate_pattern(pattern: &str) -> AddrResult<()> {
        if pattern.is_empty() {
            return Err(AddrFormatError::new("Empty glob pattern"));
        }

        // Check for valid glob characters
        let valid_chars = pattern.chars().all(|c| {
            c.is_ascii_hexdigit() || c == '*' || c == '?' || c == '.' || c == ':' || c == '-'
        });

        if !valid_chars {
            return Err(AddrFormatError::new("Invalid characters in glob pattern"));
        }

        // Basic format validation
        if pattern.contains("::") && pattern.contains('.') {
            return Err(AddrFormatError::new("Mixed IPv4/IPv6 notation not supported in globs"));
        }

        Ok(())
    }

    /// Detect IP type from pattern
    fn detect_ip_type(pattern: &str) -> AddrResult<IPAddressType> {
        if pattern.contains(':') {
            Ok(IPAddressType::IPv6)
        } else if pattern.contains('.') {
            Ok(IPAddressType::IPv4)
        } else {
            Err(AddrFormatError::new("Cannot determine IP type from pattern"))
        }
    }

    /// Convert glob pattern to regex
    fn pattern_to_regex(pattern: &str, ip_type: IPAddressType) -> AddrResult<Regex> {
        let mut regex_pattern = String::new();
        regex_pattern.push('^');

        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            match chars[i] {
                '*' => {
                    match ip_type {
                        IPAddressType::IPv4 => {
                            // * matches any sequence of digits
                            regex_pattern.push_str(r"\d+");
                        }
                        IPAddressType::IPv6 => {
                            // * matches any sequence of hex digits
                            regex_pattern.push_str(r"[0-9a-fA-F]+");
                        }
                    }
                }
                '?' => {
                    match ip_type {
                        IPAddressType::IPv4 => {
                            // ? matches a single digit
                            regex_pattern.push_str(r"\d");
                        }
                        IPAddressType::IPv6 => {
                            // ? matches a single hex digit
                            regex_pattern.push_str(r"[0-9a-fA-F]");
                        }
                    }
                }
                '.' | ':' => {
                    // Literal separators
                    regex_pattern.push('\\');
                    regex_pattern.push(chars[i]);
                }
                c if c.is_ascii_alphanumeric() => {
                    // Literal character
                    regex_pattern.push(c);
                }
                _ => {
                    return Err(AddrFormatError::new(format!("Unsupported character in pattern: {}", chars[i])));
                }
            }
            i += 1;
        }

        regex_pattern.push('$');

        Regex::new(&regex_pattern)
            .map_err(|e| AddrFormatError::new(format!("Invalid regex pattern: {}", e)))
    }

    /// Convert IPv4 glob to ranges
    fn ipv4_glob_to_ranges(&self) -> AddrResult<Vec<IPRange>> {
        // For simplicity, generate all possible combinations and test
        // In a production implementation, you'd want a more efficient approach
        let mut ranges: Vec<IPRange> = Vec::new();
        let octets = self.parse_ipv4_pattern()?;

        // Generate all combinations
        for a in &octets[0] {
            for b in &octets[1] {
                for c in &octets[2] {
                    for d in &octets[3] {
                        let addr = IPAddress::new_v4(std::net::Ipv4Addr::new(*a, *b, *c, *d));

                        if let Some(last_range) = ranges.last_mut() {
                            if let Some(next_addr) = last_range.end().next() {
                                if next_addr == addr {
                                    // Extend the last range
                                    *last_range = IPRange::new(last_range.start().clone(), addr)?;
                                    continue;
                                }
                            }
                        }

                        // Start a new range
                        ranges.push(IPRange::new(addr.clone(), addr)?);
                    }
                }
            }
        }

        // Merge adjacent ranges
        crate::ip::range::merge_ranges(&ranges)
    }

    /// Convert IPv6 glob to ranges
    fn ipv6_glob_to_ranges(&self) -> AddrResult<Vec<IPRange>> {
        // IPv6 glob to ranges is more complex due to the larger address space
        // For now, return an error suggesting to use more specific patterns
        Err(AddrFormatError::new(
            "IPv6 glob to ranges conversion not fully implemented. Use more specific patterns."
        ))
    }

    /// Parse IPv4 glob pattern into possible octet values
    fn parse_ipv4_pattern(&self) -> AddrResult<Vec<Vec<u8>>> {
        let parts: Vec<&str> = self.pattern.split('.').collect();
        if parts.len() != 4 {
            return Err(AddrFormatError::new("IPv4 pattern must have 4 octets"));
        }

        let mut octets = Vec::with_capacity(4);

        for part in parts {
            let values = self.expand_octet_pattern(part)?;
            octets.push(values);
        }

        Ok(octets)
    }

    /// Expand a single octet pattern to all possible values
    fn expand_octet_pattern(&self, pattern: &str) -> AddrResult<Vec<u8>> {
        if pattern == "*" {
            // All possible values 0-255
            return Ok((0..=255).collect());
        }

        if !pattern.contains('*') && !pattern.contains('?') {
            // Literal value
            let value = pattern.parse::<u8>()
                .map_err(|_| AddrFormatError::new("Invalid octet value"))?;
            return Ok(vec![value]);
        }

        // Pattern with wildcards
        let mut values = Vec::new();
        for i in 0..=255 {
            let test_str = i.to_string();
            if self.matches_octet_pattern(pattern, &test_str) {
                values.push(i);
            }
        }

        Ok(values)
    }

    /// Check if a string matches an octet pattern
    fn matches_octet_pattern(&self, pattern: &str, value: &str) -> bool {
        if pattern.len() != value.len() && !pattern.contains('*') {
            return false;
        }

        let pattern_chars: Vec<char> = pattern.chars().collect();
        let value_chars: Vec<char> = value.chars().collect();

        if pattern_chars.len() != value_chars.len() && !pattern.contains('*') {
            return false;
        }

        for (i, &p_char) in pattern_chars.iter().enumerate() {
            if i >= value_chars.len() {
                return false;
            }

            match p_char {
                '*' => return true, // * matches rest of string
                '?' => continue, // ? matches any single character
                c if c == value_chars[i] => continue,
                _ => return false,
            }
        }

        true
    }
}

impl FromStr for IPGlob {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        Self::new(s)
    }
}

impl PartialEq for IPGlob {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.ip_type == other.ip_type
    }
}

impl fmt::Display for IPGlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pattern)
    }
}

/// Utility functions for working with IP globs

/// Validate if a string is a valid IP glob pattern
pub fn valid_glob(pattern: &str) -> bool {
    IPGlob::new(pattern).is_ok()
}

/// Convert a CIDR network to glob patterns
pub fn cidr_to_glob(network: &IPNetwork) -> AddrResult<Vec<String>> {
    match network.ip_type() {
        IPAddressType::IPv4 => cidr_to_ipv4_globs(network),
        IPAddressType::IPv6 => cidr_to_ipv6_globs(network),
    }
}

/// Convert IPv4 CIDR to glob patterns
fn cidr_to_ipv4_globs(network: &IPNetwork) -> AddrResult<Vec<String>> {
    let network_addr = network.network_address().as_ipv4()
        .ok_or_else(|| AddrFormatError::new("Not an IPv4 network"))?;

    let octets = network_addr.octets();
    let prefix_len = network.prefix_length();

    let mut globs = Vec::new();

    // Simple approach: create globs based on prefix length
    match prefix_len {
        0..=8 => {
            globs.push("*.*.*.*".to_string());
        }
        9..=16 => {
            globs.push(format!("{}.*.*.*", octets[0]));
        }
        17..=24 => {
            globs.push(format!("{}.{}.*.*", octets[0], octets[1]));
        }
        25..=32 => {
            globs.push(format!("{}.{}.{}.*", octets[0], octets[1], octets[2]));
        }
        _ => {
            return Err(AddrFormatError::new("Invalid prefix length"));
        }
    }

    Ok(globs)
}

/// Convert IPv6 CIDR to glob patterns
fn cidr_to_ipv6_globs(_network: &IPNetwork) -> AddrResult<Vec<String>> {
    // IPv6 glob generation is complex due to address compression
    Err(AddrFormatError::new("IPv6 CIDR to glob conversion not implemented"))
}

/// Convert glob patterns to CIDR networks
pub fn glob_to_cidrs(pattern: &str) -> AddrResult<Vec<IPNetwork>> {
    let glob = IPGlob::new(pattern)?;
    glob.to_cidrs()
}

/// Convert glob pattern to IP range
pub fn glob_to_iprange(pattern: &str) -> AddrResult<Vec<IPRange>> {
    let glob = IPGlob::new(pattern)?;
    glob.to_ranges()
}

/// Convert glob pattern to tuple of (start_ip, end_ip)
pub fn glob_to_iptuple(pattern: &str) -> AddrResult<Vec<(IPAddress, IPAddress)>> {
    let ranges = glob_to_iprange(pattern)?;
    Ok(ranges.into_iter().map(|r| (r.start().clone(), r.end().clone())).collect())
}

/// Convert IP range to glob patterns
pub fn iprange_to_globs(range: &IPRange) -> AddrResult<Vec<String>> {
    match range.version() {
        4 => iprange_to_ipv4_globs(range),
        6 => iprange_to_ipv6_globs(range),
        _ => Err(AddrFormatError::new("Invalid IP version")),
    }
}

/// Convert IPv4 range to glob patterns
fn iprange_to_ipv4_globs(range: &IPRange) -> AddrResult<Vec<String>> {
    let start = range.start().as_ipv4()
        .ok_or_else(|| AddrFormatError::new("Not an IPv4 range"))?;
    let end = range.end().as_ipv4()
        .ok_or_else(|| AddrFormatError::new("Not an IPv4 range"))?;

    let start_octets = start.octets();
    let end_octets = end.octets();

    // Simple case: if only the last octet differs and it's a complete range
    if start_octets[0] == end_octets[0] &&
       start_octets[1] == end_octets[1] &&
       start_octets[2] == end_octets[2] &&
       start_octets[3] == 0 &&
       end_octets[3] == 255 {
        return Ok(vec![format!("{}.{}.{}.*", start_octets[0], start_octets[1], start_octets[2])]);
    }

    // For complex ranges, create multiple specific globs
    let mut globs = Vec::new();

    // This is a simplified implementation
    // A full implementation would handle all cases optimally
    if start == end {
        globs.push(format!("{}.{}.{}.{}", start_octets[0], start_octets[1], start_octets[2], start_octets[3]));
    } else {
        // Generate range notation (not a true glob but useful)
        globs.push(format!("{}-{}", range.start(), range.end()));
    }

    Ok(globs)
}

/// Convert IPv6 range to glob patterns
fn iprange_to_ipv6_globs(_range: &IPRange) -> AddrResult<Vec<String>> {
    Err(AddrFormatError::new("IPv6 range to glob conversion not implemented"))
}

lazy_static! {
    /// Common glob patterns
    static ref COMMON_GLOBS: Vec<(&'static str, &'static str)> = vec![
        ("*.*.*.*", "All IPv4 addresses"),
        ("10.*.*.*", "Class A private network (10.0.0.0/8)"),
        ("172.16.*.*", "Class B private network start (172.16.0.0/12)"),
        ("192.168.*.*", "Class C private network (192.168.0.0/16)"),
        ("127.*.*.*", "IPv4 loopback network (127.0.0.0/8)"),
        ("169.254.*.*", "IPv4 link-local network (169.254.0.0/16)"),
        ("224.*.*.*", "IPv4 multicast Class D (224.0.0.0/4)"),
        ("*:*:*:*:*:*:*:*", "All IPv6 addresses"),
        ("fe80:*:*:*:*:*:*:*", "IPv6 link-local addresses"),
        ("ff00:*:*:*:*:*:*:*", "IPv6 multicast addresses"),
        ("2001:db8:*:*:*:*:*:*", "IPv6 documentation network"),
    ];
}

/// Get predefined common glob patterns
pub fn common_glob_patterns() -> &'static Vec<(&'static str, &'static str)> {
    &COMMON_GLOBS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_glob_creation() {
        let glob = IPGlob::new("192.168.1.*").unwrap();
        assert_eq!(glob.pattern(), "192.168.1.*");
        assert_eq!(glob.ip_type(), IPAddressType::IPv4);
    }

    #[test]
    fn test_ipv6_glob_creation() {
        let glob = IPGlob::new("2001:db8:*:*:*:*:*:*").unwrap();
        assert_eq!(glob.pattern(), "2001:db8:*:*:*:*:*:*");
        assert_eq!(glob.ip_type(), IPAddressType::IPv6);
    }

    #[test]
    fn test_glob_validation() {
        assert!(valid_glob("192.168.1.*"));
        assert!(valid_glob("10.*.*.?"));
        assert!(valid_glob("2001:db8::*"));

        assert!(!valid_glob(""));
        assert!(!valid_glob("192.168.1.256"));
        assert!(!valid_glob("invalid pattern"));
    }

    #[test]
    fn test_ipv4_glob_matching() {
        let glob = IPGlob::new("192.168.1.*").unwrap();

        let addr1 = IPAddress::from_str("192.168.1.1").unwrap();
        let addr2 = IPAddress::from_str("192.168.1.255").unwrap();
        let addr3 = IPAddress::from_str("192.168.2.1").unwrap();

        assert!(glob.matches(&addr1));
        assert!(glob.matches(&addr2));
        assert!(!glob.matches(&addr3));
    }

    #[test]
    fn test_question_mark_pattern() {
        let glob = IPGlob::new("192.168.1.?").unwrap();

        let addr1 = IPAddress::from_str("192.168.1.1").unwrap();
        let addr2 = IPAddress::from_str("192.168.1.9").unwrap();
        let addr3 = IPAddress::from_str("192.168.1.10").unwrap(); // Two digits

        assert!(glob.matches(&addr1));
        assert!(glob.matches(&addr2));
        assert!(!glob.matches(&addr3)); // ? matches only single digit
    }

    #[test]
    fn test_cidr_to_glob() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let globs = cidr_to_glob(&network).unwrap();

        assert!(!globs.is_empty());
        assert!(globs.contains(&"192.168.1.*".to_string()));
    }

    #[test]
    fn test_glob_to_cidrs() {
        let cidrs = glob_to_cidrs("192.168.1.*").unwrap();
        assert!(!cidrs.is_empty());

        // The exact result depends on implementation, but should cover 192.168.1.0-255
        let total_addresses: u128 = cidrs.iter().map(|c| c.num_addresses()).sum();
        assert_eq!(total_addresses, 256);
    }

    #[test]
    fn test_glob_to_ranges() {
        let ranges = glob_to_iprange("192.168.1.*").unwrap();
        assert!(!ranges.is_empty());

        let total_size: u128 = ranges.iter().map(|r| r.size()).sum();
        assert_eq!(total_size, 256);
    }

    #[test]
    fn test_glob_to_iptuple() {
        let tuples = glob_to_iptuple("192.168.1.*").unwrap();
        assert!(!tuples.is_empty());

        // Should have start and end addresses
        for (start, end) in tuples {
            assert!(start <= end);
        }
    }

    #[test]
    fn test_common_patterns() {
        let patterns = common_glob_patterns();
        assert!(!patterns.is_empty());

        // Test that all common patterns are valid
        for (pattern, _description) in patterns.iter() {
            assert!(valid_glob(pattern), "Pattern {} should be valid", pattern);
        }
    }

    #[test]
    fn test_ipv4_octet_expansion() {
        let glob = IPGlob::new("192.168.1.*").unwrap();

        let values = glob.expand_octet_pattern("*").unwrap();
        assert_eq!(values.len(), 256);
        assert!(values.contains(&0));
        assert!(values.contains(&255));

        let literal = glob.expand_octet_pattern("42").unwrap();
        assert_eq!(literal, vec![42]);
    }

    #[test]
    fn test_mixed_patterns() {
        let glob = IPGlob::new("10.*.20.?").unwrap();

        let addr1 = IPAddress::from_str("10.5.20.1").unwrap();
        let addr2 = IPAddress::from_str("10.255.20.9").unwrap();
        let addr3 = IPAddress::from_str("10.1.21.1").unwrap(); // Wrong third octet

        assert!(glob.matches(&addr1));
        assert!(glob.matches(&addr2));
        assert!(!glob.matches(&addr3));
    }

    #[test]
    fn test_error_cases() {
        assert!(IPGlob::new("").is_err());
        assert!(IPGlob::new("not.an.ip.pattern").is_err());
        assert!(IPGlob::new("192.168.1").is_err()); // Too few octets
    }

    #[test]
    fn test_ipv6_basic_matching() {
        // Basic IPv6 pattern matching
        let glob = IPGlob::new("2001:db8:*:*:*:*:*:*").unwrap();

        let addr1 = IPAddress::from_str("2001:db8:1234:5678::1").unwrap();
        let addr2 = IPAddress::from_str("2001:db9::1").unwrap();

        assert!(glob.matches(&addr1));
        assert!(!glob.matches(&addr2));
    }
}