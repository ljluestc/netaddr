//! IP Range implementation for arbitrary ranges

use crate::error::{AddrFormatError, AddrResult};
use crate::ip::{IPAddress, IPAddressType, IPNetwork};
use std::fmt;
use std::str::FromStr;

/// Represents an arbitrary range of IP addresses
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IPRange {
    start: IPAddress,
    end: IPAddress,
}

impl IPRange {
    /// Create a new IP range
    pub fn new(start: IPAddress, end: IPAddress) -> AddrResult<Self> {
        if start.ip_type() != end.ip_type() {
            return Err(AddrFormatError::new(
                "Start and end addresses must be the same IP version"
            ));
        }

        if start > end {
            return Err(AddrFormatError::new(
                "Start address must be less than or equal to end address"
            ));
        }

        Ok(Self { start, end })
    }

    /// Get the start address
    pub fn start(&self) -> &IPAddress {
        &self.start
    }

    /// Get the end address
    pub fn end(&self) -> &IPAddress {
        &self.end
    }

    /// Get the IP version (4 or 6)
    pub fn version(&self) -> u8 {
        self.start.version()
    }

    /// Check if this is an IPv4 range
    pub fn is_ipv4(&self) -> bool {
        self.start.is_ipv4()
    }

    /// Check if this is an IPv6 range
    pub fn is_ipv6(&self) -> bool {
        self.start.is_ipv6()
    }

    /// Check if an IP address is contained in this range
    pub fn contains(&self, addr: &IPAddress) -> bool {
        if self.start.ip_type() != addr.ip_type() {
            return false;
        }

        *addr >= self.start && *addr <= self.end
    }

    /// Get the number of addresses in this range
    pub fn size(&self) -> u128 {
        match (self.start.as_ip_addr(), self.end.as_ip_addr()) {
            (std::net::IpAddr::V4(start), std::net::IpAddr::V4(end)) => {
                let start_u32 = u32::from(*start);
                let end_u32 = u32::from(*end);
                (end_u32 - start_u32 + 1) as u128
            }
            (std::net::IpAddr::V6(start), std::net::IpAddr::V6(end)) => {
                let start_u128 = u128::from(*start);
                let end_u128 = u128::from(*end);
                end_u128 - start_u128 + 1
            }
            _ => unreachable!("Different IP versions should be caught in constructor"),
        }
    }

    /// Check if this range overlaps with another range
    pub fn overlaps(&self, other: &IPRange) -> bool {
        if self.start.ip_type() != other.start.ip_type() {
            return false;
        }

        self.start <= other.end && other.start <= self.end
    }

    /// Get the intersection of this range with another range
    pub fn intersection(&self, other: &IPRange) -> Option<IPRange> {
        if !self.overlaps(other) {
            return None;
        }

        let start = std::cmp::max(&self.start, &other.start).clone();
        let end = std::cmp::min(&self.end, &other.end).clone();

        IPRange::new(start, end).ok()
    }

    /// Convert this range to a list of CIDR blocks
    pub fn to_cidrs(&self) -> AddrResult<Vec<IPNetwork>> {
        let mut cidrs = Vec::new();

        match (self.start.as_ip_addr(), self.end.as_ip_addr()) {
            (std::net::IpAddr::V4(start), std::net::IpAddr::V4(end)) => {
                let mut current = u32::from(*start);
                let end_u32 = u32::from(*end);

                while current <= end_u32 {
                    let maxsize = Self::maxblock_ipv4(current, end_u32 - current + 1);
                    let maxblock = Self::largest_power_of_2_le(maxsize);
                    let prefix_len = 32 - (maxblock.trailing_zeros() as u8);

                    let network_addr = IPAddress::new_v4(std::net::Ipv4Addr::from(current));
                    let network = IPNetwork::new(network_addr, prefix_len)?;
                    cidrs.push(network);

                    current += maxblock;
                    if current == 0 {
                        break; // Overflow protection
                    }
                }
            }
            (std::net::IpAddr::V6(start), std::net::IpAddr::V6(end)) => {
                let mut current = u128::from(*start);
                let end_u128 = u128::from(*end);

                while current <= end_u128 {
                    let remaining = end_u128 - current + 1;
                    let maxblock = Self::largest_power_of_2_le_u128(remaining);
                    let prefix_len = 128 - (maxblock.trailing_zeros() as u8);

                    // Align to block boundary if needed
                    let aligned_current = current & !(maxblock - 1);
                    if aligned_current != current {
                        let smaller_block = Self::largest_power_of_2_le_u128(current - aligned_current);
                        let smaller_prefix = 128 - (smaller_block.trailing_zeros() as u8);

                        let network_addr = IPAddress::new_v6(std::net::Ipv6Addr::from(current));
                        let network = IPNetwork::new(network_addr, smaller_prefix)?;
                        cidrs.push(network);

                        current += smaller_block;
                        continue;
                    }

                    let network_addr = IPAddress::new_v6(std::net::Ipv6Addr::from(current));
                    let network = IPNetwork::new(network_addr, prefix_len)?;
                    cidrs.push(network);

                    current += maxblock;
                    if current == 0 {
                        break; // Overflow protection
                    }
                }
            }
            _ => unreachable!(),
        }

        Ok(cidrs)
    }

    /// Get an iterator over all IP addresses in this range
    pub fn hosts(&self) -> RangeHostIterator {
        RangeHostIterator::new(self)
    }

    /// Calculate maximum block size for IPv4
    fn maxblock_ipv4(address: u32, max_size: u32) -> u32 {
        let mut maxsize = 1;

        // Find the largest power of 2 that:
        // 1. Is <= max_size
        // 2. Address is aligned to it
        while maxsize <= max_size && (address & (maxsize - 1)) == 0 {
            maxsize <<= 1;
        }

        maxsize >> 1
    }

    /// Find the largest power of 2 that is <= n
    fn largest_power_of_2_le(n: u32) -> u32 {
        if n == 0 {
            return 0;
        }

        let mut power = 1;
        while power <= n {
            power <<= 1;
        }
        power >> 1
    }

    /// Find the largest power of 2 that is <= n (u128 version)
    fn largest_power_of_2_le_u128(n: u128) -> u128 {
        if n == 0 {
            return 0;
        }

        let mut power = 1;
        while power <= n {
            power <<= 1;
        }
        power >> 1
    }

    /// Create a range from a hyphen-separated string (e.g., "192.168.1.1-192.168.1.10")
    pub fn from_hyphen_string(s: &str) -> AddrResult<Self> {
        let parts: Vec<&str> = s.split('-').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return Err(AddrFormatError::new(
                "Range must be in format 'start-end'"
            ));
        }

        let start = IPAddress::from_str(parts[0])?;
        let end = IPAddress::from_str(parts[1])?;

        IPRange::new(start, end)
    }

    /// Check if this range represents a single address
    pub fn is_single_address(&self) -> bool {
        self.start == self.end
    }

    /// Split this range at a given address
    pub fn split_at(&self, addr: &IPAddress) -> AddrResult<(Option<IPRange>, Option<IPRange>)> {
        if !self.contains(addr) {
            return Err(AddrFormatError::new(
                "Split address must be within the range"
            ));
        }

        let left = if *addr == self.start {
            None
        } else {
            let prev = addr.prev().ok_or_else(|| {
                AddrFormatError::new("Cannot split at the minimum address")
            })?;
            Some(IPRange::new(self.start.clone(), prev)?)
        };

        let right = if *addr == self.end {
            None
        } else {
            let next = addr.next().ok_or_else(|| {
                AddrFormatError::new("Cannot split at the maximum address")
            })?;
            Some(IPRange::new(next, self.end.clone())?)
        };

        Ok((left, right))
    }
}

impl FromStr for IPRange {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        Self::from_hyphen_string(s)
    }
}

impl fmt::Display for IPRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl PartialOrd for IPRange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IPRange {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.start.cmp(&other.start) {
            std::cmp::Ordering::Equal => self.end.cmp(&other.end),
            other => other,
        }
    }
}

/// Iterator over host addresses in a range
pub struct RangeHostIterator {
    current: Option<IPAddress>,
    end: IPAddress,
    finished: bool,
}

impl RangeHostIterator {
    fn new(range: &IPRange) -> Self {
        Self {
            current: Some(range.start.clone()),
            end: range.end.clone(),
            finished: false,
        }
    }
}

impl Iterator for RangeHostIterator {
    type Item = IPAddress;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let current = self.current.as_ref()?;

        let result = current.clone();

        if current == &self.end {
            self.finished = true;
        } else {
            self.current = current.next();
            if self.current.is_none() {
                self.finished = true;
            }
        }

        Some(result)
    }
}

/// Convert a list of CIDR blocks to a list of IP ranges
pub fn cidrs_to_ranges(cidrs: &[IPNetwork]) -> AddrResult<Vec<IPRange>> {
    let mut ranges: Vec<IPRange> = Vec::new();

    for cidr in cidrs {
        let start = cidr.network_address().clone();
        let end = match cidr.ip_type() {
            IPAddressType::IPv4 => {
                cidr.broadcast_address()?
            }
            IPAddressType::IPv6 => {
                cidr.last_host().ok_or_else(|| {
                    AddrFormatError::new("Cannot determine last address of IPv6 network")
                })?
            }
        };

        ranges.push(IPRange::new(start, end)?);
    }

    Ok(ranges)
}

/// Merge overlapping or adjacent IP ranges
pub fn merge_ranges(ranges: &[IPRange]) -> AddrResult<Vec<IPRange>> {
    if ranges.is_empty() {
        return Ok(Vec::new());
    }

    // Separate IPv4 and IPv6 ranges
    let mut ipv4_ranges: Vec<_> = ranges.iter().filter(|r| r.is_ipv4()).cloned().collect();
    let mut ipv6_ranges: Vec<_> = ranges.iter().filter(|r| r.is_ipv6()).cloned().collect();

    // Sort ranges
    ipv4_ranges.sort();
    ipv6_ranges.sort();

    let mut merged = Vec::new();

    // Merge IPv4 ranges
    if !ipv4_ranges.is_empty() {
        let mut current = ipv4_ranges[0].clone();

        for range in ipv4_ranges.into_iter().skip(1) {
            // Check if ranges are adjacent or overlapping
            let current_end_next = current.end.next();

            if range.start <= current.end || Some(range.start.clone()) == current_end_next {
                // Merge ranges
                if range.end > current.end {
                    current = IPRange::new(current.start, range.end)?;
                }
            } else {
                // Ranges don't overlap, add current and start new
                merged.push(current);
                current = range;
            }
        }
        merged.push(current);
    }

    // Merge IPv6 ranges
    if !ipv6_ranges.is_empty() {
        let mut current = ipv6_ranges[0].clone();

        for range in ipv6_ranges.into_iter().skip(1) {
            // Check if ranges are adjacent or overlapping
            let current_end_next = current.end.next();

            if range.start <= current.end || Some(range.start.clone()) == current_end_next {
                // Merge ranges
                if range.end > current.end {
                    current = IPRange::new(current.start, range.end)?;
                }
            } else {
                // Ranges don't overlap, add current and start new
                merged.push(current);
                current = range;
            }
        }
        merged.push(current);
    }

    merged.sort();
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_creation() {
        let start = IPAddress::from_str("192.168.1.1").unwrap();
        let end = IPAddress::from_str("192.168.1.10").unwrap();
        let range = IPRange::new(start, end).unwrap();

        assert_eq!(range.start().to_string(), "192.168.1.1");
        assert_eq!(range.end().to_string(), "192.168.1.10");
        assert!(range.is_ipv4());
    }

    #[test]
    fn test_range_from_string() {
        let range = IPRange::from_str("192.168.1.1-192.168.1.10").unwrap();
        assert_eq!(range.start().to_string(), "192.168.1.1");
        assert_eq!(range.end().to_string(), "192.168.1.10");
    }

    #[test]
    fn test_range_contains() {
        let range = IPRange::from_str("192.168.1.1-192.168.1.10").unwrap();
        let addr = IPAddress::from_str("192.168.1.5").unwrap();
        let outside_addr = IPAddress::from_str("192.168.1.20").unwrap();

        assert!(range.contains(&addr));
        assert!(!range.contains(&outside_addr));
    }

    #[test]
    fn test_range_size() {
        let range = IPRange::from_str("192.168.1.1-192.168.1.10").unwrap();
        assert_eq!(range.size(), 10);

        let single = IPRange::from_str("192.168.1.1-192.168.1.1").unwrap();
        assert_eq!(single.size(), 1);
        assert!(single.is_single_address());
    }

    #[test]
    fn test_range_overlap() {
        let range1 = IPRange::from_str("192.168.1.1-192.168.1.10").unwrap();
        let range2 = IPRange::from_str("192.168.1.5-192.168.1.15").unwrap();
        let range3 = IPRange::from_str("192.168.1.20-192.168.1.30").unwrap();

        assert!(range1.overlaps(&range2));
        assert!(!range1.overlaps(&range3));

        let intersection = range1.intersection(&range2).unwrap();
        assert_eq!(intersection.start().to_string(), "192.168.1.5");
        assert_eq!(intersection.end().to_string(), "192.168.1.10");
    }

    #[test]
    fn test_range_to_cidrs() {
        let range = IPRange::from_str("192.168.1.0-192.168.1.255").unwrap();
        let cidrs = range.to_cidrs().unwrap();
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].to_string(), "192.168.1.0/24");

        let range = IPRange::from_str("192.168.1.1-192.168.1.10").unwrap();
        let cidrs = range.to_cidrs().unwrap();
        assert!(cidrs.len() > 1); // Should be broken into multiple CIDRs
    }

    #[test]
    fn test_range_iterator() {
        let range = IPRange::from_str("192.168.1.1-192.168.1.3").unwrap();
        let hosts: Vec<IPAddress> = range.hosts().collect();
        assert_eq!(hosts.len(), 3);
        assert_eq!(hosts[0].to_string(), "192.168.1.1");
        assert_eq!(hosts[1].to_string(), "192.168.1.2");
        assert_eq!(hosts[2].to_string(), "192.168.1.3");
    }

    #[test]
    fn test_range_split() {
        let range = IPRange::from_str("192.168.1.1-192.168.1.10").unwrap();
        let split_addr = IPAddress::from_str("192.168.1.5").unwrap();
        let (left, right) = range.split_at(&split_addr).unwrap();

        let left = left.unwrap();
        let right = right.unwrap();

        assert_eq!(left.end().to_string(), "192.168.1.4");
        assert_eq!(right.start().to_string(), "192.168.1.6");
    }

    #[test]
    fn test_merge_ranges() {
        let ranges = vec![
            IPRange::from_str("192.168.1.1-192.168.1.5").unwrap(),
            IPRange::from_str("192.168.1.6-192.168.1.10").unwrap(), // Adjacent
            IPRange::from_str("192.168.1.15-192.168.1.20").unwrap(),
            IPRange::from_str("192.168.1.18-192.168.1.25").unwrap(), // Overlapping
        ];

        let merged = merge_ranges(&ranges).unwrap();
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].to_string(), "192.168.1.1-192.168.1.10");
        assert_eq!(merged[1].to_string(), "192.168.1.15-192.168.1.25");
    }

    #[test]
    fn test_ipv6_range() {
        let range = IPRange::from_str("2001:db8::1-2001:db8::10").unwrap();
        assert!(range.is_ipv6());
        assert_eq!(range.size(), 16);

        let addr = IPAddress::from_str("2001:db8::5").unwrap();
        assert!(range.contains(&addr));
    }
}