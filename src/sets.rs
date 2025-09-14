//! IP set operations - unions, intersections, and other set-based operations

use crate::error::{AddrFormatError, AddrResult};
use crate::ip::{IPAddress, IPNetwork, IPRange, IPAddressType};
use std::collections::BTreeSet;
use std::fmt;
use std::ops::{BitAnd, BitOr, BitXor, Sub};

/// A set of IP addresses and networks that supports efficient set operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPSet {
    ranges: BTreeSet<IPRange>,
}

impl IPSet {
    /// Create a new empty IP set
    pub fn new() -> Self {
        Self {
            ranges: BTreeSet::new(),
        }
    }

    /// Create an IP set from a single address
    pub fn from_address(addr: IPAddress) -> AddrResult<Self> {
        let range = IPRange::new(addr.clone(), addr)?;
        let mut set = Self::new();
        set.ranges.insert(range);
        Ok(set)
    }

    /// Create an IP set from a single network
    pub fn from_network(network: IPNetwork) -> AddrResult<Self> {
        let start = network.network_address().clone();
        let end = match network.ip_type() {
            IPAddressType::IPv4 => network.broadcast_address()?,
            IPAddressType::IPv6 => {
                network.last_host().ok_or_else(|| {
                    AddrFormatError::new("Cannot determine last address of IPv6 network")
                })?
            }
        };
        let range = IPRange::new(start, end)?;
        let mut set = Self::new();
        set.ranges.insert(range);
        Ok(set)
    }

    /// Create an IP set from a range
    pub fn from_range(range: IPRange) -> Self {
        let mut set = Self::new();
        set.ranges.insert(range);
        set
    }

    /// Create an IP set from multiple addresses
    pub fn from_addresses(addresses: &[IPAddress]) -> AddrResult<Self> {
        let mut set = Self::new();
        for addr in addresses {
            set.add_address(addr.clone())?;
        }
        Ok(set)
    }

    /// Create an IP set from multiple networks
    pub fn from_networks(networks: &[IPNetwork]) -> AddrResult<Self> {
        let mut set = Self::new();
        for network in networks {
            set.add_network(network.clone())?;
        }
        Ok(set)
    }

    /// Create an IP set from multiple ranges
    pub fn from_ranges(ranges: &[IPRange]) -> AddrResult<Self> {
        let mut set = Self::new();
        for range in ranges {
            set.add_range(range.clone())?;
        }
        Ok(set)
    }

    /// Add a single address to the set
    pub fn add_address(&mut self, addr: IPAddress) -> AddrResult<()> {
        let range = IPRange::new(addr.clone(), addr)?;
        self.add_range(range)
    }

    /// Add a network to the set
    pub fn add_network(&mut self, network: IPNetwork) -> AddrResult<()> {
        let start = network.network_address().clone();
        let end = match network.ip_type() {
            IPAddressType::IPv4 => network.broadcast_address()?,
            IPAddressType::IPv6 => {
                network.last_host().ok_or_else(|| {
                    AddrFormatError::new("Cannot determine last address of IPv6 network")
                })?
            }
        };
        let range = IPRange::new(start, end)?;
        self.add_range(range)
    }

    /// Add a range to the set
    pub fn add_range(&mut self, range: IPRange) -> AddrResult<()> {
        // Collect overlapping ranges
        let mut overlapping = Vec::new();
        let mut to_remove = Vec::new();

        for existing_range in &self.ranges {
            if existing_range.overlaps(&range) || self.ranges_adjacent(existing_range, &range) {
                overlapping.push(existing_range.clone());
                to_remove.push(existing_range.clone());
            }
        }

        // Remove overlapping ranges
        for range_to_remove in to_remove {
            self.ranges.remove(&range_to_remove);
        }

        // Merge all overlapping ranges with the new range
        let mut merged_ranges = overlapping;
        merged_ranges.push(range);

        let final_ranges = crate::ip::range::merge_ranges(&merged_ranges)?;

        // Add the merged ranges back
        for merged_range in final_ranges {
            self.ranges.insert(merged_range);
        }

        Ok(())
    }

    /// Check if two ranges are adjacent (can be merged)
    fn ranges_adjacent(&self, range1: &IPRange, range2: &IPRange) -> bool {
        if range1.version() != range2.version() {
            return false;
        }

        // Check if range1.end + 1 == range2.start or range2.end + 1 == range1.start
        if let (Some(next1), Some(next2)) = (range1.end().next(), range2.end().next()) {
            *range2.start() == next1 || *range1.start() == next2
        } else {
            false
        }
    }

    /// Remove an address from the set
    pub fn remove_address(&mut self, addr: &IPAddress) -> AddrResult<()> {
        let single_range = IPRange::new(addr.clone(), addr.clone())?;
        self.remove_range(&single_range)
    }

    /// Remove a network from the set
    pub fn remove_network(&mut self, network: &IPNetwork) -> AddrResult<()> {
        let start = network.network_address().clone();
        let end = match network.ip_type() {
            IPAddressType::IPv4 => network.broadcast_address()?,
            IPAddressType::IPv6 => {
                network.last_host().ok_or_else(|| {
                    AddrFormatError::new("Cannot determine last address of IPv6 network")
                })?
            }
        };
        let range = IPRange::new(start, end)?;
        self.remove_range(&range)
    }

    /// Remove a range from the set
    pub fn remove_range(&mut self, range_to_remove: &IPRange) -> AddrResult<()> {
        let mut new_ranges = BTreeSet::new();

        for existing_range in &self.ranges {
            if !existing_range.overlaps(range_to_remove) {
                // No overlap, keep the range as-is
                new_ranges.insert(existing_range.clone());
            } else {
                // There's overlap, need to split or exclude
                if range_to_remove.start() > existing_range.start() {
                    // Part before the removal range
                    let before_end = range_to_remove.start().prev()
                        .ok_or_else(|| AddrFormatError::new("Cannot create range before minimum address"))?;
                    let before_range = IPRange::new(existing_range.start().clone(), before_end)?;
                    new_ranges.insert(before_range);
                }

                if range_to_remove.end() < existing_range.end() {
                    // Part after the removal range
                    let after_start = range_to_remove.end().next()
                        .ok_or_else(|| AddrFormatError::new("Cannot create range after maximum address"))?;
                    let after_range = IPRange::new(after_start, existing_range.end().clone())?;
                    new_ranges.insert(after_range);
                }
            }
        }

        self.ranges = new_ranges;
        Ok(())
    }

    /// Check if the set contains an address
    pub fn contains_address(&self, addr: &IPAddress) -> bool {
        self.ranges.iter().any(|range| range.contains(addr))
    }

    /// Check if the set contains a network
    pub fn contains_network(&self, network: &IPNetwork) -> bool {
        let network_start = network.network_address();
        let network_end = match network.ip_type() {
            IPAddressType::IPv4 => {
                if let Ok(broadcast) = network.broadcast_address() {
                    broadcast
                } else {
                    return false;
                }
            }
            IPAddressType::IPv6 => {
                if let Some(last) = network.last_host() {
                    last
                } else {
                    return false;
                }
            }
        };

        self.ranges.iter().any(|range| {
            range.contains(network_start) && range.contains(&network_end)
        })
    }

    /// Check if the set contains a range
    pub fn contains_range(&self, range_to_check: &IPRange) -> bool {
        self.ranges.iter().any(|range| {
            range.contains(range_to_check.start()) && range.contains(range_to_check.end())
        })
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Get the size (number of IP addresses) in the set
    pub fn size(&self) -> u128 {
        self.ranges.iter().map(|range| range.size()).sum()
    }

    /// Get all ranges in the set
    pub fn ranges(&self) -> Vec<IPRange> {
        self.ranges.iter().cloned().collect()
    }

    /// Get all networks that represent this set
    pub fn networks(&self) -> AddrResult<Vec<IPNetwork>> {
        let mut networks = Vec::new();
        for range in &self.ranges {
            networks.extend(range.to_cidrs()?);
        }
        Ok(networks)
    }

    /// Iterate over all individual IP addresses in the set
    pub fn addresses(&self) -> impl Iterator<Item = IPAddress> + '_ {
        self.ranges.iter().flat_map(|range| range.hosts())
    }

    /// Union operation - combine two sets
    pub fn union(&self, other: &IPSet) -> AddrResult<IPSet> {
        let mut result = self.clone();
        for range in &other.ranges {
            result.add_range(range.clone())?;
        }
        Ok(result)
    }

    /// Intersection operation - find common addresses
    pub fn intersection(&self, other: &IPSet) -> AddrResult<IPSet> {
        let mut result = IPSet::new();

        for range1 in &self.ranges {
            for range2 in &other.ranges {
                if let Some(intersection) = range1.intersection(range2) {
                    result.add_range(intersection)?;
                }
            }
        }

        Ok(result)
    }

    /// Difference operation - subtract other set from this set
    pub fn difference(&self, other: &IPSet) -> AddrResult<IPSet> {
        let mut result = self.clone();
        for range in &other.ranges {
            result.remove_range(range)?;
        }
        Ok(result)
    }

    /// Symmetric difference operation - addresses in either set but not both
    pub fn symmetric_difference(&self, other: &IPSet) -> AddrResult<IPSet> {
        let union = self.union(other)?;
        let intersection = self.intersection(other)?;
        union.difference(&intersection)
    }

    /// Check if two sets are disjoint (no common addresses)
    pub fn is_disjoint(&self, other: &IPSet) -> AddrResult<bool> {
        let intersection = self.intersection(other)?;
        Ok(intersection.is_empty())
    }

    /// Check if this set is a subset of another set
    pub fn is_subset(&self, other: &IPSet) -> AddrResult<bool> {
        let difference = self.difference(other)?;
        Ok(difference.is_empty())
    }

    /// Check if this set is a superset of another set
    pub fn is_superset(&self, other: &IPSet) -> AddrResult<bool> {
        other.is_subset(self)
    }

    /// Compact the set by merging adjacent ranges
    pub fn compact(&mut self) -> AddrResult<()> {
        let ranges: Vec<_> = self.ranges.iter().cloned().collect();
        let merged = crate::ip::range::merge_ranges(&ranges)?;
        self.ranges.clear();
        for range in merged {
            self.ranges.insert(range);
        }
        Ok(())
    }

    /// Split IPv4 and IPv6 addresses into separate sets
    pub fn split_by_version(&self) -> (IPSet, IPSet) {
        let mut ipv4_set = IPSet::new();
        let mut ipv6_set = IPSet::new();

        for range in &self.ranges {
            if range.is_ipv4() {
                ipv4_set.ranges.insert(range.clone());
            } else {
                ipv6_set.ranges.insert(range.clone());
            }
        }

        (ipv4_set, ipv6_set)
    }

    /// Get the minimum address in the set
    pub fn min_address(&self) -> Option<IPAddress> {
        self.ranges.iter().map(|range| range.start()).min().cloned()
    }

    /// Get the maximum address in the set
    pub fn max_address(&self) -> Option<IPAddress> {
        self.ranges.iter().map(|range| range.end()).max().cloned()
    }
}

impl Default for IPSet {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for IPSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "IPSet([])")
        } else {
            let ranges_str: Vec<String> = self.ranges.iter().map(|r| r.to_string()).collect();
            write!(f, "IPSet([{}])", ranges_str.join(", "))
        }
    }
}

// Implement set operations using operator overloading
impl BitOr for &IPSet {
    type Output = AddrResult<IPSet>;

    fn bitor(self, rhs: &IPSet) -> Self::Output {
        self.union(rhs)
    }
}

impl BitAnd for &IPSet {
    type Output = AddrResult<IPSet>;

    fn bitand(self, rhs: &IPSet) -> Self::Output {
        self.intersection(rhs)
    }
}

impl Sub for &IPSet {
    type Output = AddrResult<IPSet>;

    fn sub(self, rhs: &IPSet) -> Self::Output {
        self.difference(rhs)
    }
}

impl BitXor for &IPSet {
    type Output = AddrResult<IPSet>;

    fn bitxor(self, rhs: &IPSet) -> Self::Output {
        self.symmetric_difference(rhs)
    }
}

/// Create an IP set from various inputs
pub trait IntoIPSet {
    fn into_ip_set(self) -> AddrResult<IPSet>;
}

impl IntoIPSet for IPAddress {
    fn into_ip_set(self) -> AddrResult<IPSet> {
        IPSet::from_address(self)
    }
}

impl IntoIPSet for IPNetwork {
    fn into_ip_set(self) -> AddrResult<IPSet> {
        IPSet::from_network(self)
    }
}

impl IntoIPSet for IPRange {
    fn into_ip_set(self) -> AddrResult<IPSet> {
        Ok(IPSet::from_range(self))
    }
}

impl IntoIPSet for Vec<IPAddress> {
    fn into_ip_set(self) -> AddrResult<IPSet> {
        IPSet::from_addresses(&self)
    }
}

impl IntoIPSet for Vec<IPNetwork> {
    fn into_ip_set(self) -> AddrResult<IPSet> {
        IPSet::from_networks(&self)
    }
}

impl IntoIPSet for Vec<IPRange> {
    fn into_ip_set(self) -> AddrResult<IPSet> {
        IPSet::from_ranges(&self)
    }
}

/// Utility functions for set operations
pub fn ip_set_union(sets: &[&IPSet]) -> AddrResult<IPSet> {
    let mut result = IPSet::new();
    for set in sets {
        result = result.union(set)?;
    }
    Ok(result)
}

pub fn ip_set_intersection(sets: &[&IPSet]) -> AddrResult<Option<IPSet>> {
    if sets.is_empty() {
        return Ok(None);
    }

    let mut result = sets[0].clone();
    for set in &sets[1..] {
        result = result.intersection(set)?;
        if result.is_empty() {
            break;
        }
    }

    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ip_set_creation() {
        let addr = IPAddress::from_str("192.168.1.1").unwrap();
        let set = IPSet::from_address(addr).unwrap();
        assert_eq!(set.size(), 1);

        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let set = IPSet::from_network(network).unwrap();
        assert_eq!(set.size(), 256);

        let range = IPRange::from_str("192.168.1.1-192.168.1.10").unwrap();
        let set = IPSet::from_range(range);
        assert_eq!(set.size(), 10);
    }

    #[test]
    fn test_ip_set_contains() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let set = IPSet::from_network(network.clone()).unwrap();

        let addr = IPAddress::from_str("192.168.1.100").unwrap();
        assert!(set.contains_address(&addr));

        let outside_addr = IPAddress::from_str("192.168.2.100").unwrap();
        assert!(!set.contains_address(&outside_addr));

        assert!(set.contains_network(&network));
    }

    #[test]
    fn test_ip_set_add_remove() {
        let mut set = IPSet::new();
        let addr = IPAddress::from_str("192.168.1.1").unwrap();

        set.add_address(addr.clone()).unwrap();
        assert!(set.contains_address(&addr));
        assert_eq!(set.size(), 1);

        set.remove_address(&addr).unwrap();
        assert!(!set.contains_address(&addr));
        assert_eq!(set.size(), 0);
    }

    #[test]
    fn test_ip_set_union() {
        let net1 = IPNetwork::from_str("192.168.1.0/25").unwrap(); // .0-.127
        let net2 = IPNetwork::from_str("192.168.1.128/25").unwrap(); // .128-.255

        let set1 = IPSet::from_network(net1).unwrap();
        let set2 = IPSet::from_network(net2).unwrap();

        let union = set1.union(&set2).unwrap();
        assert_eq!(union.size(), 256); // Full /24 network
    }

    #[test]
    fn test_ip_set_intersection() {
        let net1 = IPNetwork::from_str("192.168.1.0/24").unwrap();  // .0-.255
        let net2 = IPNetwork::from_str("192.168.1.128/25").unwrap(); // .128-.255

        let set1 = IPSet::from_network(net1).unwrap();
        let set2 = IPSet::from_network(net2).unwrap();

        let intersection = set1.intersection(&set2).unwrap();
        assert_eq!(intersection.size(), 128); // .128-.255
    }

    #[test]
    fn test_ip_set_difference() {
        let net1 = IPNetwork::from_str("192.168.1.0/24").unwrap();  // .0-.255
        let net2 = IPNetwork::from_str("192.168.1.128/25").unwrap(); // .128-.255

        let set1 = IPSet::from_network(net1).unwrap();
        let set2 = IPSet::from_network(net2).unwrap();

        let difference = set1.difference(&set2).unwrap();
        assert_eq!(difference.size(), 128); // .0-.127
    }

    #[test]
    fn test_ip_set_symmetric_difference() {
        let range1 = IPRange::from_str("192.168.1.1-192.168.1.10").unwrap();
        let range2 = IPRange::from_str("192.168.1.5-192.168.1.15").unwrap();

        let set1 = IPSet::from_range(range1);
        let set2 = IPSet::from_range(range2);

        let sym_diff = set1.symmetric_difference(&set2).unwrap();
        // Should contain 1-4 and 11-15
        assert_eq!(sym_diff.size(), 9);
    }

    #[test]
    fn test_ip_set_operators() {
        let net1 = IPNetwork::from_str("192.168.1.0/25").unwrap();
        let net2 = IPNetwork::from_str("192.168.1.128/25").unwrap();

        let set1 = IPSet::from_network(net1).unwrap();
        let set2 = IPSet::from_network(net2).unwrap();

        let union = (&set1 | &set2).unwrap();
        assert_eq!(union.size(), 256);

        let intersection = (&set1 & &set2).unwrap();
        assert!(intersection.is_empty());

        let difference = (&set1 - &set2).unwrap();
        assert_eq!(difference.size(), 128);

        let sym_diff = (&set1 ^ &set2).unwrap();
        assert_eq!(sym_diff.size(), 256);
    }

    #[test]
    fn test_ip_set_merge_adjacent() {
        let mut set = IPSet::new();

        // Add adjacent ranges that should be merged
        let range1 = IPRange::from_str("192.168.1.1-192.168.1.10").unwrap();
        let range2 = IPRange::from_str("192.168.1.11-192.168.1.20").unwrap();

        set.add_range(range1).unwrap();
        set.add_range(range2).unwrap();

        // Should be merged into one range
        assert_eq!(set.ranges().len(), 1);
        assert_eq!(set.size(), 20);
    }

    #[test]
    fn test_ip_set_split_by_version() {
        let mut set = IPSet::new();

        let ipv4_addr = IPAddress::from_str("192.168.1.1").unwrap();
        let ipv6_addr = IPAddress::from_str("2001:db8::1").unwrap();

        set.add_address(ipv4_addr).unwrap();
        set.add_address(ipv6_addr).unwrap();

        let (ipv4_set, ipv6_set) = set.split_by_version();

        assert_eq!(ipv4_set.size(), 1);
        assert_eq!(ipv6_set.size(), 1);
    }

    #[test]
    fn test_ip_set_min_max() {
        let range = IPRange::from_str("192.168.1.5-192.168.1.15").unwrap();
        let set = IPSet::from_range(range);

        assert_eq!(set.min_address().unwrap().to_string(), "192.168.1.5");
        assert_eq!(set.max_address().unwrap().to_string(), "192.168.1.15");
    }

    #[test]
    fn test_ip_set_subset_superset() {
        let large_net = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let small_net = IPNetwork::from_str("192.168.1.128/25").unwrap();

        let large_set = IPSet::from_network(large_net).unwrap();
        let small_set = IPSet::from_network(small_net).unwrap();

        assert!(small_set.is_subset(&large_set).unwrap());
        assert!(large_set.is_superset(&small_set).unwrap());
        assert!(!large_set.is_subset(&small_set).unwrap());
    }

    #[test]
    fn test_ip_set_disjoint() {
        let net1 = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let net2 = IPNetwork::from_str("192.168.2.0/24").unwrap();

        let set1 = IPSet::from_network(net1).unwrap();
        let set2 = IPSet::from_network(net2).unwrap();

        assert!(set1.is_disjoint(&set2).unwrap());
    }

    #[test]
    fn test_into_ip_set_trait() {
        let addr = IPAddress::from_str("192.168.1.1").unwrap();
        let set = addr.into_ip_set().unwrap();
        assert_eq!(set.size(), 1);

        let addresses = vec![
            IPAddress::from_str("192.168.1.1").unwrap(),
            IPAddress::from_str("192.168.1.2").unwrap(),
        ];
        let set = addresses.into_ip_set().unwrap();
        assert_eq!(set.size(), 2);
    }
}