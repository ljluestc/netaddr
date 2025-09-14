//! IP address and network operations

use crate::error::{AddrFormatError, AddrResult};
use crate::ip::{IPAddress, IPNetwork, IPRange};
use std::collections::HashSet;
use std::str::FromStr;

/// Find all matching CIDRs that contain the given IP address
pub fn all_matching_cidrs(
    address: &IPAddress,
    cidrs: &[IPNetwork],
) -> Vec<IPNetwork> {
    cidrs
        .iter()
        .filter(|cidr| cidr.contains(address))
        .cloned()
        .collect()
}

/// Find the largest CIDR block that contains the given IP address
pub fn largest_matching_cidr(
    address: &IPAddress,
    cidrs: &[IPNetwork],
) -> Option<IPNetwork> {
    cidrs
        .iter()
        .filter(|cidr| cidr.contains(address))
        .min_by_key(|cidr| cidr.prefix_length())
        .cloned()
}

/// Find the smallest CIDR block that contains the given IP address
pub fn smallest_matching_cidr(
    address: &IPAddress,
    cidrs: &[IPNetwork],
) -> Option<IPNetwork> {
    cidrs
        .iter()
        .filter(|cidr| cidr.contains(address))
        .max_by_key(|cidr| cidr.prefix_length())
        .cloned()
}

/// Find the smallest CIDR block that spans all given IP addresses
pub fn spanning_cidr(addresses: &[IPAddress]) -> AddrResult<Option<IPNetwork>> {
    if addresses.is_empty() {
        return Ok(None);
    }

    if addresses.len() == 1 {
        let addr = &addresses[0];
        let prefix_len = match addr.ip_type() {
            crate::ip::IPAddressType::IPv4 => 32,
            crate::ip::IPAddressType::IPv6 => 128,
        };
        return Ok(Some(IPNetwork::new(addr.clone(), prefix_len)?));
    }

    // Check all addresses are same IP version
    let first_version = addresses[0].ip_type();
    if !addresses.iter().all(|addr| addr.ip_type() == first_version) {
        return Err(AddrFormatError::new("All addresses must be the same IP version"));
    }

    // Find min and max addresses
    let min_addr = addresses.iter().min().unwrap();
    let max_addr = addresses.iter().max().unwrap();

    // Find the network that spans from min to max
    match first_version {
        crate::ip::IPAddressType::IPv4 => {
            let min_u32 = u32::from(*min_addr.as_ipv4().unwrap());
            let max_u32 = u32::from(*max_addr.as_ipv4().unwrap());
            let xor = min_u32 ^ max_u32;
            let prefix_len = if xor == 0 { 32 } else { 32 - (32 - xor.leading_zeros()) as u8 };

            let network_mask = (!0u32) << (32 - prefix_len);
            let network_addr = min_u32 & network_mask;
            let network_ip = IPAddress::new_v4(std::net::Ipv4Addr::from(network_addr));

            Ok(Some(IPNetwork::new(network_ip, prefix_len)?))
        }
        crate::ip::IPAddressType::IPv6 => {
            let min_u128 = u128::from(*min_addr.as_ipv6().unwrap());
            let max_u128 = u128::from(*max_addr.as_ipv6().unwrap());
            let xor = min_u128 ^ max_u128;
            let prefix_len = if xor == 0 { 128 } else { 128 - (128 - xor.leading_zeros()) as u8 };

            let shift = 128 - prefix_len;
            let network_mask = if shift >= 128 { 0 } else { !((1u128 << shift) - 1) };
            let network_addr = min_u128 & network_mask;
            let network_ip = IPAddress::new_v6(std::net::Ipv6Addr::from(network_addr));

            Ok(Some(IPNetwork::new(network_ip, prefix_len)?))
        }
    }
}

/// Convert CIDR notation from abbreviated to verbose form
pub fn cidr_abbrev_to_verbose(cidr_str: &str) -> AddrResult<String> {
    let network = IPNetwork::from_str(cidr_str)?;
    let netmask = network.netmask()?;
    Ok(format!("{}/{}", network.network_address(), netmask))
}

/// Exclude one CIDR block from another, returning the remaining blocks
pub fn cidr_exclude(
    base: &IPNetwork,
    exclude: &IPNetwork,
) -> AddrResult<Vec<IPNetwork>> {
    // If they don't overlap, return the base unchanged
    if !base.overlaps(exclude) {
        return Ok(vec![base.clone()]);
    }

    // If exclude completely contains base, return empty
    if exclude.contains_network(base) {
        return Ok(Vec::new());
    }

    // If base completely contains exclude, we need to split
    if base.contains_network(exclude) {
        return split_network_exclude(base, exclude);
    }

    // Partial overlap case
    let mut result = Vec::new();

    // Find the overlapping part and the non-overlapping parts
    let base_range = IPRange::new(
        base.network_address().clone(),
        base.last_host().unwrap_or_else(|| base.network_address().clone()),
    )?;

    let exclude_range = IPRange::new(
        exclude.network_address().clone(),
        exclude.last_host().unwrap_or_else(|| exclude.network_address().clone()),
    )?;

    if let Some(intersection) = base_range.intersection(&exclude_range) {
        // Add the parts before and after the intersection
        if base_range.start() < intersection.start() {
            let before_end = intersection.start().prev().unwrap();
            let before_range = IPRange::new(base_range.start().clone(), before_end)?;
            result.extend(before_range.to_cidrs()?);
        }

        if intersection.end() < base_range.end() {
            let after_start = intersection.end().next().unwrap();
            let after_range = IPRange::new(after_start, base_range.end().clone())?;
            result.extend(after_range.to_cidrs()?);
        }
    }

    Ok(result)
}

/// Split a network to exclude a contained subnet
fn split_network_exclude(
    base: &IPNetwork,
    exclude: &IPNetwork,
) -> AddrResult<Vec<IPNetwork>> {
    let mut result = Vec::new();
    let mut queue = vec![base.clone()];

    while let Some(current) = queue.pop() {
        if !current.overlaps(exclude) {
            result.push(current);
            continue;
        }

        if exclude.contains_network(&current) {
            // Skip this network entirely
            continue;
        }

        if current.prefix_length() >= exclude.prefix_length() {
            // Can't split further in a meaningful way
            if current != *exclude {
                result.push(current);
            }
            continue;
        }

        // Split current network into two halves
        let subnets = current.subnets(current.prefix_length() + 1)?;
        if subnets.len() == 2 {
            queue.extend(subnets);
        }
    }

    Ok(result)
}

/// Merge adjacent and overlapping CIDR blocks
pub fn cidr_merge(cidrs: &[IPNetwork]) -> AddrResult<Vec<IPNetwork>> {
    if cidrs.is_empty() {
        return Ok(Vec::new());
    }

    // Convert to ranges, merge them, then back to CIDRs
    let mut ranges = Vec::new();
    for cidr in cidrs {
        let start = cidr.network_address().clone();
        let end = match cidr.ip_type() {
            crate::ip::IPAddressType::IPv4 => cidr.broadcast_address()?,
            crate::ip::IPAddressType::IPv6 => {
                cidr.last_host().ok_or_else(|| {
                    AddrFormatError::new("Cannot determine last address")
                })?
            }
        };
        ranges.push(IPRange::new(start, end)?);
    }

    let merged_ranges = crate::ip::range::merge_ranges(&ranges)?;

    // Convert back to CIDRs
    let mut result = Vec::new();
    for range in merged_ranges {
        result.extend(range.to_cidrs()?);
    }

    Ok(result)
}

/// Convert IP ranges to CIDR blocks
pub fn iprange_to_cidrs(ranges: &[IPRange]) -> AddrResult<Vec<IPNetwork>> {
    let mut result = Vec::new();
    for range in ranges {
        result.extend(range.to_cidrs()?);
    }
    Ok(result)
}

/// Iterate over an IP range
pub fn iter_iprange(range: &IPRange) -> impl Iterator<Item = IPAddress> {
    range.hosts()
}

/// Iterate over unique IPs from multiple sources
pub fn iter_unique_ips<I>(sources: I) -> impl Iterator<Item = IPAddress>
where
    I: IntoIterator<Item = IPAddress>,
{
    let mut seen = HashSet::new();
    sources.into_iter().filter(move |ip| seen.insert(ip.clone()))
}

/// Expand partial IPv4 address strings
pub fn expand_partial_ipv4_address(partial: &str) -> AddrResult<IPAddress> {
    crate::ip::ipv4::IPv4::expand_partial(partial)
        .map(|ipv4| IPAddress::from(std::net::Ipv4Addr::from(ipv4)))
}

/// Validate IPv4 string
pub fn valid_ipv4(s: &str) -> bool {
    crate::ip::ipv4::IPv4::from_str(s).is_ok()
}

/// Validate IPv6 string
pub fn valid_ipv6(s: &str) -> bool {
    crate::ip::ipv6::IPv6::from_str(s).is_ok()
}

/// Format IPv6 in compact form
pub fn ipv6_compact(addr: &IPAddress) -> AddrResult<String> {
    if let Some(ipv6_addr) = addr.as_ipv6() {
        Ok(ipv6_addr.to_string())
    } else {
        Err(AddrFormatError::new("Address is not IPv6"))
    }
}

/// Format IPv6 in full form
pub fn ipv6_full(addr: &IPAddress) -> AddrResult<String> {
    if let Some(ipv6_addr) = addr.as_ipv6() {
        let ipv6 = crate::ip::ipv6::IPv6::from(*ipv6_addr);
        Ok(ipv6.full())
    } else {
        Err(AddrFormatError::new("Address is not IPv6"))
    }
}

/// Format IPv6 in verbose form (same as full)
pub fn ipv6_verbose(addr: &IPAddress) -> AddrResult<String> {
    ipv6_full(addr)
}

/// Convert IPv6 to Base85 representation (RFC 1924)
pub fn ipv6_to_base85(addr: &IPAddress) -> AddrResult<String> {
    if let Some(ipv6_addr) = addr.as_ipv6() {
        let ipv6 = crate::ip::ipv6::IPv6::from(*ipv6_addr);
        Ok(crate::ip::ipv6::Base85::encode(&ipv6))
    } else {
        Err(AddrFormatError::new("Address is not IPv6"))
    }
}

/// Convert Base85 representation to IPv6 (RFC 1924)
pub fn base85_to_ipv6(s: &str) -> AddrResult<IPAddress> {
    let ipv6 = crate::ip::ipv6::Base85::decode(s)?;
    Ok(IPAddress::from(std::net::Ipv6Addr::from(ipv6)))
}

/// Generate supernets from a list of networks
pub fn supernets(networks: &[IPNetwork]) -> AddrResult<Vec<IPNetwork>> {
    let mut result = HashSet::new();

    for network in networks {
        if let Some(supernet) = network.supernet() {
            result.insert(supernet);
        }
    }

    Ok(result.into_iter().collect())
}

/// Generate all possible subnets of a given network
pub fn all_subnets(
    network: &IPNetwork,
    min_prefix_len: u8,
    max_prefix_len: u8,
) -> AddrResult<Vec<IPNetwork>> {
    let mut result = Vec::new();

    for prefix_len in (network.prefix_length() + 1)..=max_prefix_len.min(
        match network.ip_type() {
            crate::ip::IPAddressType::IPv4 => 32,
            crate::ip::IPAddressType::IPv6 => 128,
        }
    ) {
        if prefix_len >= min_prefix_len {
            result.extend(network.subnets(prefix_len)?);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_spanning_cidr() {
        let addresses = vec![
            IPAddress::from_str("192.168.1.1").unwrap(),
            IPAddress::from_str("192.168.1.100").unwrap(),
            IPAddress::from_str("192.168.1.200").unwrap(),
        ];

        let span = spanning_cidr(&addresses).unwrap().unwrap();
        assert_eq!(span.to_string(), "192.168.1.0/24");

        for addr in &addresses {
            assert!(span.contains(addr));
        }
    }

    #[test]
    fn test_cidr_matching() {
        let address = IPAddress::from_str("192.168.1.100").unwrap();
        let cidrs = vec![
            IPNetwork::from_str("192.168.0.0/16").unwrap(),
            IPNetwork::from_str("192.168.1.0/24").unwrap(),
            IPNetwork::from_str("192.168.1.96/27").unwrap(),
            IPNetwork::from_str("10.0.0.0/8").unwrap(),
        ];

        let matching = all_matching_cidrs(&address, &cidrs);
        assert_eq!(matching.len(), 3);

        let largest = largest_matching_cidr(&address, &cidrs).unwrap();
        assert_eq!(largest.prefix_length(), 16);

        let smallest = smallest_matching_cidr(&address, &cidrs).unwrap();
        assert_eq!(smallest.prefix_length(), 27);
    }

    #[test]
    fn test_cidr_exclude() {
        let base = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let exclude = IPNetwork::from_str("192.168.1.128/25").unwrap();

        let remaining = cidr_exclude(&base, &exclude).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].to_string(), "192.168.1.0/25");
    }

    #[test]
    fn test_cidr_merge() {
        let cidrs = vec![
            IPNetwork::from_str("192.168.1.0/26").unwrap(),
            IPNetwork::from_str("192.168.1.64/26").unwrap(),
            IPNetwork::from_str("192.168.1.128/26").unwrap(),
            IPNetwork::from_str("192.168.1.192/26").unwrap(),
        ];

        let merged = cidr_merge(&cidrs).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_ipv6_operations() {
        let addr = IPAddress::from_str("2001:db8::1").unwrap();

        let compact = ipv6_compact(&addr).unwrap();
        assert_eq!(compact, "2001:db8::1");

        let full = ipv6_full(&addr).unwrap();
        assert_eq!(full, "2001:0db8:0000:0000:0000:0000:0000:0001");

        let base85 = ipv6_to_base85(&addr).unwrap();
        let back = base85_to_ipv6(&base85).unwrap();
        assert_eq!(addr, back);
    }

    #[test]
    fn test_validation() {
        assert!(valid_ipv4("192.168.1.1"));
        assert!(!valid_ipv4("192.168.1.256"));
        assert!(!valid_ipv4("not.an.ip.address"));

        assert!(valid_ipv6("2001:db8::1"));
        assert!(!valid_ipv6("2001:db8::g"));
        assert!(!valid_ipv6("not::an::ipv6"));
    }

    #[test]
    fn test_partial_ipv4_expansion() {
        let expanded = expand_partial_ipv4_address("192.168.1").unwrap();
        assert_eq!(expanded.to_string(), "192.168.1.0");

        let expanded = expand_partial_ipv4_address("10").unwrap();
        assert_eq!(expanded.to_string(), "10.0.0.0");
    }

    #[test]
    fn test_unique_iteration() {
        let addresses = vec![
            IPAddress::from_str("192.168.1.1").unwrap(),
            IPAddress::from_str("192.168.1.2").unwrap(),
            IPAddress::from_str("192.168.1.1").unwrap(), // Duplicate
            IPAddress::from_str("192.168.1.3").unwrap(),
        ];

        let unique: Vec<_> = iter_unique_ips(addresses).collect();
        assert_eq!(unique.len(), 3);
    }
}