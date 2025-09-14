//! IP Network (CIDR) implementation

use crate::error::{AddrFormatError, AddrResult};
use crate::ip::{IPAddress, IPAddressType};
use std::fmt;
use std::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Represents an IP network with CIDR notation (e.g., 192.168.1.0/24)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IPNetwork {
    network_address: IPAddress,
    prefix_length: u8,
}

impl IPNetwork {
    /// Create a new IP network
    pub fn new(network_address: IPAddress, prefix_length: u8) -> AddrResult<Self> {
        let max_prefix = match network_address.ip_type() {
            IPAddressType::IPv4 => 32,
            IPAddressType::IPv6 => 128,
        };

        if prefix_length > max_prefix {
            return Err(AddrFormatError::new(format!(
                "Invalid prefix length {} for {} address",
                prefix_length,
                match network_address.ip_type() {
                    IPAddressType::IPv4 => "IPv4",
                    IPAddressType::IPv6 => "IPv6",
                }
            )));
        }

        // Normalize network address (clear host bits)
        let normalized_network = Self::normalize_network_address(&network_address, prefix_length)?;

        Ok(Self {
            network_address: normalized_network,
            prefix_length,
        })
    }

    /// Create without normalizing the network address
    pub fn new_unchecked(network_address: IPAddress, prefix_length: u8) -> Self {
        Self {
            network_address,
            prefix_length,
        }
    }

    /// Get the network address
    pub fn network_address(&self) -> &IPAddress {
        &self.network_address
    }

    /// Get the prefix length
    pub fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    /// Get the IP version (4 or 6)
    pub fn version(&self) -> u8 {
        self.network_address.version()
    }

    /// Get the IP address type
    pub fn ip_type(&self) -> IPAddressType {
        self.network_address.ip_type()
    }

    /// Check if this is an IPv4 network
    pub fn is_ipv4(&self) -> bool {
        self.network_address.is_ipv4()
    }

    /// Check if this is an IPv6 network
    pub fn is_ipv6(&self) -> bool {
        self.network_address.is_ipv6()
    }

    /// Get the subnet mask
    pub fn netmask(&self) -> AddrResult<IPAddress> {
        match self.network_address.ip_type() {
            IPAddressType::IPv4 => {
                if self.prefix_length == 0 {
                    Ok(IPAddress::new_v4(Ipv4Addr::new(0, 0, 0, 0)))
                } else {
                    let mask_bits = (!0u32) << (32 - self.prefix_length);
                    Ok(IPAddress::new_v4(Ipv4Addr::from(mask_bits)))
                }
            }
            IPAddressType::IPv6 => {
                if self.prefix_length == 0 {
                    Ok(IPAddress::new_v6(Ipv6Addr::from(0u128)))
                } else {
                    let shift = 128 - self.prefix_length;
                    let mask_bits = if shift >= 128 { 0 } else { !((1u128 << shift) - 1) };
                    Ok(IPAddress::new_v6(Ipv6Addr::from(mask_bits)))
                }
            }
        }
    }

    /// Get the broadcast address (IPv4 only)
    pub fn broadcast_address(&self) -> AddrResult<IPAddress> {
        match self.network_address.ip_type() {
            IPAddressType::IPv4 => {
                let network_u32 = u32::from(*self.network_address.as_ipv4().unwrap());
                let host_bits = 32 - self.prefix_length;
                let broadcast_u32 = network_u32 | ((1u32 << host_bits) - 1);
                Ok(IPAddress::new_v4(Ipv4Addr::from(broadcast_u32)))
            }
            IPAddressType::IPv6 => {
                Err(AddrFormatError::new("IPv6 networks don't have broadcast addresses"))
            }
        }
    }

    /// Get the number of host addresses in this network
    pub fn num_addresses(&self) -> u128 {
        let host_bits = match self.network_address.ip_type() {
            IPAddressType::IPv4 => 32 - self.prefix_length,
            IPAddressType::IPv6 => 128 - self.prefix_length,
        };

        if host_bits >= 128 {
            return u128::MAX;
        }

        1u128 << host_bits
    }

    /// Check if an IP address is contained in this network
    pub fn contains(&self, addr: &IPAddress) -> bool {
        if self.network_address.ip_type() != addr.ip_type() {
            return false;
        }

        match (self.network_address.as_ip_addr(), addr.as_ip_addr()) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let net_u32 = u32::from(*net);
                let addr_u32 = u32::from(*addr);
                let mask = (!0u32) << (32 - self.prefix_length);
                (net_u32 & mask) == (addr_u32 & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let net_u128 = u128::from(*net);
                let addr_u128 = u128::from(*addr);
                let shift = 128 - self.prefix_length;
                let mask = if shift >= 128 { 0 } else { !((1u128 << shift) - 1) };
                (net_u128 & mask) == (addr_u128 & mask)
            }
            _ => false,
        }
    }

    /// Check if this network contains another network
    pub fn contains_network(&self, other: &IPNetwork) -> bool {
        if self.network_address.ip_type() != other.network_address.ip_type() {
            return false;
        }

        // This network must have a smaller or equal prefix length (larger network)
        if self.prefix_length > other.prefix_length {
            return false;
        }

        // Check if the other network's address is within this network
        self.contains(&other.network_address)
    }

    /// Check if this network overlaps with another network
    pub fn overlaps(&self, other: &IPNetwork) -> bool {
        if self.network_address.ip_type() != other.network_address.ip_type() {
            return false;
        }

        self.contains_network(other)
            || other.contains_network(self)
            || self.contains(&other.network_address)
            || other.contains(&self.network_address)
    }

    /// Get an iterator over all IP addresses in this network
    pub fn hosts(&self) -> NetworkHostIterator {
        NetworkHostIterator::new(self)
    }

    /// Get the first usable host address (network + 1 for IPv4, network for IPv6)
    pub fn first_host(&self) -> Option<IPAddress> {
        match self.network_address.ip_type() {
            IPAddressType::IPv4 => {
                if self.prefix_length == 32 {
                    // Single host network
                    Some(self.network_address.clone())
                } else if self.prefix_length == 31 {
                    // Point-to-point link (RFC 3021)
                    Some(self.network_address.clone())
                } else {
                    // Regular network, skip network address
                    self.network_address.next()
                }
            }
            IPAddressType::IPv6 => {
                // IPv6 doesn't have the same concept of unusable network address
                Some(self.network_address.clone())
            }
        }
    }

    /// Get the last usable host address (broadcast - 1 for IPv4, last address for IPv6)
    pub fn last_host(&self) -> Option<IPAddress> {
        match self.network_address.ip_type() {
            IPAddressType::IPv4 => {
                if self.prefix_length == 32 {
                    // Single host network
                    Some(self.network_address.clone())
                } else if self.prefix_length == 31 {
                    // Point-to-point link (RFC 3021)
                    let broadcast = self.broadcast_address().ok()?;
                    Some(broadcast)
                } else {
                    // Regular network, subtract 1 from broadcast
                    let broadcast = self.broadcast_address().ok()?;
                    broadcast.prev()
                }
            }
            IPAddressType::IPv6 => {
                let host_bits = 128 - self.prefix_length;
                let network_u128 = u128::from(*self.network_address.as_ipv6().unwrap());
                let last_u128 = network_u128 | ((1u128 << host_bits) - 1);
                Some(IPAddress::new_v6(Ipv6Addr::from(last_u128)))
            }
        }
    }

    /// Create subnets by dividing this network
    pub fn subnets(&self, new_prefix_length: u8) -> AddrResult<Vec<IPNetwork>> {
        let max_prefix = match self.network_address.ip_type() {
            IPAddressType::IPv4 => 32,
            IPAddressType::IPv6 => 128,
        };

        if new_prefix_length <= self.prefix_length || new_prefix_length > max_prefix {
            return Err(AddrFormatError::new(
                "Invalid subnet prefix length"
            ));
        }

        let subnet_size = 1u128 << (new_prefix_length - self.prefix_length);
        let mut subnets = Vec::new();

        match self.network_address.ip_type() {
            IPAddressType::IPv4 => {
                let network_u32 = u32::from(*self.network_address.as_ipv4().unwrap());
                let step = 1u32 << (32 - new_prefix_length);

                for i in 0..subnet_size {
                    if let Ok(i_u32) = u32::try_from(i) {
                        let subnet_addr = network_u32 + (i_u32 * step);
                        let subnet_ip = IPAddress::new_v4(Ipv4Addr::from(subnet_addr));
                        subnets.push(IPNetwork::new(subnet_ip, new_prefix_length)?);
                    }
                }
            }
            IPAddressType::IPv6 => {
                let network_u128 = u128::from(*self.network_address.as_ipv6().unwrap());
                let step = 1u128 << (128 - new_prefix_length);

                for i in 0..subnet_size {
                    let subnet_addr = network_u128 + (i * step);
                    let subnet_ip = IPAddress::new_v6(Ipv6Addr::from(subnet_addr));
                    subnets.push(IPNetwork::new(subnet_ip, new_prefix_length)?);
                }
            }
        }

        Ok(subnets)
    }

    /// Get the parent network (supernet)
    pub fn supernet(&self) -> Option<IPNetwork> {
        if self.prefix_length == 0 {
            return None;
        }

        let parent_prefix = self.prefix_length - 1;

        match self.network_address.ip_type() {
            IPAddressType::IPv4 => {
                let network_u32 = u32::from(*self.network_address.as_ipv4().unwrap());
                let parent_mask = (!0u32) << (32 - parent_prefix);
                let parent_network_u32 = network_u32 & parent_mask;
                let parent_ip = IPAddress::new_v4(Ipv4Addr::from(parent_network_u32));
                IPNetwork::new(parent_ip, parent_prefix).ok()
            }
            IPAddressType::IPv6 => {
                let network_u128 = u128::from(*self.network_address.as_ipv6().unwrap());
                let shift = 128 - parent_prefix;
                let parent_mask = if shift >= 128 { 0 } else { !((1u128 << shift) - 1) };
                let parent_network_u128 = network_u128 & parent_mask;
                let parent_ip = IPAddress::new_v6(Ipv6Addr::from(parent_network_u128));
                IPNetwork::new(parent_ip, parent_prefix).ok()
            }
        }
    }

    /// Normalize network address by clearing host bits
    fn normalize_network_address(addr: &IPAddress, prefix_length: u8) -> AddrResult<IPAddress> {
        match addr.ip_type() {
            IPAddressType::IPv4 => {
                if prefix_length == 0 {
                    return Ok(IPAddress::new_v4(Ipv4Addr::new(0, 0, 0, 0)));
                }
                let addr_u32 = u32::from(*addr.as_ipv4().unwrap());
                let mask = (!0u32) << (32 - prefix_length);
                let network_u32 = addr_u32 & mask;
                Ok(IPAddress::new_v4(Ipv4Addr::from(network_u32)))
            }
            IPAddressType::IPv6 => {
                if prefix_length == 0 {
                    return Ok(IPAddress::new_v6(Ipv6Addr::from(0u128)));
                }
                let addr_u128 = u128::from(*addr.as_ipv6().unwrap());
                let shift = 128 - prefix_length;
                let mask = if shift >= 128 { 0 } else { !((1u128 << shift) - 1) };
                let network_u128 = addr_u128 & mask;
                Ok(IPAddress::new_v6(Ipv6Addr::from(network_u128)))
            }
        }
    }
}

impl FromStr for IPNetwork {
    type Err = AddrFormatError;

    fn from_str(s: &str) -> AddrResult<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(AddrFormatError::new(
                "Network must be in CIDR notation (address/prefix)"
            ));
        }

        let address = IPAddress::from_str(parts[0])?;
        let prefix_length = parts[1].parse::<u8>()
            .map_err(|_| AddrFormatError::new("Invalid prefix length"))?;

        IPNetwork::new(address, prefix_length)
    }
}

impl fmt::Display for IPNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network_address, self.prefix_length)
    }
}

impl PartialOrd for IPNetwork {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IPNetwork {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.network_address.cmp(&other.network_address) {
            std::cmp::Ordering::Equal => self.prefix_length.cmp(&other.prefix_length),
            other => other,
        }
    }
}

/// Iterator over host addresses in a network
pub struct NetworkHostIterator {
    current: Option<IPAddress>,
    end: Option<IPAddress>,
    finished: bool,
}

impl NetworkHostIterator {
    fn new(network: &IPNetwork) -> Self {
        let current = network.first_host();
        let end = network.last_host();

        Self {
            current: current.clone(),
            end: end.clone(),
            finished: current.is_none() || end.is_none(),
        }
    }
}

impl Iterator for NetworkHostIterator {
    type Item = IPAddress;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let current = self.current.as_ref()?;
        let end = self.end.as_ref()?;

        if current > end {
            self.finished = true;
            return None;
        }

        let result = current.clone();

        if current == end {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_creation() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        assert_eq!(network.network_address().to_string(), "192.168.1.0");
        assert_eq!(network.prefix_length(), 24);
        assert!(network.is_ipv4());
    }

    #[test]
    fn test_network_normalization() {
        // Should normalize to network address
        let network = IPNetwork::from_str("192.168.1.100/24").unwrap();
        assert_eq!(network.network_address().to_string(), "192.168.1.0");
    }

    #[test]
    fn test_netmask() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let netmask = network.netmask().unwrap();
        assert_eq!(netmask.to_string(), "255.255.255.0");
    }

    #[test]
    fn test_broadcast_address() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let broadcast = network.broadcast_address().unwrap();
        assert_eq!(broadcast.to_string(), "192.168.1.255");
    }

    #[test]
    fn test_contains() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let addr = IPAddress::from_str("192.168.1.100").unwrap();
        let outside_addr = IPAddress::from_str("192.168.2.100").unwrap();

        assert!(network.contains(&addr));
        assert!(!network.contains(&outside_addr));
    }

    #[test]
    fn test_num_addresses() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        assert_eq!(network.num_addresses(), 256);

        let network = IPNetwork::from_str("192.168.1.0/30").unwrap();
        assert_eq!(network.num_addresses(), 4);
    }

    #[test]
    fn test_first_last_host() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        assert_eq!(network.first_host().unwrap().to_string(), "192.168.1.1");
        assert_eq!(network.last_host().unwrap().to_string(), "192.168.1.254");

        // Point-to-point network
        let p2p = IPNetwork::from_str("192.168.1.0/31").unwrap();
        assert_eq!(p2p.first_host().unwrap().to_string(), "192.168.1.0");
        assert_eq!(p2p.last_host().unwrap().to_string(), "192.168.1.1");

        // Host route
        let host = IPNetwork::from_str("192.168.1.1/32").unwrap();
        assert_eq!(host.first_host().unwrap().to_string(), "192.168.1.1");
        assert_eq!(host.last_host().unwrap().to_string(), "192.168.1.1");
    }

    #[test]
    fn test_subnetting() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let subnets = network.subnets(26).unwrap();
        assert_eq!(subnets.len(), 4);
        assert_eq!(subnets[0].to_string(), "192.168.1.0/26");
        assert_eq!(subnets[1].to_string(), "192.168.1.64/26");
        assert_eq!(subnets[2].to_string(), "192.168.1.128/26");
        assert_eq!(subnets[3].to_string(), "192.168.1.192/26");
    }

    #[test]
    fn test_supernetting() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let supernet = network.supernet().unwrap();
        assert_eq!(supernet.to_string(), "192.168.0.0/23");
    }

    #[test]
    fn test_ipv6_network() {
        let network = IPNetwork::from_str("2001:db8::/32").unwrap();
        assert!(network.is_ipv6());
        assert_eq!(network.num_addresses(), 1u128 << 96);

        let addr = IPAddress::from_str("2001:db8:1234:5678::1").unwrap();
        assert!(network.contains(&addr));
    }

    #[test]
    fn test_network_iterator() {
        let network = IPNetwork::from_str("192.168.1.0/30").unwrap();
        let hosts: Vec<IPAddress> = network.hosts().collect();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].to_string(), "192.168.1.1");
        assert_eq!(hosts[1].to_string(), "192.168.1.2");
    }

    #[test]
    fn test_network_overlap() {
        let net1 = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let net2 = IPNetwork::from_str("192.168.1.128/25").unwrap();
        let net3 = IPNetwork::from_str("192.168.2.0/24").unwrap();

        assert!(net1.overlaps(&net2));
        assert!(net1.contains_network(&net2));
        assert!(!net1.overlaps(&net3));
    }
}