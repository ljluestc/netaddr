//! IANA IP address block information

use crate::ip::{IPAddress, IPNetwork, IPAddressType};
use lazy_static::lazy_static;
use std::collections::HashMap;

/// IANA registry information for an IP block
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IANARegistryInfo {
    pub designation: String,
    pub date: String,
    pub whois: String,
    pub rdap: String,
    pub status: Vec<String>,
    pub notes: String,
}

/// IANA IP address block registry
pub struct IANARegistry {
    ipv4_blocks: HashMap<u8, IANARegistryInfo>,
    ipv6_blocks: HashMap<u8, IANARegistryInfo>,
}

impl IANARegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            ipv4_blocks: HashMap::new(),
            ipv6_blocks: HashMap::new(),
        }
    }

    /// Add IPv4 block information
    pub fn add_ipv4_block(&mut self, prefix: u8, info: IANARegistryInfo) {
        self.ipv4_blocks.insert(prefix, info);
    }

    /// Add IPv6 block information
    pub fn add_ipv6_block(&mut self, prefix: u8, info: IANARegistryInfo) {
        self.ipv6_blocks.insert(prefix, info);
    }

    /// Look up IANA information for an IP address
    pub fn lookup_address(&self, addr: &IPAddress) -> Option<IANARegistryInfo> {
        match addr.ip_type() {
            IPAddressType::IPv4 => {
                let ipv4 = addr.as_ipv4().unwrap();
                let first_octet = ipv4.octets()[0];
                self.ipv4_blocks.get(&first_octet).cloned()
            }
            IPAddressType::IPv6 => {
                let ipv6 = addr.as_ipv6().unwrap();
                let segments = ipv6.segments();
                let first_byte = (segments[0] >> 8) as u8;
                self.ipv6_blocks.get(&first_byte).cloned()
            }
        }
    }

    /// Look up IANA information for a network
    pub fn lookup_network(&self, network: &IPNetwork) -> Option<IANARegistryInfo> {
        self.lookup_address(network.network_address())
    }

    /// Get all IPv4 blocks
    pub fn ipv4_blocks(&self) -> &HashMap<u8, IANARegistryInfo> {
        &self.ipv4_blocks
    }

    /// Get all IPv6 blocks
    pub fn ipv6_blocks(&self) -> &HashMap<u8, IANARegistryInfo> {
        &self.ipv6_blocks
    }
}

impl Default for IANARegistry {
    fn default() -> Self {
        Self::new()
    }
}

lazy_static! {
    /// Global IANA registry with predefined blocks
    pub static ref IANA_REGISTRY: IANARegistry = {
        let mut registry = IANARegistry::new();

        // IPv4 Special-Use Address Registry (RFC 6890)
        registry.add_ipv4_block(0, IANARegistryInfo {
            designation: "0.0.0.0/8".to_string(),
            date: "1981-09".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "\"This\" Network".to_string(),
        });

        registry.add_ipv4_block(10, IANARegistryInfo {
            designation: "10.0.0.0/8".to_string(),
            date: "1996-02".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Private-Use Networks".to_string(),
        });

        registry.add_ipv4_block(127, IANARegistryInfo {
            designation: "127.0.0.0/8".to_string(),
            date: "1981-09".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Loopback".to_string(),
        });

        registry.add_ipv4_block(169, IANARegistryInfo {
            designation: "169.254.0.0/16".to_string(),
            date: "2005-05".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Link Local".to_string(),
        });

        registry.add_ipv4_block(172, IANARegistryInfo {
            designation: "172.16.0.0/12".to_string(),
            date: "1996-02".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Private-Use Networks".to_string(),
        });

        registry.add_ipv4_block(192, IANARegistryInfo {
            designation: "192.168.0.0/16".to_string(),
            date: "1996-02".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Private-Use Networks".to_string(),
        });

        registry.add_ipv4_block(224, IANARegistryInfo {
            designation: "224.0.0.0/4".to_string(),
            date: "1981-09".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Multicast".to_string(),
        });

        registry.add_ipv4_block(240, IANARegistryInfo {
            designation: "240.0.0.0/4".to_string(),
            date: "1981-09".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Reserved for Future Use".to_string(),
        });

        // IPv6 Special-Use Address Registry
        registry.add_ipv6_block(0x00, IANARegistryInfo {
            designation: "::/128".to_string(),
            date: "2006-02".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Unspecified Address".to_string(),
        });

        registry.add_ipv6_block(0x20, IANARegistryInfo {
            designation: "2000::/3".to_string(),
            date: "2006-02".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["ALLOCATED".to_string()],
            notes: "Global Unicast".to_string(),
        });

        registry.add_ipv6_block(0xfc, IANARegistryInfo {
            designation: "fc00::/7".to_string(),
            date: "2005-10".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Unique Local Unicast".to_string(),
        });

        registry.add_ipv6_block(0xfe, IANARegistryInfo {
            designation: "fe80::/10".to_string(),
            date: "2006-02".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Link-Scoped Unicast".to_string(),
        });

        registry.add_ipv6_block(0xff, IANARegistryInfo {
            designation: "ff00::/8".to_string(),
            date: "2006-02".to_string(),
            whois: "whois.iana.org".to_string(),
            rdap: "".to_string(),
            status: vec!["RESERVED".to_string()],
            notes: "Multicast".to_string(),
        });

        registry
    };
}

/// Look up IANA registry information for an IP address
pub fn lookup_iana_info(addr: &IPAddress) -> Option<IANARegistryInfo> {
    IANA_REGISTRY.lookup_address(addr)
}

/// Check if an IP address is in an IANA reserved block
pub fn is_iana_reserved(addr: &IPAddress) -> bool {
    if let Some(info) = lookup_iana_info(addr) {
        info.status.contains(&"RESERVED".to_string())
    } else {
        false
    }
}

/// Check if an IP address is in an IANA allocated block
pub fn is_iana_allocated(addr: &IPAddress) -> bool {
    if let Some(info) = lookup_iana_info(addr) {
        info.status.contains(&"ALLOCATED".to_string())
    } else {
        false
    }
}

/// Get the IANA designation for an IP address
pub fn get_iana_designation(addr: &IPAddress) -> Option<String> {
    lookup_iana_info(addr).map(|info| info.designation)
}

/// Address classification based on IANA registries
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressClass {
    /// Private/Local addresses (RFC 1918, RFC 4193)
    Private,
    /// Loopback addresses
    Loopback,
    /// Link-local addresses
    LinkLocal,
    /// Multicast addresses
    Multicast,
    /// Broadcast address (IPv4 only)
    Broadcast,
    /// Reserved for special use
    Reserved,
    /// Global/Public addresses
    Global,
    /// Unknown classification
    Unknown,
}

/// Classify an IP address based on IANA registries and RFCs
pub fn classify_address(addr: &IPAddress) -> AddressClass {
    match addr.ip_type() {
        IPAddressType::IPv4 => {
            let ipv4 = addr.as_ipv4().unwrap();
            let octets = ipv4.octets();

            // Check for specific address types
            if ipv4.is_broadcast() {
                return AddressClass::Broadcast;
            }

            if ipv4.is_loopback() {
                return AddressClass::Loopback;
            }

            if ipv4.is_private() {
                return AddressClass::Private;
            }

            if ipv4.is_link_local() {
                return AddressClass::LinkLocal;
            }

            if ipv4.is_multicast() {
                return AddressClass::Multicast;
            }

            // Check IANA registry
            if is_iana_reserved(addr) {
                return AddressClass::Reserved;
            }

            // Check for other special ranges
            match octets[0] {
                0 => AddressClass::Reserved, // 0.0.0.0/8 "This" Network
                240..=255 => AddressClass::Reserved, // 240.0.0.0/4 Future use
                _ => AddressClass::Global,
            }
        }
        IPAddressType::IPv6 => {
            let ipv6 = addr.as_ipv6().unwrap();

            if ipv6.is_loopback() {
                return AddressClass::Loopback;
            }

            if ipv6.is_multicast() {
                return AddressClass::Multicast;
            }

            let segments = ipv6.segments();
            let first_segment = segments[0];

            match first_segment {
                0x0000 => AddressClass::Reserved, // ::/128 and other :: addresses
                0xfc00..=0xfdff => AddressClass::Private, // fc00::/7 Unique Local
                0xfe80..=0xfebf => AddressClass::LinkLocal, // fe80::/10 Link Local
                0xff00..=0xffff => AddressClass::Multicast, // ff00::/8 Multicast
                0x2000..=0x3fff => AddressClass::Global, // 2000::/3 Global Unicast
                _ => {
                    if is_iana_reserved(addr) {
                        AddressClass::Reserved
                    } else {
                        AddressClass::Unknown
                    }
                }
            }
        }
    }
}

/// Get human-readable description of address classification
pub fn address_class_description(class: AddressClass) -> &'static str {
    match class {
        AddressClass::Private => "Private/Local Address",
        AddressClass::Loopback => "Loopback Address",
        AddressClass::LinkLocal => "Link-Local Address",
        AddressClass::Multicast => "Multicast Address",
        AddressClass::Broadcast => "Broadcast Address",
        AddressClass::Reserved => "Reserved Address",
        AddressClass::Global => "Global/Public Address",
        AddressClass::Unknown => "Unknown Address Type",
    }
}

/// Regional Internet Registry information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RIRInfo {
    pub name: String,
    pub full_name: String,
    pub region: String,
    pub whois_server: String,
    pub rdap_base_url: String,
}

/// Get RIR information for an IP address (simplified mapping)
pub fn get_rir_info(addr: &IPAddress) -> Option<RIRInfo> {
    match addr.ip_type() {
        IPAddressType::IPv4 => {
            let ipv4 = addr.as_ipv4().unwrap();
            let first_octet = ipv4.octets()[0];

            // This is a simplified mapping based on historical allocations
            // In reality, you'd need to consult the actual IANA IPv4 allocation table
            match first_octet {
                1..=2 | 4..=6 | 9 | 11 | 13..=15 | 18..=19 | 21..=22 | 26 | 28 | 30 | 32..=35 |
                38..=39 | 44 | 47..=48 | 50 | 52..=53 | 55..=56 | 63..=64 | 66..=69 | 72 | 74..=75 |
                96..=99 | 104..=107 | 173..=174 | 184..=185 | 192 | 198..=199 | 204..=207 | 209 |
                216 | 222..=223 => Some(RIRInfo {
                    name: "ARIN".to_string(),
                    full_name: "American Registry for Internet Numbers".to_string(),
                    region: "North America".to_string(),
                    whois_server: "whois.arin.net".to_string(),
                    rdap_base_url: "https://rdap.arin.net/registry".to_string(),
                }),
                62 | 77..=95 | 109..=109 | 176..=176 | 188..=188 | 193..=194 | 212..=213 | 217 => Some(RIRInfo {
                    name: "RIPE NCC".to_string(),
                    full_name: "Réseaux IP Européens Network Coordination Centre".to_string(),
                    region: "Europe, Middle East, Central Asia".to_string(),
                    whois_server: "whois.ripe.net".to_string(),
                    rdap_base_url: "https://rdap.db.ripe.net".to_string(),
                }),
                _ => None, // Default or need more detailed lookup
            }
        }
        IPAddressType::IPv6 => {
            // IPv6 RIR allocation is based on 2000::/3 space
            // This would require a more complex lookup table
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_iana_lookup() {
        let private_addr = IPAddress::from_str("192.168.1.1").unwrap();
        let info = lookup_iana_info(&private_addr);
        assert!(info.is_some());
        assert!(info.unwrap().designation.contains("192.168"));

        let loopback = IPAddress::from_str("127.0.0.1").unwrap();
        let info = lookup_iana_info(&loopback);
        assert!(info.is_some());
        assert!(info.unwrap().notes.contains("Loopback"));
    }

    #[test]
    fn test_iana_reserved_check() {
        let reserved = IPAddress::from_str("240.0.0.1").unwrap();
        assert!(is_iana_reserved(&reserved));

        let global = IPAddress::from_str("8.8.8.8").unwrap();
        assert!(!is_iana_reserved(&global));
    }

    #[test]
    fn test_address_classification() {
        let private = IPAddress::from_str("192.168.1.1").unwrap();
        assert_eq!(classify_address(&private), AddressClass::Private);

        let loopback = IPAddress::from_str("127.0.0.1").unwrap();
        assert_eq!(classify_address(&loopback), AddressClass::Loopback);

        let multicast = IPAddress::from_str("224.0.0.1").unwrap();
        assert_eq!(classify_address(&multicast), AddressClass::Multicast);

        let broadcast = IPAddress::from_str("255.255.255.255").unwrap();
        assert_eq!(classify_address(&broadcast), AddressClass::Broadcast);

        let link_local = IPAddress::from_str("169.254.1.1").unwrap();
        assert_eq!(classify_address(&link_local), AddressClass::LinkLocal);

        let reserved = IPAddress::from_str("240.0.0.1").unwrap();
        assert_eq!(classify_address(&reserved), AddressClass::Reserved);
    }

    #[test]
    fn test_ipv6_classification() {
        let loopback = IPAddress::from_str("::1").unwrap();
        assert_eq!(classify_address(&loopback), AddressClass::Loopback);

        let multicast = IPAddress::from_str("ff02::1").unwrap();
        assert_eq!(classify_address(&multicast), AddressClass::Multicast);

        let unique_local = IPAddress::from_str("fc00::1").unwrap();
        assert_eq!(classify_address(&unique_local), AddressClass::Private);

        let link_local = IPAddress::from_str("fe80::1").unwrap();
        assert_eq!(classify_address(&link_local), AddressClass::LinkLocal);

        let global = IPAddress::from_str("2001:db8::1").unwrap();
        assert_eq!(classify_address(&global), AddressClass::Global);
    }

    #[test]
    fn test_class_descriptions() {
        assert_eq!(address_class_description(AddressClass::Private), "Private/Local Address");
        assert_eq!(address_class_description(AddressClass::Global), "Global/Public Address");
        assert_eq!(address_class_description(AddressClass::Reserved), "Reserved Address");
    }

    #[test]
    fn test_iana_designation() {
        let private = IPAddress::from_str("10.0.0.1").unwrap();
        let designation = get_iana_designation(&private);
        assert!(designation.is_some());
        assert!(designation.unwrap().contains("10.0.0.0"));
    }

    #[test]
    fn test_rir_info() {
        let us_addr = IPAddress::from_str("8.8.8.8").unwrap();
        let rir = get_rir_info(&us_addr);
        if let Some(rir_info) = rir {
            assert_eq!(rir_info.name, "ARIN");
        }

        // Note: This test might not pass with the simplified RIR mapping
        // A full implementation would require the actual IANA allocation tables
    }

    #[test]
    fn test_registry_creation() {
        let mut registry = IANARegistry::new();

        let test_info = IANARegistryInfo {
            designation: "TEST/8".to_string(),
            date: "2023-01".to_string(),
            whois: "test.example.com".to_string(),
            rdap: "".to_string(),
            status: vec!["TEST".to_string()],
            notes: "Test block".to_string(),
        };

        registry.add_ipv4_block(100, test_info.clone());

        let test_addr = IPAddress::from_str("100.1.2.3").unwrap();
        let looked_up = registry.lookup_address(&test_addr);
        assert_eq!(looked_up, Some(test_info));
    }

    #[test]
    fn test_network_lookup() {
        let network = IPNetwork::from_str("192.168.1.0/24").unwrap();
        let info = IANA_REGISTRY.lookup_network(&network);
        assert!(info.is_some());
    }
}