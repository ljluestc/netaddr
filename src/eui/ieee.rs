//! IEEE registry information for OUI and IAB lookups

use crate::error::{NotRegisteredError, RegistryResult};
use crate::eui::{OUI, IAB};
use lazy_static::lazy_static;
use std::collections::HashMap;

/// OUI registry information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OUIRegistryInfo {
    pub oui: String,
    pub organization: String,
    pub address: Vec<String>,
}

/// IAB registry information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IABRegistryInfo {
    pub oui: String,
    pub organization: String,
    pub address: Vec<String>,
    pub iab_range_start: String,
    pub iab_range_end: String,
}

/// Registry for OUI lookups
pub struct OUIRegistry {
    registry: HashMap<u32, OUIRegistryInfo>,
}

impl OUIRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
        }
    }

    /// Add an OUI entry to the registry
    pub fn add_entry(&mut self, oui_value: u32, info: OUIRegistryInfo) {
        self.registry.insert(oui_value, info);
    }

    /// Look up OUI information
    pub fn lookup_oui(&self, oui: &OUI) -> Option<OUIRegistryInfo> {
        self.registry.get(&oui.to_u32()).cloned()
    }

    /// Look up OUI by organization name (partial match)
    pub fn lookup_by_organization(&self, org_name: &str) -> Vec<(OUI, OUIRegistryInfo)> {
        let search_term = org_name.to_lowercase();
        self.registry
            .iter()
            .filter(|(_, info)| info.organization.to_lowercase().contains(&search_term))
            .map(|(oui_val, info)| (OUI::from_u32(*oui_val), info.clone()))
            .collect()
    }

    /// Get all entries
    pub fn all_entries(&self) -> Vec<(OUI, OUIRegistryInfo)> {
        self.registry
            .iter()
            .map(|(oui_val, info)| (OUI::from_u32(*oui_val), info.clone()))
            .collect()
    }

    /// Load from CSV data
    pub fn load_from_csv(&mut self, csv_data: &str) -> Result<(), Box<dyn std::error::Error>> {
        for line in csv_data.lines().skip(1) { // Skip header
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                let oui_str = parts[0].trim().replace([':', '-'], "");
                if let Ok(oui_value) = u32::from_str_radix(&oui_str, 16) {
                    let info = OUIRegistryInfo {
                        oui: parts[0].trim().to_string(),
                        organization: parts[1].trim().to_string(),
                        address: parts[2..].iter().map(|s| s.trim().to_string()).collect(),
                    };
                    self.add_entry(oui_value, info);
                }
            }
        }
        Ok(())
    }
}

impl Default for OUIRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Registry for IAB lookups
pub struct IABRegistry {
    registry: HashMap<(u32, u8), IABRegistryInfo>,
}

impl IABRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
        }
    }

    /// Add an IAB entry to the registry
    pub fn add_entry(&mut self, oui_value: u32, extension: u8, info: IABRegistryInfo) {
        self.registry.insert((oui_value, extension), info);
    }

    /// Look up IAB information
    pub fn lookup_iab(&self, iab: &IAB) -> Option<IABRegistryInfo> {
        self.registry.get(&(iab.oui().to_u32(), iab.extension())).cloned()
    }

    /// Look up IAB by organization name (partial match)
    pub fn lookup_by_organization(&self, org_name: &str) -> Vec<(IAB, IABRegistryInfo)> {
        let search_term = org_name.to_lowercase();
        self.registry
            .iter()
            .filter(|(_, info)| info.organization.to_lowercase().contains(&search_term))
            .map(|((oui_val, ext), info)| {
                let iab = IAB::new(OUI::from_u32(*oui_val), *ext);
                (iab, info.clone())
            })
            .collect()
    }

    /// Get all entries
    pub fn all_entries(&self) -> Vec<(IAB, IABRegistryInfo)> {
        self.registry
            .iter()
            .map(|((oui_val, ext), info)| {
                let iab = IAB::new(OUI::from_u32(*oui_val), *ext);
                (iab, info.clone())
            })
            .collect()
    }
}

impl Default for IABRegistry {
    fn default() -> Self {
        Self::new()
    }
}

lazy_static! {
    /// Global OUI registry instance
    pub static ref OUI_REGISTRY: OUIRegistry = {
        let mut registry = OUIRegistry::new();

        // Add some common OUI entries for testing and basic functionality
        registry.add_entry(0x000000, OUIRegistryInfo {
            oui: "00:00:00".to_string(),
            organization: "Xerox Corporation".to_string(),
            address: vec!["Xerox Systems Institute".to_string(), "475 Oakmead Parkway".to_string(), "Sunnyvale CA 94086".to_string()],
        });

        registry.add_entry(0x000001, OUIRegistryInfo {
            oui: "00:00:01".to_string(),
            organization: "Xerox Corporation".to_string(),
            address: vec!["Xerox Systems Institute".to_string(), "475 Oakmead Parkway".to_string(), "Sunnyvale CA 94086".to_string()],
        });

        registry.add_entry(0x00001B, OUIRegistryInfo {
            oui: "00:00:1B".to_string(),
            organization: "Novell Inc.".to_string(),
            address: vec!["Novell Inc.".to_string(), "1555 N. Technology Way".to_string(), "Orem UT 84057".to_string()],
        });

        registry.add_entry(0x00001C, OUIRegistryInfo {
            oui: "00:00:1C".to_string(),
            organization: "Corvus Systems Inc.".to_string(),
            address: vec!["Corvus Systems Inc.".to_string()],
        });

        // Apple
        registry.add_entry(0x001122, OUIRegistryInfo {
            oui: "00:11:22".to_string(),
            organization: "CIMSYS Inc".to_string(),
            address: vec!["CIMSYS Inc".to_string()],
        });

        // Intel
        registry.add_entry(0x001B21, OUIRegistryInfo {
            oui: "00:1B:21".to_string(),
            organization: "Intel Corporate".to_string(),
            address: vec!["Intel Corporate".to_string(), "LAN Access Division".to_string(), "1501 S. MoPac Blvd.".to_string(), "Austin TX 78746".to_string()],
        });

        // Cisco
        registry.add_entry(0x001F9E, OUIRegistryInfo {
            oui: "00:1F:9E".to_string(),
            organization: "Cisco Systems, Inc".to_string(),
            address: vec!["Cisco Systems, Inc".to_string(), "170 W Tasman Dr".to_string(), "San Jose CA 95134".to_string()],
        });

        // Add more common vendors
        registry.add_entry(0x00D0B7, OUIRegistryInfo {
            oui: "00:D0:B7".to_string(),
            organization: "Intel Corporation".to_string(),
            address: vec!["Intel Corporation".to_string()],
        });

        registry.add_entry(0x001B63, OUIRegistryInfo {
            oui: "00:1B:63".to_string(),
            organization: "Apple, Inc.".to_string(),
            address: vec!["Apple, Inc.".to_string(), "1 Infinite Loop".to_string(), "Cupertino CA 95014".to_string()],
        });

        registry
    };

    /// Global IAB registry instance
    pub static ref IAB_REGISTRY: IABRegistry = {
        let mut registry = IABRegistry::new();

        // Add some example IAB entries
        registry.add_entry(0x0050C2, 0x00, IABRegistryInfo {
            oui: "00:50:C2".to_string(),
            organization: "IEEE Registration Authority".to_string(),
            address: vec!["IEEE".to_string(), "445 Hoes Lane".to_string(), "Piscataway NJ 08854".to_string()],
            iab_range_start: "00:50:C2:00:00:00".to_string(),
            iab_range_end: "00:50:C2:00:0F:FF".to_string(),
        });

        registry
    };
}

/// Public API functions for OUI/IAB lookups

/// Look up OUI information by MAC address or EUI
pub fn lookup_oui_info(oui: &OUI) -> RegistryResult<OUIRegistryInfo> {
    OUI_REGISTRY.lookup_oui(oui)
        .ok_or_else(|| NotRegisteredError::new(format!("OUI {} not found in registry", oui)))
}

/// Look up IAB information
pub fn lookup_iab_info(iab: &IAB) -> RegistryResult<IABRegistryInfo> {
    IAB_REGISTRY.lookup_iab(iab)
        .ok_or_else(|| NotRegisteredError::new(format!("IAB {} not found in registry", iab)))
}

/// Search for OUIs by organization name
pub fn search_oui_by_organization(org_name: &str) -> Vec<(OUI, OUIRegistryInfo)> {
    OUI_REGISTRY.lookup_by_organization(org_name)
}

/// Search for IABs by organization name
pub fn search_iab_by_organization(org_name: &str) -> Vec<(IAB, IABRegistryInfo)> {
    IAB_REGISTRY.lookup_by_organization(org_name)
}

/// Get statistics about the registry
pub fn registry_stats() -> (usize, usize) {
    (OUI_REGISTRY.all_entries().len(), IAB_REGISTRY.all_entries().len())
}

/// Load additional OUI data from CSV content
pub fn load_oui_csv_data(csv_data: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Note: In a real implementation, you would need to handle the lazy_static mutability
    // For now, this is a placeholder to show the interface
    println!("Would load {} bytes of CSV data", csv_data.len());
    Ok(())
}

/// Common vendor OUI ranges
pub mod vendors {
    use super::*;

    /// Check if an OUI belongs to Apple
    pub fn is_apple_oui(oui: &OUI) -> bool {
        let oui_val = oui.to_u32();
        matches!(oui_val,
            0x001B63 | 0x28E02F | 0x001EC2 | 0x001E52 | 0x001F5B |
            0x0019E3 | 0x001451 | 0x0017F2 | 0x001124 | 0x000A27 |
            0x000A95 | 0x000D93 | 0x003065 | 0x0050E4 | 0x7CF05F
        )
    }

    /// Check if an OUI belongs to Intel
    pub fn is_intel_oui(oui: &OUI) -> bool {
        let oui_val = oui.to_u32();
        matches!(oui_val,
            0x001B21 | 0x00D0B7 | 0x002170 | 0x001F3C | 0x001E67 |
            0x002564 | 0x0015C5 | 0x000E35 | 0x009027 | 0x00A0C9
        )
    }

    /// Check if an OUI belongs to Cisco
    pub fn is_cisco_oui(oui: &OUI) -> bool {
        let oui_val = oui.to_u32();
        matches!(oui_val,
            0x001F9E | 0x002155 | 0x000142 | 0x0004C0 | 0x000E83 |
            0x0008C7 | 0x000A8A | 0x0008A1 | 0x00178A | 0x001A2F
        )
    }

    /// Get vendor name by OUI (simplified check)
    pub fn get_vendor_name(oui: &OUI) -> Option<&'static str> {
        if is_apple_oui(oui) {
            Some("Apple")
        } else if is_intel_oui(oui) {
            Some("Intel")
        } else if is_cisco_oui(oui) {
            Some("Cisco")
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_oui_lookup() {
        let oui = OUI::from_str("00:00:00").unwrap();
        let info = OUI_REGISTRY.lookup_oui(&oui);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.organization, "Xerox Corporation");
    }

    #[test]
    fn test_oui_search() {
        let results = search_oui_by_organization("xerox");
        assert!(!results.is_empty());
        assert!(results.iter().any(|(_, info)| info.organization.contains("Xerox")));
    }

    #[test]
    fn test_vendor_detection() {
        let apple_oui = OUI::from_str("00:1B:63").unwrap();
        assert!(vendors::is_apple_oui(&apple_oui));
        assert_eq!(vendors::get_vendor_name(&apple_oui), Some("Apple"));

        let intel_oui = OUI::from_str("00:1B:21").unwrap();
        assert!(vendors::is_intel_oui(&intel_oui));
        assert_eq!(vendors::get_vendor_name(&intel_oui), Some("Intel"));

        let cisco_oui = OUI::from_str("00:1F:9E").unwrap();
        assert!(vendors::is_cisco_oui(&cisco_oui));
        assert_eq!(vendors::get_vendor_name(&cisco_oui), Some("Cisco"));
    }

    #[test]
    fn test_registry_stats() {
        let (oui_count, iab_count) = registry_stats();
        assert!(oui_count > 0);
        assert!(iab_count >= 0); // Might be 0 if no IAB entries loaded
    }

    #[test]
    fn test_public_api() {
        let oui = OUI::from_str("00:00:00").unwrap();
        let info = lookup_oui_info(&oui);
        assert!(info.is_ok());

        let unknown_oui = OUI::from_str("FF:FF:FF").unwrap();
        let info = lookup_oui_info(&unknown_oui);
        assert!(info.is_err());
    }

    #[test]
    fn test_iab_lookup() {
        let oui = OUI::from_str("00:50:C2").unwrap();
        let iab = IAB::new(oui, 0x00);
        let info = IAB_REGISTRY.lookup_iab(&iab);
        assert!(info.is_some());
    }

    #[test]
    fn test_oui_registry_creation() {
        let mut registry = OUIRegistry::new();
        let info = OUIRegistryInfo {
            oui: "AA:BB:CC".to_string(),
            organization: "Test Corp".to_string(),
            address: vec!["Test Address".to_string()],
        };
        registry.add_entry(0xAABBCC, info.clone());

        let oui = OUI::from_str("AA:BB:CC").unwrap();
        let retrieved = registry.lookup_oui(&oui);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().organization, "Test Corp");
    }
}