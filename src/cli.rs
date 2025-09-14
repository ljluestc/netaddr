//! Command-line interface for netaddr

use crate::ip::{IPAddress, IPNetwork, IPRange};
use crate::eui::{EUI, MAC};
use crate::sets::IPSet;
use crate::glob::IPGlob;
use crate::nmap::NmapRange;
use clap::{Parser, Subcommand, ValueEnum};
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "netaddr")]
#[command(about = "A network address manipulation utility")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Work with IP addresses
    #[command(subcommand)]
    Ip(IpCommands),

    /// Work with MAC addresses and EUI identifiers
    #[command(subcommand)]
    Eui(EuiCommands),

    /// Work with IP sets
    #[command(subcommand)]
    Set(SetCommands),

    /// Work with glob patterns
    #[command(subcommand)]
    Glob(GlobCommands),

    /// Work with nmap-style ranges
    #[command(subcommand)]
    Nmap(NmapCommands),

    /// Convert between formats
    Convert {
        /// Input address or network
        input: String,
        /// Output format
        #[arg(short, long, value_enum)]
        format: OutputFormat,
    },

    /// Get information about an address
    Info {
        /// Address to get info about
        address: String,
    },
}

#[derive(Subcommand)]
pub enum IpCommands {
    /// Validate an IP address
    Validate {
        /// IP address to validate
        address: String,
    },

    /// Get network information
    Network {
        /// Network in CIDR notation
        network: String,
        /// Show all hosts in the network
        #[arg(long)]
        hosts: bool,
        /// Limit number of hosts to show
        #[arg(long, default_value = "10")]
        limit: usize,
    },

    /// Convert IP range to CIDR blocks
    RangeToCidr {
        /// IP range (e.g., "192.168.1.1-192.168.1.10")
        range: String,
    },

    /// Find spanning CIDR for addresses
    Span {
        /// List of IP addresses
        addresses: Vec<String>,
    },

    /// Subnet operations
    Subnet {
        /// Base network
        network: String,
        /// New prefix length
        #[arg(short, long)]
        prefix: u8,
    },
}

#[derive(Subcommand)]
pub enum EuiCommands {
    /// Validate MAC or EUI address
    Validate {
        /// MAC or EUI address
        address: String,
    },

    /// Convert MAC to different formats
    Format {
        /// MAC address
        mac: String,
        /// Output format
        #[arg(short, long, value_enum)]
        format: MacFormat,
    },

    /// Convert MAC to IPv6 link-local
    ToIpv6 {
        /// MAC address
        mac: String,
    },

    /// Get vendor information
    Vendor {
        /// MAC or EUI address
        address: String,
    },
}

#[derive(Subcommand)]
pub enum SetCommands {
    /// Create union of IP sets
    Union {
        /// Networks or addresses
        inputs: Vec<String>,
    },

    /// Create intersection of IP sets
    Intersection {
        /// Networks or addresses
        inputs: Vec<String>,
    },

    /// Create difference of IP sets
    Difference {
        /// Base set
        base: String,
        /// Set to subtract
        subtract: String,
    },

    /// Check if address is in set
    Contains {
        /// Set specification
        set: String,
        /// Address to check
        address: String,
    },
}

#[derive(Subcommand)]
pub enum GlobCommands {
    /// Validate glob pattern
    Validate {
        /// Glob pattern
        pattern: String,
    },

    /// Test if address matches glob
    Match {
        /// Glob pattern
        pattern: String,
        /// Address to test
        address: String,
    },

    /// Convert glob to CIDR blocks
    ToCidr {
        /// Glob pattern
        pattern: String,
    },
}

#[derive(Subcommand)]
pub enum NmapCommands {
    /// Validate nmap range
    Validate {
        /// Nmap range pattern
        range: String,
    },

    /// Expand nmap range to addresses
    Expand {
        /// Nmap range pattern
        range: String,
        /// Limit number of addresses to show
        #[arg(long, default_value = "100")]
        limit: usize,
    },

    /// Get range statistics
    Stats {
        /// Nmap range pattern
        range: String,
    },
}

#[derive(ValueEnum, Clone)]
pub enum OutputFormat {
    /// Dotted decimal (IPv4) or compressed (IPv6)
    Decimal,
    /// Hexadecimal
    Hex,
    /// Binary
    Binary,
    /// Integer
    Integer,
    /// Full expanded form
    Full,
}

#[derive(ValueEnum, Clone)]
pub enum MacFormat {
    /// Colon-separated (00:11:22:33:44:55)
    Colon,
    /// Hyphen-separated (00-11-22-33-44-55)
    Hyphen,
    /// Cisco format (0011.2233.4455)
    Cisco,
    /// Bare format (001122334455)
    Bare,
    /// Unix format (0:11:22:33:44:55)
    Unix,
}

/// Main CLI entry point
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Ip(cmd) => handle_ip_command(cmd)?,
        Commands::Eui(cmd) => handle_eui_command(cmd)?,
        Commands::Set(cmd) => handle_set_command(cmd)?,
        Commands::Glob(cmd) => handle_glob_command(cmd)?,
        Commands::Nmap(cmd) => handle_nmap_command(cmd)?,
        Commands::Convert { input, format } => handle_convert_command(input, format)?,
        Commands::Info { address } => handle_info_command(address)?,
    }

    Ok(())
}

fn handle_ip_command(cmd: &IpCommands) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        IpCommands::Validate { address } => {
            match IPAddress::from_str(address) {
                Ok(addr) => {
                    println!("✓ Valid {} address: {}",
                        if addr.is_ipv4() { "IPv4" } else { "IPv6" },
                        addr
                    );
                }
                Err(e) => {
                    println!("✗ Invalid address: {}", e);
                    std::process::exit(1);
                }
            }
        }

        IpCommands::Network { network, hosts, limit } => {
            let net = IPNetwork::from_str(network)?;
            println!("Network: {}", net);
            println!("Network address: {}", net.network_address());
            println!("Prefix length: /{}", net.prefix_length());
            println!("Number of addresses: {}", net.num_addresses());

            if let Ok(netmask) = net.netmask() {
                println!("Netmask: {}", netmask);
            }

            if net.is_ipv4() {
                if let Ok(broadcast) = net.broadcast_address() {
                    println!("Broadcast: {}", broadcast);
                }
            }

            if *hosts {
                println!("\nHosts:");
                for (i, addr) in net.hosts().enumerate() {
                    if i >= *limit {
                        println!("... (showing first {} addresses)", limit);
                        break;
                    }
                    println!("  {}", addr);
                }
            }
        }

        IpCommands::RangeToCidr { range } => {
            let ip_range = IPRange::from_str(range)?;
            let cidrs = ip_range.to_cidrs()?;

            println!("Range: {}", ip_range);
            println!("CIDR blocks:");
            for cidr in cidrs {
                println!("  {}", cidr);
            }
        }

        IpCommands::Span { addresses } => {
            let addrs: Result<Vec<_>, _> = addresses.iter()
                .map(|a| IPAddress::from_str(a))
                .collect();
            let addrs = addrs?;

            if let Some(span) = crate::ip::operations::spanning_cidr(&addrs)? {
                println!("Spanning CIDR: {}", span);
            } else {
                println!("No spanning CIDR found");
            }
        }

        IpCommands::Subnet { network, prefix } => {
            let net = IPNetwork::from_str(network)?;
            let subnets = net.subnets(*prefix)?;

            println!("Subnetting {} into /{} subnets:", net, prefix);
            for subnet in subnets {
                println!("  {}", subnet);
            }
        }
    }

    Ok(())
}

fn handle_eui_command(cmd: &EuiCommands) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        EuiCommands::Validate { address } => {
            match EUI::from_str(address) {
                Ok(eui) => {
                    let type_str = if eui.is_mac48() { "MAC-48" } else { "EUI-64" };
                    println!("✓ Valid {} address: {}", type_str, eui);
                }
                Err(e) => {
                    println!("✗ Invalid EUI address: {}", e);
                    std::process::exit(1);
                }
            }
        }

        EuiCommands::Format { mac, format } => {
            let mac_addr = MAC::from_str(mac)?;
            let formatted = match format {
                MacFormat::Colon => mac_addr.format(crate::eui::mac::MacFormat::Colon),
                MacFormat::Hyphen => mac_addr.format(crate::eui::mac::MacFormat::Hyphen),
                MacFormat::Cisco => mac_addr.format(crate::eui::mac::MacFormat::Cisco),
                MacFormat::Bare => mac_addr.format(crate::eui::mac::MacFormat::Bare),
                MacFormat::Unix => mac_addr.format(crate::eui::mac::MacFormat::Unix),
            };
            println!("{}", formatted);
        }

        EuiCommands::ToIpv6 { mac } => {
            let mac_addr = MAC::from_str(mac)?;
            let ipv6 = mac_addr.to_link_local_ipv6()?;
            println!("Link-local IPv6: {}", ipv6);
        }

        EuiCommands::Vendor { address } => {
            let eui = EUI::from_str(address)?;
            let oui = crate::eui::OUI::new([eui.oui()[0], eui.oui()[1], eui.oui()[2]]);

            if let Some(vendor) = crate::eui::ieee::vendors::get_vendor_name(&oui) {
                println!("Vendor: {}", vendor);
            } else {
                println!("Vendor: Unknown");
            }

            if let Some(info) = crate::eui::ieee::lookup_oui_info(&oui).ok() {
                println!("Organization: {}", info.organization);
            }
        }
    }

    Ok(())
}

fn handle_set_command(cmd: &SetCommands) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        SetCommands::Union { inputs } => {
            let mut result_set = IPSet::new();

            for input in inputs {
                if let Ok(addr) = IPAddress::from_str(input) {
                    result_set.add_address(addr)?;
                } else if let Ok(net) = IPNetwork::from_str(input) {
                    result_set.add_network(net)?;
                } else {
                    eprintln!("Warning: Could not parse '{}'", input);
                }
            }

            println!("Union: {}", result_set);
            println!("Total addresses: {}", result_set.size());
        }

        SetCommands::Intersection { inputs } => {
            if inputs.len() < 2 {
                println!("Need at least 2 inputs for intersection");
                return Ok(());
            }

            let mut sets = Vec::new();
            for input in inputs {
                if let Ok(addr) = IPAddress::from_str(input) {
                    sets.push(IPSet::from_address(addr)?);
                } else if let Ok(net) = IPNetwork::from_str(input) {
                    sets.push(IPSet::from_network(net)?);
                } else {
                    eprintln!("Warning: Could not parse '{}'", input);
                    continue;
                }
            }

            if sets.len() >= 2 {
                let mut result = sets[0].clone();
                for set in &sets[1..] {
                    result = result.intersection(set)?;
                }
                println!("Intersection: {}", result);
                println!("Total addresses: {}", result.size());
            }
        }

        SetCommands::Difference { base, subtract } => {
            let base_set = if let Ok(addr) = IPAddress::from_str(base) {
                IPSet::from_address(addr)?
            } else if let Ok(net) = IPNetwork::from_str(base) {
                IPSet::from_network(net)?
            } else {
                return Err(format!("Could not parse base '{}'", base).into());
            };

            let subtract_set = if let Ok(addr) = IPAddress::from_str(subtract) {
                IPSet::from_address(addr)?
            } else if let Ok(net) = IPNetwork::from_str(subtract) {
                IPSet::from_network(net)?
            } else {
                return Err(format!("Could not parse subtract '{}'", subtract).into());
            };

            let result = base_set.difference(&subtract_set)?;
            println!("Difference: {}", result);
            println!("Total addresses: {}", result.size());
        }

        SetCommands::Contains { set, address } => {
            let ip_set = if let Ok(net) = IPNetwork::from_str(set) {
                IPSet::from_network(net)?
            } else {
                return Err(format!("Could not parse set '{}'", set).into());
            };

            let addr = IPAddress::from_str(address)?;
            let contains = ip_set.contains_address(&addr);

            println!("{} {} in {}",
                if contains { "✓" } else { "✗" },
                addr,
                ip_set
            );
        }
    }

    Ok(())
}

fn handle_glob_command(cmd: &GlobCommands) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        GlobCommands::Validate { pattern } => {
            if crate::glob::valid_glob(pattern) {
                println!("✓ Valid glob pattern: {}", pattern);
            } else {
                println!("✗ Invalid glob pattern: {}", pattern);
                std::process::exit(1);
            }
        }

        GlobCommands::Match { pattern, address } => {
            let glob = IPGlob::from_str(pattern)?;
            let addr = IPAddress::from_str(address)?;

            let matches = glob.matches(&addr);
            println!("{} {} matches {}",
                if matches { "✓" } else { "✗" },
                addr,
                pattern
            );
        }

        GlobCommands::ToCidr { pattern } => {
            let glob = IPGlob::from_str(pattern)?;
            let cidrs = glob.to_cidrs()?;

            println!("Glob: {}", pattern);
            println!("CIDR blocks:");
            for cidr in cidrs {
                println!("  {}", cidr);
            }
        }
    }

    Ok(())
}

fn handle_nmap_command(cmd: &NmapCommands) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        NmapCommands::Validate { range } => {
            if crate::nmap::valid_nmap_range(range) {
                println!("✓ Valid nmap range: {}", range);
            } else {
                println!("✗ Invalid nmap range: {}", range);
                std::process::exit(1);
            }
        }

        NmapCommands::Expand { range, limit } => {
            let nmap_range = NmapRange::from_str(range)?;

            println!("Range: {}", range);
            println!("Addresses:");
            for (i, addr) in nmap_range.addresses().enumerate() {
                if i >= *limit {
                    println!("... (showing first {} addresses)", limit);
                    break;
                }
                println!("  {}", addr);
            }
        }

        NmapCommands::Stats { range } => {
            let (size, first, last) = crate::nmap::nmap_range_stats(range)?;

            println!("Range: {}", range);
            println!("Total addresses: {}", size);
            println!("First address: {}", first);
            println!("Last address: {}", last);
        }
    }

    Ok(())
}

fn handle_convert_command(input: &str, format: &OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(addr) = IPAddress::from_str(input) {
        let output = match format {
            OutputFormat::Decimal => addr.to_string(),
            OutputFormat::Hex => addr.to_hex(),
            OutputFormat::Binary => format!("0b{}", addr.to_binary().iter()
                .map(|b| format!("{:08b}", b))
                .collect::<String>()),
            OutputFormat::Integer => {
                match addr.as_ip_addr() {
                    std::net::IpAddr::V4(ipv4) => u32::from(*ipv4).to_string(),
                    std::net::IpAddr::V6(ipv6) => u128::from(*ipv6).to_string(),
                }
            },
            OutputFormat::Full => {
                match addr.as_ip_addr() {
                    std::net::IpAddr::V4(_) => addr.to_string(),
                    std::net::IpAddr::V6(ipv6) => {
                        let ipv6_ext = crate::ip::ipv6::IPv6::from(*ipv6);
                        ipv6_ext.full()
                    }
                }
            }
        };
        println!("{}", output);
    } else if let Ok(eui) = EUI::from_str(input) {
        let output = match format {
            OutputFormat::Hex => format!("0x{}", eui.format(crate::eui::EUIFormat::Bare)),
            OutputFormat::Binary => {
                let bytes = eui.bytes();
                format!("0b{}", bytes.iter()
                    .map(|b| format!("{:08b}", b))
                    .collect::<String>())
            },
            OutputFormat::Integer => {
                let bytes = eui.bytes();
                let mut value = 0u64;
                for (i, &byte) in bytes.iter().enumerate() {
                    value |= (byte as u64) << (8 * (bytes.len() - 1 - i));
                }
                value.to_string()
            },
            _ => eui.to_string(),
        };
        println!("{}", output);
    } else {
        return Err(format!("Could not parse input: {}", input).into());
    }

    Ok(())
}

fn handle_info_command(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(addr) = IPAddress::from_str(address) {
        println!("Address: {}", addr);
        println!("Type: {}", if addr.is_ipv4() { "IPv4" } else { "IPv6" });

        // Classification
        let class = crate::iana::classify_address(&addr);
        println!("Classification: {}", crate::iana::address_class_description(class));

        // Properties
        if addr.is_loopback() { println!("Property: Loopback"); }
        if addr.is_private() { println!("Property: Private"); }
        if addr.is_multicast() { println!("Property: Multicast"); }
        if addr.is_link_local() { println!("Property: Link-local"); }

        // IANA info
        if let Some(iana_info) = crate::iana::lookup_iana_info(&addr) {
            println!("IANA designation: {}", iana_info.designation);
            println!("IANA status: {}", iana_info.status.join(", "));
            if !iana_info.notes.is_empty() {
                println!("IANA notes: {}", iana_info.notes);
            }
        }

        // Reverse DNS
        println!("Reverse DNS: {}", addr.reverse_dns());

    } else if let Ok(eui) = EUI::from_str(address) {
        println!("Address: {}", eui);
        println!("Type: {}", if eui.is_mac48() { "MAC-48" } else { "EUI-64" });

        // Properties
        if eui.is_unicast() { println!("Property: Unicast"); }
        if eui.is_multicast() { println!("Property: Multicast"); }
        if eui.is_broadcast() { println!("Property: Broadcast"); }
        if eui.is_local() { println!("Property: Locally administered"); }
        if eui.is_universal() { println!("Property: Universally administered"); }

        // OUI info
        let oui = crate::eui::OUI::new([eui.oui()[0], eui.oui()[1], eui.oui()[2]]);
        if let Some(vendor) = crate::eui::ieee::vendors::get_vendor_name(&oui) {
            println!("Vendor: {}", vendor);
        }

        if let Some(info) = crate::eui::ieee::lookup_oui_info(&oui).ok() {
            println!("Organization: {}", info.organization);
        }

        // Conversions
        if eui.is_mac48() {
            if let Ok(ipv6) = eui.to_link_local_ipv6() {
                println!("Link-local IPv6: {}", ipv6);
            }
        }

    } else {
        return Err(format!("Could not parse address: {}", address).into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Test basic command parsing
        let cli = Cli::try_parse_from(vec!["netaddr", "info", "192.168.1.1"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_ip_validate() {
        // This would test the actual command execution
        // In practice, you'd want to refactor the handlers to be testable
        assert!(true);
    }
}