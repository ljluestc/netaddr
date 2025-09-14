//! # netaddr - Network Address Manipulation Library
//!
//! A comprehensive Rust library for representing and manipulating network addresses,
//! inspired by the Python netaddr library.
//!
//! ## Features
//!
//! ### Layer 3 addresses
//! - IPv4 and IPv6 addresses, subnets, masks, prefixes
//! - iterating, slicing, sorting, summarizing and classifying IP networks
//! - dealing with various ranges formats (CIDR, arbitrary ranges and globs, nmap)
//! - set based operations (unions, intersections etc) over IP addresses and subnets
//! - parsing a large variety of different formats and notations
//! - looking up IANA IP block information
//! - generating DNS reverse lookups
//! - supernetting and subnetting
//!
//! ### Layer 2 addresses
//! - representation and manipulation MAC addresses and EUI-64 identifiers
//! - looking up IEEE organisational information (OUI, IAB)
//! - generating derived IPv6 addresses

pub mod core;
pub mod error;
pub mod ip;
pub mod eui;
pub mod strategy;
pub mod glob;
pub mod nmap;
pub mod sets;
pub mod iana;
pub mod ieee;
pub mod cli;

// Re-export commonly used types
pub use error::{AddrFormatError, AddrConversionError, NotRegisteredError};
pub use ip::{IPAddress, IPNetwork, IPRange};
pub use eui::{EUI, MAC, EUI64};
pub use sets::IPSet;
pub use glob::IPGlob;

// Re-export core constants
pub use core::{ZEROFILL, INET_ATON, INET_PTON, NOHOST};

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parse flags for address parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseFlags(u32);

impl ParseFlags {
    pub const ZEROFILL: Self = Self(1);
    pub const INET_PTON: Self = Self(2);
    pub const NOHOST: Self = Self(4);
    pub const INET_ATON: Self = Self(8);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn all() -> Self {
        Self(Self::ZEROFILL.0 | Self::INET_PTON.0 | Self::NOHOST.0 | Self::INET_ATON.0)
    }

    pub const fn contains(&self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}