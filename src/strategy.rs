//! Strategy module for parsing and formatting addresses

pub mod ipv4;
pub mod ipv6;
pub mod eui48;
pub mod eui64;

pub use ipv4::IPv4Strategy;
pub use ipv6::IPv6Strategy;
pub use eui48::EUI48Strategy;
pub use eui64::EUI64Strategy;