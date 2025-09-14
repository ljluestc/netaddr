//! IP address functionality module

pub mod ipv4;
pub mod ipv6;
pub mod network;
pub mod range;
pub mod address;
pub mod operations;

pub use address::{IPAddress, IPAddressType};
pub use network::IPNetwork;
pub use range::IPRange;
pub use operations::*;