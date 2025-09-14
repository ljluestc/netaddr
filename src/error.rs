//! Error types for the netaddr library

use thiserror::Error;

/// An error indicating a network address is not correctly formatted.
#[derive(Error, Debug, Clone, PartialEq)]
#[error("Address format error: {message}")]
pub struct AddrFormatError {
    pub message: String,
}

impl AddrFormatError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// An error indicating a failure to convert between address types or notations.
#[derive(Error, Debug, Clone, PartialEq)]
#[error("Address conversion error: {message}")]
pub struct AddrConversionError {
    pub message: String,
}

impl AddrConversionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// An error indicating that an OUI or IAB was not found in the IEEE Registry.
#[derive(Error, Debug, Clone, PartialEq)]
#[error("Not registered error: {message}")]
pub struct NotRegisteredError {
    pub message: String,
}

impl NotRegisteredError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// General result type for netaddr operations
pub type NetAddrResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Specific result type for address format operations
pub type AddrResult<T> = Result<T, AddrFormatError>;

/// Specific result type for address conversion operations
pub type ConversionResult<T> = Result<T, AddrConversionError>;

/// Specific result type for registry lookup operations
pub type RegistryResult<T> = Result<T, NotRegisteredError>;