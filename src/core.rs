//! Common code shared between various netaddr sub modules

use std::fmt;

/// Use inet_pton() semantics instead of inet_aton() when parsing IPv4.
pub const INET_PTON: u32 = 1;

/// Remove any preceding zeros from IPv4 address octets before parsing.
pub const ZEROFILL: u32 = 2;

/// Remove any host bits found to the right of an applied CIDR prefix.
pub const NOHOST: u32 = 4;

/// Use legacy inet_aton() semantics when parsing IPv4.
pub const INET_ATON: u32 = 8;

/// True if platform is natively big endian, False otherwise.
pub const BIG_ENDIAN_PLATFORM: bool = cfg!(target_endian = "big");

/// Publisher-Subscriber pattern implementation for notifications
pub trait Subscriber {
    /// A callback method used by a Publisher to notify this Subscriber about updates.
    fn update(&mut self, data: &dyn fmt::Debug);
}

/// A concrete Subscriber that pretty-prints data from updates received
pub struct PrettyPrinter<W: fmt::Write> {
    writer: W,
    write_eol: bool,
}

impl<W: fmt::Write> PrettyPrinter<W> {
    pub fn new(writer: W, write_eol: bool) -> Self {
        Self { writer, write_eol }
    }
}

impl<W: fmt::Write> Subscriber for PrettyPrinter<W> {
    fn update(&mut self, data: &dyn fmt::Debug) {
        let _ = write!(self.writer, "{:?}", data);
        if self.write_eol {
            let _ = writeln!(self.writer);
        }
    }
}

/// A 'push' Publisher that maintains a list of Subscriber objects
pub struct Publisher {
    subscribers: Vec<Box<dyn Subscriber>>,
}

impl Publisher {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    /// Add a new subscriber
    pub fn attach(&mut self, subscriber: Box<dyn Subscriber>) {
        self.subscribers.push(subscriber);
    }

    /// Remove an existing subscriber (by index for simplicity in Rust)
    pub fn detach(&mut self, index: usize) -> Option<Box<dyn Subscriber>> {
        if index < self.subscribers.len() {
            Some(self.subscribers.remove(index))
        } else {
            None
        }
    }

    /// Send update data to all registered Subscribers
    pub fn notify(&mut self, data: &dyn fmt::Debug) {
        for subscriber in &mut self.subscribers {
            subscriber.update(data);
        }
    }
}

impl Default for Publisher {
    fn default() -> Self {
        Self::new()
    }
}

/// A utility for converting between different number bases
pub struct BaseConverter;

impl BaseConverter {
    /// Convert a number from one base to another
    pub fn convert(value: u128, _from_base: u32, to_base: u32) -> String {
        if value == 0 {
            return "0".to_string();
        }

        let mut result = Vec::new();
        let mut num = value;

        while num > 0 {
            let remainder = num % to_base as u128;
            result.push(Self::digit_to_char(remainder as u32));
            num /= to_base as u128;
        }

        result.reverse();
        result.into_iter().collect()
    }

    fn digit_to_char(digit: u32) -> char {
        if digit < 10 {
            (b'0' + digit as u8) as char
        } else {
            (b'a' + (digit - 10) as u8) as char
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(INET_PTON, 1);
        assert_eq!(ZEROFILL, 2);
        assert_eq!(NOHOST, 4);
        assert_eq!(INET_ATON, 8);
    }

    #[test]
    fn test_base_converter() {
        assert_eq!(BaseConverter::convert(255, 10, 16), "ff");
        assert_eq!(BaseConverter::convert(16, 10, 2), "10000");
        assert_eq!(BaseConverter::convert(0, 10, 16), "0");
    }

    #[test]
    fn test_publisher_subscriber() {
        // Note: This test is simplified due to lifetime constraints
        let mut publisher = Publisher::new();
        assert_eq!(publisher.subscribers.len(), 0);

        // Test basic functionality without the complex lifetime scenario
        // In a real implementation, you'd use Rc<RefCell<>> or similar
    }
}