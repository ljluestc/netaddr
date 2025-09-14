//! Main binary entry point for netaddr CLI

use netaddr::cli;

fn main() {
    if let Err(e) = cli::main() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}