// R0 skeleton — owner R7 (generated from spec §4)
#![forbid(unsafe_code)]
mod args;
mod bootstrap;
mod logging;
mod panic;

#[allow(clippy::print_stdout)] // the one allowed print site (§4.1.3)
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("r2 {}", env!("CARGO_PKG_VERSION"));
    }
}
