extern crate vergen;

use vergen::*;

fn main() {
    let mut flags = OutputFns::all();
    flags.toggle(NOW);
    assert!(vergen(flags).is_ok());
}