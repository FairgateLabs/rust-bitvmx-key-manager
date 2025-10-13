// Modules added to ensure that examples compile, (will be checked at cargo test)

// Compile-check winternitz example
#[allow(dead_code)]
mod winternitz_example {
    include!("../examples/winternitz.rs");
}
