// Modules added to ensure that examples compile, (will be checked at cargo test)

// Compile-check winternitz example
#[allow(dead_code)]
mod winternitz_example {
    include!("../examples/winternitz.rs");
}

// Compile-check import example
#[allow(dead_code)]
mod import_example {
    include!("../examples/import.rs");
}

// Compile-check keygen example
#[allow(dead_code)]
mod keygen_example {
    include!("../examples/keygen.rs");
}
