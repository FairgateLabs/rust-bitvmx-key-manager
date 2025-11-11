// Modules added to ensure that examples compile and run successfully

// Include each example in its own module with a wrapper function to run them
mod create_example {
    include!("../examples/create.rs");
    pub fn run_example() {
        main();
    }
}

mod deriving_winternitz_example {
    include!("../examples/deriving_winternitz.rs");
    pub fn run_example() {
        main();
    }
}

mod key_gen_example {
    include!("../examples/key_gen.rs");
    pub fn run_example() {
        main();
    }
}

mod key_import_example {
    include!("../examples/key_import.rs");
    pub fn run_example() {
        main();
    }
}

mod sign_verify_ecdsa_example {
    include!("../examples/sign_verify_ecdsa.rs");
    pub fn run_example() {
        main();
    }
}

mod sign_verify_schnorr_taproot_example {
    include!("../examples/sign_verify_schnorr_taproot.rs");
    pub fn run_example() {
        main();
    }
}

mod sign_verify_winternitz_example {
    include!("../examples/sign_verify_winternitz.rs");
    pub fn run_example() {
        main();
    }
}

mod rsa_example {
    include!("../examples/rsa.rs");
    pub fn run_example() {
        main();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_create_example() {
        super::create_example::run_example();
    }

    #[test]
    fn test_deriving_winternitz_example() {
        super::deriving_winternitz_example::run_example();
    }

    #[test]
    fn test_key_gen_example() {
        super::key_gen_example::run_example();
    }

    #[test]
    fn test_key_import_example() {
        super::key_import_example::run_example();
    }

    #[test]
    fn test_sign_verify_ecdsa_example() {
        super::sign_verify_ecdsa_example::run_example();
    }

    #[test]
    fn test_sign_verify_schnorr_taproot_example() {
        super::sign_verify_schnorr_taproot_example::run_example();
    }

    #[test]
    fn test_sign_verify_winternitz_example() {
        super::sign_verify_winternitz_example::run_example();
    }

    #[test]
    fn test_rsa_example() {
        super::rsa_example::run_example();
    }
}
