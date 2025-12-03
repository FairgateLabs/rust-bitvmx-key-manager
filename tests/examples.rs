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

mod sign_verify_musig2_example {
    include!("../examples/sign_verify_musig2.rs");
    pub fn run_example() {
        main();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    
    // Use a mutex to ensure examples run sequentially and don't interfere with each other
    static TEST_MUTEX: Mutex<()> = Mutex::new(());
    
    fn setup_and_cleanup<F>(test_fn: F) 
    where 
        F: FnOnce()
    {
        let _guard = TEST_MUTEX.lock().unwrap();
        
        // Ensure storage directory exists
        let _ = std::fs::create_dir_all("./examples/storage");
        
        // Run the test
        test_fn();
        
        // Clean up after test
        let _ = std::fs::remove_dir_all("./examples/storage");
        let _ = std::fs::remove_dir_all("test_output");
    }

    #[test]
    fn test_create_example() {
        setup_and_cleanup(|| {
            super::create_example::run_example();
        });
    }

    #[test]
    fn test_deriving_winternitz_example() {
        setup_and_cleanup(|| {
            super::deriving_winternitz_example::run_example();
        });
    }

    #[test]
    fn test_key_gen_example() {
        setup_and_cleanup(|| {
            super::key_gen_example::run_example();
        });
    }

    #[test]
    fn test_key_import_example() {
        setup_and_cleanup(|| {
            super::key_import_example::run_example();
        });
    }

    #[test]
    fn test_sign_verify_ecdsa_example() {
        setup_and_cleanup(|| {
            super::sign_verify_ecdsa_example::run_example();
        });
    }

    #[test]
    fn test_sign_verify_schnorr_taproot_example() {
        setup_and_cleanup(|| {
            super::sign_verify_schnorr_taproot_example::run_example();
        });
    }

    #[test]
    fn test_sign_verify_winternitz_example() {
        setup_and_cleanup(|| {
            super::sign_verify_winternitz_example::run_example();
        });
    }

    #[test]
    fn test_rsa_example() {
        setup_and_cleanup(|| {
            super::rsa_example::run_example();
        });
    }

    #[test]
    fn test_sign_verify_musig2_example() {
        setup_and_cleanup(|| {
            super::sign_verify_musig2_example::run_example();
        });
    }
}
