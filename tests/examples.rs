// Modules added to ensure that examples compile and run successfully

// Import the example functions
mod keymanager_usage_example {
    // Re-export everything from the example to make it accessible
    include!("../examples/keymanager_usage.rs");

    // Public wrapper function for testing
    pub fn run_example() {
        main();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_keymanager_usage_example() {
        super::keymanager_usage_example::run_example();
    }
}
