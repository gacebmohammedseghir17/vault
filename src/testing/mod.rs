//! Testing utilities for ERDPS Agent
//!
//! This module provides utilities for testing the ERDPS Agent, including:
//! - Port allocation for test isolation
//! - Test harnesses and helpers
//! - Mock implementations for testing

pub mod port_allocator;
pub mod real_fs_benchmark;
pub mod real_ransom_lib;
pub mod integration_tests;
pub mod malware_testing;
pub mod malware_testing_suite;
pub mod workload_validation;

// Re-export commonly used testing utilities
pub use port_allocator::{
    allocate_test_port, get_default_port, is_port_available, get_allocator_stats, AllocatedPort,
};
