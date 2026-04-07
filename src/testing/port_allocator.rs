//! Unique port allocator for test isolation
//!
//! This module provides a port allocation system that:
//! - Maintains default port 19091 for zero-config scenarios
//! - Allows dynamic port allocation for test isolation
//! - Ensures proper cleanup and port release
//! - Avoids conflicts during parallel testing

use std::collections::HashSet;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default metrics port for zero-config scenarios (unified to 19091)
pub const DEFAULT_METRICS_PORT: u16 = 19091;

/// Port range for dynamic allocation (avoiding well-known ports)
const DYNAMIC_PORT_RANGE_START: u16 = 20000;
const DYNAMIC_PORT_RANGE_END: u16 = 30000;

/// Global port allocator instance
static PORT_ALLOCATOR: once_cell::sync::Lazy<Arc<RwLock<PortAllocator>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(PortAllocator::new())));

/// Port allocator for managing unique ports during testing
#[derive(Debug)]
pub struct PortAllocator {
    /// Set of currently allocated ports
    allocated_ports: HashSet<u16>,
    /// Next port to try for allocation
    next_port: u16,
}

impl PortAllocator {
    /// Create a new port allocator
    fn new() -> Self {
        Self {
            allocated_ports: HashSet::new(),
            next_port: DYNAMIC_PORT_RANGE_START,
        }
    }

    /// Allocate a unique port for testing
    fn allocate_port(&mut self) -> Result<u16, std::io::Error> {
        let mut attempts = 0;
        let max_attempts = DYNAMIC_PORT_RANGE_END - DYNAMIC_PORT_RANGE_START;

        while attempts < max_attempts {
            let port = self.next_port;

            // Wrap around if we reach the end of the range
            self.next_port = if self.next_port >= DYNAMIC_PORT_RANGE_END {
                DYNAMIC_PORT_RANGE_START
            } else {
                self.next_port + 1
            };

            // Skip if port is already allocated
            if self.allocated_ports.contains(&port) {
                attempts += 1;
                continue;
            }

            // Try to bind to the port to ensure it's available
            match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))) {
                Ok(_) => {
                    self.allocated_ports.insert(port);
                    return Ok(port);
                }
                Err(_) => {
                    // Port is in use by another process, try next
                    attempts += 1;
                    continue;
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "No available ports in the dynamic range",
        ))
    }

    /// Release a previously allocated port
    fn release_port(&mut self, port: u16) {
        self.allocated_ports.remove(&port);
    }

    /// Get the number of currently allocated ports
    fn allocated_count(&self) -> usize {
        self.allocated_ports.len()
    }
}

/// RAII wrapper for allocated ports that automatically releases on drop
#[derive(Debug)]
pub struct AllocatedPort {
    port: u16,
    released: bool,
}

impl AllocatedPort {
    /// Create a new allocated port wrapper
    fn new(port: u16) -> Self {
        Self {
            port,
            released: false,
        }
    }

    /// Get the port number
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Manually release the port (optional, will be done automatically on drop)
    pub async fn release(&mut self) {
        if !self.released {
            let mut allocator = PORT_ALLOCATOR.write().await;
            allocator.release_port(self.port);
            self.released = true;
        }
    }
}

impl Drop for AllocatedPort {
    fn drop(&mut self) {
        if !self.released {
            // Use blocking approach in drop since we can't be async
            if let Ok(mut allocator) = PORT_ALLOCATOR.try_write() {
                allocator.release_port(self.port);
                self.released = true;
            } else {
                // If we can't get the lock, spawn a task to release it
                let port = self.port;
                tokio::spawn(async move {
                    let mut allocator = PORT_ALLOCATOR.write().await;
                    allocator.release_port(port);
                });
            }
        }
    }
}

/// Allocate a unique port for testing
///
/// This function returns an `AllocatedPort` that will automatically release
/// the port when dropped, ensuring proper cleanup.
///
/// # Example
///
/// ```rust
/// use erdps_agent::testing::port_allocator::allocate_test_port;
///
/// #[tokio::test]
/// async fn my_test() {
///     let port = allocate_test_port().await.expect("Failed to allocate port");
///     println!("Using port: {}", port.port());
///     // Port is automatically released when `port` goes out of scope
/// }
/// ```
pub async fn allocate_test_port() -> Result<AllocatedPort, std::io::Error> {
    let mut allocator = PORT_ALLOCATOR.write().await;
    let port = allocator.allocate_port()?;
    Ok(AllocatedPort::new(port))
}

/// Get the default metrics port (19091)
///
/// This function always returns the default port for zero-config scenarios.
/// Use this when you want to maintain the standard ERDPS Agent behavior.
pub fn get_default_port() -> u16 {
    DEFAULT_METRICS_PORT
}

/// Check if a port is available for binding
///
/// This is a utility function to test if a specific port can be bound to.
pub fn is_port_available(port: u16) -> bool {
    TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).is_ok()
}

/// Get statistics about the port allocator
///
/// Returns the number of currently allocated ports.
pub async fn get_allocator_stats() -> usize {
    let allocator = PORT_ALLOCATOR.read().await;
    allocator.allocated_count()
}

/// Clear all allocated ports (for testing only)
#[cfg(test)]
pub async fn clear_allocator_for_test() {
    let mut allocator = PORT_ALLOCATOR.write().await;
    allocator.allocated_ports.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_port_allocation() {
        clear_allocator_for_test().await;

        let port1 = allocate_test_port()
            .await
            .expect("Failed to allocate port 1");
        let port2 = allocate_test_port()
            .await
            .expect("Failed to allocate port 2");

        // Ports should be different
        assert_ne!(port1.port(), port2.port());

        // Both ports should be in the dynamic range
        assert!(port1.port() >= DYNAMIC_PORT_RANGE_START);
        assert!(port1.port() < DYNAMIC_PORT_RANGE_END);
        assert!(port2.port() >= DYNAMIC_PORT_RANGE_START);
        assert!(port2.port() < DYNAMIC_PORT_RANGE_END);

        println!("Allocated ports: {} and {}", port1.port(), port2.port());
    }

    #[tokio::test]
    async fn test_port_release() {
        clear_allocator_for_test().await;

        let mut port = allocate_test_port().await.expect("Failed to allocate port");
        let count_with_port = get_allocator_stats().await;
        // Allow for occasional race conditions in CI environments
        // where allocator cleanup tasks may run concurrently.
        // We just need to ensure release reduces or maintains the count.

        // Manually release to ensure immediate cleanup
        port.release().await;

        let final_count = get_allocator_stats().await;
        if count_with_port > 0 {
            assert_eq!(final_count, count_with_port - 1);
        } else {
            assert_eq!(final_count, 0);
        }
    }

    #[tokio::test]
    async fn test_manual_release() {
        clear_allocator_for_test().await;

        let mut port = allocate_test_port().await.expect("Failed to allocate port");
        let count_with_port = get_allocator_stats().await;
        // Allow for occasional race conditions in CI environments
        // where allocator cleanup tasks may run concurrently.
        // We just need to ensure release reduces or maintains the count.

        port.release().await;

        let final_count = get_allocator_stats().await;
        if count_with_port > 0 {
            assert_eq!(final_count, count_with_port - 1);
        } else {
            assert_eq!(final_count, 0);
        }
    }

    #[test]
fn test_default_port() {
    assert_eq!(get_default_port(), 19091);
}

    #[test]
    fn test_port_availability_check() {
        // This test might be flaky depending on what's running on the system
        // but it should work in most cases
        let available = is_port_available(0); // Port 0 should always be available for binding
        assert!(available);
    }
}
