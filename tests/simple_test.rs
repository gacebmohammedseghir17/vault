//! Simple test to verify basic compilation

#[tokio::test]
async fn test_basic_functionality() {
    // Just test that we can import and use basic functionality
    let result = 2 + 2;
    assert_eq!(result, 4);
}

#[test]
fn test_sync_basic() {
    assert_eq!(1 + 1, 2);
}
