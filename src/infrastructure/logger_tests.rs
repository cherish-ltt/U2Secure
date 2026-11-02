use super::*;

#[test]
fn logger_appends_sanitized_operations_and_uses_explicit_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let primary = dir.path().join("primary.log");
    let fallback = dir.path().join("fallback.log");
    let logger = FileLogger::with_fallback(primary.to_str().unwrap(), &fallback);
    assert_eq!(logger.path(), primary.to_str().unwrap());
    logger.log("first operation");
    logger.log_operation("keys", "ssh-ed25519 TEST_PUBLIC_MARKER\nnext line");
    let second = FileLogger::with_path(&primary);
    second.log_operation("keys", "ssh-rsa TEST_PUBLIC_MARKER\rnext line");
    let output = std::fs::read_to_string(&primary).unwrap();
    assert!(output.contains("first operation"));
    assert!(output.contains("[KEY_REDACTED]"));
    assert!(output.contains("next line"));
    assert!(!output.contains("TEST_PUBLIC_MARKER"));
    assert!(!fallback.exists());
    let logger = FileLogger::with_fallback(dir.path().to_str().unwrap(), &fallback);
    logger.log("fallback operation");
    assert_eq!(logger.path(), fallback.to_str().unwrap());
    assert!(
        std::fs::read_to_string(fallback)
            .unwrap()
            .contains("fallback operation")
    );
}
