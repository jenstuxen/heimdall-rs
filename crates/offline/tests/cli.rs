//! End-to-end tests for the network-silent Heimdall adapter.

use std::process::Command;

#[test]
fn emits_heimdall_json_for_supplied_bytecode() {
    let output = Command::new(env!("CARGO_BIN_EXE_heimdall-offline"))
        .args(["--bytecode", "0x60006000f3"])
        .output()
        .expect("failed to run heimdall-offline");

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout was not valid JSON");
    assert_eq!(result["engine"], "heimdall-rs");
    assert_eq!(result["supplied_input_bytes"], 5);
    assert_eq!(result["analyzed_bytes"], 5);
    assert_eq!(result["requested_hardfork"], "latest");
    assert_eq!(result["effective_hardfork"], "fusaka");
    assert!(result["source"].as_str().is_some_and(|source| !source.is_empty()));
    assert!(result["disassembly"].as_str().is_some_and(|assembly| assembly.contains("RETURN")));
}
