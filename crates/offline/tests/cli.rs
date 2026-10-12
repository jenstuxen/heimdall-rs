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
    assert!(result.get("selector_candidates").is_none());
}

#[test]
fn selector_bank_adds_candidates_without_rewriting_abi_or_source() {
    let bank =
        std::env::temp_dir().join(format!("heimdall-selector-bank-{}.json", std::process::id()));
    std::fs::write(
        &bank,
        r#"{"a9059cbb":["transfer(address,uint256)","many_msg_babbage(bytes1)"]}"#,
    )
    .unwrap();
    let bytecode = "0x60003560e01c63a9059cbb14601057005b00";
    let output = Command::new(env!("CARGO_BIN_EXE_heimdall-offline"))
        .args(["--bytecode", bytecode, "--selector-bank"])
        .arg(&bank)
        .output()
        .expect("failed to run heimdall-offline");
    let baseline = Command::new(env!("CARGO_BIN_EXE_heimdall-offline"))
        .args(["--bytecode", bytecode])
        .output()
        .expect("failed to run baseline heimdall-offline");
    std::fs::remove_file(bank).unwrap();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(baseline.status.success(), "{}", String::from_utf8_lossy(&baseline.stderr));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let baseline: serde_json::Value = serde_json::from_slice(&baseline.stdout).unwrap();
    assert_eq!(result["selector_candidates"]["schema"], "heimdall.selector-candidates.v1");
    let candidates = result["selector_candidates"]["functions"].as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["selector"], "0xa9059cbb");
    assert!(candidates[0]["candidates"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("transfer(address,uint256)")));
    assert_eq!(candidates[0]["status"], "no_shape_match");
    assert_eq!(result["abi"][0]["name"], "Unresolved_a9059cbb");
    assert_eq!(result["abi"], baseline["abi"]);
    assert_eq!(result["source"], baseline["source"]);
}
