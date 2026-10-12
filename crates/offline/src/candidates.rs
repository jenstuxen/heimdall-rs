//! Optional local candidate annotations; never substitute guesses into generated source.

use std::{collections::BTreeMap, fs, path::Path};

use alloy::primitives::keccak256;
use eyre::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub(crate) struct CandidateReport {
    schema: &'static str,
    snapshot_path: String,
    snapshot_keccak256: String,
    policy: &'static str,
    functions: Vec<FunctionCandidates>,
}

#[derive(Debug, Serialize)]
struct FunctionCandidates {
    selector: String,
    status: &'static str,
    observed_input_types: Vec<String>,
    candidates: Vec<String>,
    input_shape_compatible_candidates: Vec<String>,
    rejected_hash_mismatches: usize,
}

/// Compare a signature's ABI input tuple with Heimdall's mechanically inferred input types.
/// This checks only top-level input shape/types; it does not assess returns or semantics.
fn input_shape_matches(signature: &str, observed: &[String]) -> bool {
    let Some(open) = signature.find('(') else { return false };
    let Some(close) = signature.rfind(')') else { return false };
    if close < open {
        return false;
    }
    let input_text = &signature[open + 1..close];
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut inputs = Vec::new();
    if !input_text.is_empty() {
        for (index, ch) in input_text.char_indices() {
            match ch {
                '(' | '[' => depth += 1,
                ')' | ']' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    inputs.push(input_text[start..index].trim().to_owned());
                    start = index + 1;
                }
                _ => {}
            }
        }
        inputs.push(input_text[start..].trim().to_owned());
    }
    inputs.len() == observed.len()
        && inputs
            .iter()
            .zip(observed)
            .all(|(candidate, actual)| normalize_abi_type(candidate) == normalize_abi_type(actual))
}

fn normalize_abi_type(ty: &str) -> String {
    let mut normalized = ty
        .replace(" payable", "")
        .replace(" memory", "")
        .replace(" calldata", "")
        .replace(" storage", "");
    if let Some((base, dimensions)) = normalized.split_once('[') {
        let dimensions = format!("[{}", dimensions);
        normalized = format!("{}{}", canonical_base_type(base), dimensions);
    } else {
        normalized = canonical_base_type(&normalized);
    }
    normalized
}

fn canonical_base_type(ty: &str) -> String {
    match ty {
        "uint" => "uint256".to_owned(),
        "int" => "int256".to_owned(),
        "fixed" => "fixed128x18".to_owned(),
        "ufixed" => "ufixed128x18".to_owned(),
        other => other.to_owned(),
    }
}

/// Annotate mechanically discovered function selectors with hash-valid candidates.
/// The JSON input is an object mapping 4-byte selector hex to signature arrays.
/// Snapshot absence is not evidence that a function has no signature.
pub(crate) fn annotate(path: &Path, abi: &Value) -> Result<CandidateReport> {
    let bytes = fs::read(path).wrap_err("failed to read selector bank")?;
    let bank: BTreeMap<String, Vec<String>> = serde_json::from_slice(&bytes)
        .wrap_err("selector bank must be a JSON selector-to-signatures object")?;
    let mut normalized = BTreeMap::<String, Vec<String>>::new();
    for (key, signatures) in bank {
        let key = key.strip_prefix("0x").unwrap_or(&key).to_ascii_lowercase();
        if key.len() != 8 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("invalid function selector in bank: {key}");
        }
        normalized.entry(key).or_default().extend(signatures);
    }
    let mut functions = Vec::new();
    for entry in abi.as_array().into_iter().flatten() {
        if entry.get("type").and_then(Value::as_str) != Some("function") {
            continue;
        }
        let Some(selector) = entry.get("selector").and_then(Value::as_str) else { continue };
        let key = selector.trim_start_matches("0x").to_ascii_lowercase();
        let observed_input_types: Vec<String> = entry
            .get("inputs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|input| input.get("type").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let mut candidates = Vec::new();
        let mut compatible = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut rejected = 0;
        for signature in normalized.get(&key).into_iter().flatten() {
            // Hash validity is necessary, not sufficient, for ABI identity.
            let digest = keccak256(signature.as_bytes()).to_string();
            if digest.get(2..10) != Some(key.as_str()) {
                rejected += 1;
                continue;
            }
            if !seen.insert(signature) {
                continue;
            }
            candidates.push(signature.clone());
            if input_shape_matches(signature, &observed_input_types) {
                compatible.push(signature.clone());
            }
        }
        let status = match (candidates.is_empty(), compatible.len()) {
            (true, _) => "unknown",
            (false, 0) => "no_shape_match",
            (false, 1) => "unique_input_shape_candidate",
            (false, _) => "ambiguous_input_shape_candidates",
        };
        functions.push(FunctionCandidates {
            selector: format!("0x{key}"),
            status,
            observed_input_types,
            candidates,
            input_shape_compatible_candidates: compatible,
            rejected_hash_mismatches: rejected,
        });
    }
    functions.sort_by(|a, b| a.selector.cmp(&b.selector));
    Ok(CandidateReport {
        schema: "heimdall.selector-candidates.v1",
        snapshot_path: path.display().to_string(),
        snapshot_keccak256: keccak256(&bytes).to_string(),
        policy: "candidate names must hash to the observed selector; shape comparison is only a weak filter and does not imply exact ABI resolution",
        functions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_collisions_rejects_bad_hashes_and_never_selects() {
        let path = std::env::temp_dir().join(format!("heimdall-bank-{}.json", std::process::id()));
        fs::write(&path, r#"{"a9059cbb":["transfer(address,uint256)","many_msg_babbage(bytes1)","transfer(address,uint256)","wrong()"]}"#).unwrap();
        let abi = serde_json::json!([
            {"type":"function","selector":"0xa9059cbb","inputs":[{"type":"address"},{"type":"uint256"}]},
            {"type":"function","selector":"0xdeadbeef"},
            {"type":"event","selector":"0xa9059cbb"}
        ]);
        let report = annotate(&path, &abi).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(report.functions.len(), 2);
        assert_eq!(report.functions[0].candidates.len(), 2);
        assert_eq!(report.functions[0].rejected_hash_mismatches, 1);
        assert_eq!(report.functions[0].status, "unique_input_shape_candidate");
        assert_eq!(
            report.functions[0].input_shape_compatible_candidates,
            vec!["transfer(address,uint256)"]
        );
        assert!(input_shape_matches(
            "f((address,uint256),bytes32[])",
            &["(address,uint256)".to_string(), "bytes32[]".to_string()]
        ));
        assert!(!input_shape_matches(
            "f(address,address,uint256)",
            &["address".to_string(), "uint256".to_string()]
        ));
        assert_eq!(report.functions[1].status, "unknown");
    }
}
