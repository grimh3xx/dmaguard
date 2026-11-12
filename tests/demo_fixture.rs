//! The demo laptop must keep producing the findings shown in docs/demo.svg.
#![cfg(not(windows))]
use std::process::Command;

#[test]
fn laptop_fixture_findings() {
    let fx = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/laptop");
    let out = Command::new(env!("CARGO_BIN_EXE_dmaguard"))
        .args(["--json", "--root", fx])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        ["DMA-005", "DMA-002", "DMA-003", "DMA-016", "DMA-010", "DMA-013"]
    );
    assert_eq!(v["firmware"]["dmar"]["dma_ctrl_platform_opt_in"], false);
    assert_eq!(v["firmware"]["dmar"]["header"]["checksum_ok"], true);
}
