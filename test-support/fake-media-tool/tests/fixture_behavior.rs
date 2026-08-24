use std::fs;
use std::process::Command;

use tempfile::tempdir;

#[test]
fn startup_exit_probe_query_exits_nonzero_without_json() {
    let dir = tempdir().expect("temp dir");
    fs::write(
        dir.path().join("fake-media-tool.json"),
        r#"{ "mode": "startupExit", "exitCode": 7 }"#,
    )
    .expect("write scenario");

    let output = Command::new(env!("CARGO_BIN_EXE_fake-media-tool"))
        .args(["-of", "json", "-show_streams", "C:\\private\\secret.mkv"])
        .current_dir(dir.path())
        .output()
        .expect("run fake-media-tool");

    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret.mkv"));
}

#[test]
fn success_probe_query_returns_redacted_deterministic_json() {
    let dir = tempdir().expect("temp dir");

    let output = Command::new(env!("CARGO_BIN_EXE_fake-media-tool"))
        .args(["-of", "json", "-show_streams", "C:\\private\\secret.mkv"])
        .current_dir(dir.path())
        .output()
        .expect("run fake-media-tool");

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(parsed["streams"][0]["codec_type"], "video");
    assert_eq!(parsed["streams"][0]["r_frame_rate"], "30000/1001");
    assert_eq!(parsed["format"]["filename"], "fixture-input");
    assert!(!stdout.contains("private"));
    assert!(!stdout.contains("secret.mkv"));
}
