use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;

const SCENARIO_FILE: &str = "fake-media-tool.json";
const STOP_FILE: &str = "fake-media-tool.stop";

fn copied_tool(dir: &Path, role: &str) -> PathBuf {
    let name = format!("{role}{}", std::env::consts::EXE_SUFFIX);
    let destination = dir.join(name);
    fs::copy(env!("CARGO_BIN_EXE_fake-media-tool"), &destination).expect("copy named fake tool");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&destination)
            .expect("named tool metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&destination, permissions).expect("make named tool executable");
    }
    destination
}

fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait().expect("query fake tool status").is_some() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    child
        .try_wait()
        .expect("query final fake tool status")
        .is_some()
}

fn force_cleanup_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        let _ = Command::new("pkill")
            .args(["-KILL", "-P", &child.id().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

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

#[test]
fn copied_ffmpeg_and_ffprobe_names_are_invoked_directly() {
    let dir = tempdir().expect("temp dir");
    let ffmpeg = copied_tool(dir.path(), "ffmpeg");
    let ffprobe = copied_tool(dir.path(), "ffprobe");

    let version = Command::new(&ffmpeg)
        .arg("-version")
        .current_dir(dir.path())
        .output()
        .expect("invoke copied ffmpeg");
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("ffmpeg version"));

    let probe = Command::new(&ffprobe)
        .args(["-of", "json", "-show_streams", "fixture-input"])
        .current_dir(dir.path())
        .output()
        .expect("invoke copied ffprobe");
    assert!(probe.status.success());
    let document: serde_json::Value = serde_json::from_slice(&probe.stdout).expect("probe JSON");
    assert_eq!(document["streams"][0]["codec_type"], "video");
}

#[test]
fn option_looking_input_value_is_not_dispatched_as_a_query() {
    let dir = tempdir().expect("temp dir");

    let output = Command::new(env!("CARGO_BIN_EXE_fake-media-tool"))
        .args(["-i", "-version", "-f", "mpegts", "pipe:1"])
        .current_dir(dir.path())
        .output()
        .expect("run fake-media-tool");

    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 564);
    assert_eq!(output.stdout.first(), Some(&0x47));
    assert_eq!(output.stdout.get(188), Some(&0x47));
    assert_eq!(output.stdout.get(376), Some(&0x47));
}

#[test]
fn internal_child_token_used_as_an_input_value_does_not_activate_control_mode() {
    let dir = tempdir().expect("temp dir");
    let mut child = Command::new(env!("CARGO_BIN_EXE_fake-media-tool"))
        .args(["-i", "--fake-child", "-f", "mpegts", "pipe:1"])
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("run fake-media-tool");

    let exited = wait_for_exit(&mut child, Duration::from_secs(2));
    if !exited {
        force_cleanup_tree(&mut child);
        panic!("input value activated the internal child control mode");
    }
    let output = child.wait_with_output().expect("collect fake tool output");

    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 564);
    assert_eq!(output.stdout.first(), Some(&0x47));
    assert!(!dir.path().join("fake-media-child.pid").exists());
}

#[test]
fn spawned_descendant_is_discoverable_and_cleanup_is_bounded() {
    let dir = tempdir().expect("temp dir");
    fs::write(
        dir.path().join(SCENARIO_FILE),
        r#"{ "mode": "spawnDescendant" }"#,
    )
    .expect("write descendant scenario");
    let ffmpeg = copied_tool(dir.path(), "ffmpeg");
    let mut parent = Command::new(&ffmpeg)
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn descendant scenario");

    let parent_pid_path = dir.path().join("fake-media-parent.pid");
    let child_pid_path = dir.path().join("fake-media-child.pid");
    let discovered = wait_for_path(&parent_pid_path, Duration::from_secs(2))
        && wait_for_path(&child_pid_path, Duration::from_secs(2));

    if discovered {
        fs::write(dir.path().join(STOP_FILE), b"stop").expect("request fixture cleanup");
    }
    let parent_exited = wait_for_exit(&mut parent, Duration::from_secs(2));
    let child_exited = wait_for_path(
        &dir.path().join("fake-media-child.exited"),
        Duration::from_secs(2),
    );
    if !parent_exited || !child_exited {
        force_cleanup_tree(&mut parent);
    }

    assert!(
        discovered,
        "parent/descendant PID markers were not published"
    );
    let parent_pid = fs::read_to_string(parent_pid_path).expect("parent PID marker");
    let child_pid = fs::read_to_string(child_pid_path).expect("child PID marker");
    assert_ne!(parent_pid.trim(), child_pid.trim());
    assert!(parent_exited, "parent did not exit within cleanup bound");
    assert!(child_exited, "descendant did not exit within cleanup bound");
}

#[cfg(unix)]
#[test]
fn hang_mode_ignores_sigterm_until_forced_cleanup_control() {
    let dir = tempdir().expect("temp dir");
    fs::write(dir.path().join(SCENARIO_FILE), r#"{ "mode": "stall" }"#)
        .expect("write stall scenario");
    let ffmpeg = copied_tool(dir.path(), "ffmpeg");
    let mut child = Command::new(&ffmpeg)
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn stall scenario");

    assert!(wait_for_path(
        &dir.path().join("fake-media-stall.pid"),
        Duration::from_secs(2)
    ));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    thread::sleep(Duration::from_millis(150));
    let ignored = child.try_wait().expect("query after SIGTERM").is_none();
    fs::write(dir.path().join(STOP_FILE), b"stop").expect("request cleanup");
    let exited = wait_for_exit(&mut child, Duration::from_secs(2));
    if !exited {
        force_cleanup_tree(&mut child);
    }

    assert!(ignored, "stall process accepted graceful SIGTERM");
    assert!(
        exited,
        "stall process did not exit through bounded cleanup control"
    );
}
