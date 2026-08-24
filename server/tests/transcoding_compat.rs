use std::ffi::OsString;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use enginefs::hls::{HlsEngine, TranscodeConfig};
use enginefs::hwaccel::HwAccelConfig;
use reqwest::blocking::Client;
use serde_json::{Value, json};

const SERVER_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn set_env_var(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    unsafe {
        std::env::set_var(key, value);
    }
}

fn remove_env_var(key: &str) {
    unsafe {
        std::env::remove_var(key);
    }
}

struct ScopedEnv {
    path: Option<OsString>,
    fake_log: Option<OsString>,
    fake_counter: Option<OsString>,
    fake_scenario: Option<OsString>,
}

impl ScopedEnv {
    fn install(
        bin_dir: &Path,
        log_path: &Path,
        counter_path: Option<&Path>,
        scenario: &str,
    ) -> Self {
        let path = std::env::var_os("PATH");
        let fake_log = std::env::var_os("FAKE_FFMPEG_LOG");
        let fake_counter = std::env::var_os("FAKE_FFMPEG_COUNTER");
        let fake_scenario = std::env::var_os("FAKE_FFMPEG_SCENARIO");

        let mut new_path = OsString::from(bin_dir.as_os_str());
        if let Some(existing) = &path {
            new_path.push(";");
            new_path.push(existing);
        }

        set_env_var("PATH", new_path);
        set_env_var("FAKE_FFMPEG_LOG", log_path.as_os_str());
        set_env_var("FAKE_FFMPEG_SCENARIO", scenario);
        if let Some(counter_path) = counter_path {
            set_env_var("FAKE_FFMPEG_COUNTER", counter_path.as_os_str());
        } else {
            remove_env_var("FAKE_FFMPEG_COUNTER");
        }

        Self {
            path,
            fake_log,
            fake_counter,
            fake_scenario,
        }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        match &self.path {
            Some(value) => set_env_var("PATH", value),
            None => remove_env_var("PATH"),
        }
        match &self.fake_log {
            Some(value) => set_env_var("FAKE_FFMPEG_LOG", value),
            None => remove_env_var("FAKE_FFMPEG_LOG"),
        }
        match &self.fake_counter {
            Some(value) => set_env_var("FAKE_FFMPEG_COUNTER", value),
            None => remove_env_var("FAKE_FFMPEG_COUNTER"),
        }
        match &self.fake_scenario {
            Some(value) => set_env_var("FAKE_FFMPEG_SCENARIO", value),
            None => remove_env_var("FAKE_FFMPEG_SCENARIO"),
        }
    }
}

fn fake_ffmpeg_source() -> &'static str {
    r#"
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

fn log_args(args: &[String]) {
    if let Some(path) = env::var_os("FAKE_FFMPEG_LOG") {
        let mut line = String::new();
        for arg in args {
            line.push('[');
            line.push_str(arg);
            line.push(']');
        }
        line.push('\n');
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .expect("write fake ffmpeg log");
    }
}

fn append_raw(line: &str) {
    if let Some(path) = env::var_os("FAKE_FFMPEG_LOG") {
        let mut payload = String::from(line);
        payload.push('\n');
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(payload.as_bytes()))
            .expect("write fake ffmpeg raw log");
    }
}

fn counter_path() -> PathBuf {
    env::var_os("FAKE_FFMPEG_COUNTER")
        .map(PathBuf::from)
        .expect("FAKE_FFMPEG_COUNTER")
}

fn next_count() -> u32 {
    let path = counter_path();
    let count = fs::read_to_string(&path)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(0)
        + 1;
    fs::write(path, count.to_string()).expect("write counter");
    count
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    log_args(&args);

    match env::var("FAKE_FFMPEG_SCENARIO").as_deref() {
        Ok("command_log") => {}
        Ok("device_probe") => {
            if args.iter().any(|arg| arg == "-encoders") {
                println!("Encoders:");
                println!(" V..... h264_nvenc           NVIDIA NVENC H.264 encoder");
                return;
            }

            let is_verify = args
                .windows(2)
                .any(|pair| pair[0] == "-c:v" && pair[1] == "h264_nvenc");
            if !is_verify {
                std::process::exit(1);
            }
        }
        Ok("probe_retry") => {
            let count = next_count();
            append_raw(&format!("call={count} {}", args.join(" ")));
            match count {
                1 => {
                    eprintln!("Input #0, unknown, from \"sample.mkv\":");
                }
                2 => {
                    eprintln!("Input #0, matroska,webm, from \"sample.mkv\":");
                    eprintln!("Duration: 00:00:10.00, start: 0.000000, bitrate: 1200 kb/s");
                }
                _ => {
                    eprintln!("Input #0, matroska,webm, from \"sample.mkv\":");
                    eprintln!("Duration: 00:00:10.00, start: 0.000000, bitrate: 1200 kb/s");
                    eprintln!("Stream #0:0(eng): Video: hevc (Main 10), yuv420p10le(tv), 3840x2160, 23.98 fps, 24000/1001 tbr, 1k tbn");
                    eprintln!("Stream #0:1(jpn): Audio: aac (LC), 48000 Hz, stereo, fltp, 256 kb/s (default)");
                }
            }
        }
        Ok(other) => panic!("unknown FAKE_FFMPEG_SCENARIO {other}"),
        Err(_) => panic!("FAKE_FFMPEG_SCENARIO not set"),
    }

    io::stdout().flush().expect("flush stdout");
    io::stderr().flush().expect("flush stderr");
}
"#
}

fn with_fake_ffmpeg<T>(scenario: &str, test: impl FnOnce(&Path) -> T) -> T {
    let _env_guard = lock_env();
    let temp = tempfile::tempdir().expect("fake ffmpeg tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("fake ffmpeg bin dir");
    let log_path = temp.path().join("ffmpeg.log");
    let source_path = temp.path().join("fake_ffmpeg.rs");
    let ffmpeg_path = bin_dir.join("ffmpeg.exe");
    fs::write(&source_path, fake_ffmpeg_source()).expect("write fake ffmpeg source");
    let compile = std::process::Command::new("rustc")
        .arg("--edition=2024")
        .arg(&source_path)
        .arg("-o")
        .arg(&ffmpeg_path)
        .status()
        .expect("spawn rustc for fake ffmpeg");
    assert!(compile.success(), "fake ffmpeg compilation failed");
    let _scoped_env = ScopedEnv::install(
        &bin_dir,
        &log_path,
        Some(&temp.path().join("count.txt")),
        scenario,
    );
    test(&log_path)
}

fn read_log(log_path: &Path) -> String {
    fs::read_to_string(log_path).unwrap_or_default()
}

fn run_async<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

fn with_embedded_server<T>(test: impl FnOnce(&Client, String) -> T) -> T {
    let config_dir = tempfile::tempdir().expect("config tempdir");
    let cache_dir = tempfile::tempdir().expect("cache tempdir");
    let handle = stream_server::start(stream_server::ServerConfig {
        http_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        config_dir: Some(config_dir.path().join("config")),
        cache_dir: Some(cache_dir.path().join("cache")),
        ..stream_server::ServerConfig::default()
    })
    .expect("start embedded server");
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");
    let base = format!("http://{}", handle.http_addr());

    let result = test(&client, base);

    handle.shutdown().expect("shutdown request");
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let joiner = std::thread::spawn(move || {
        let _ = tx.send(handle.join());
    });
    let shutdown_source = rx
        .recv_timeout(SERVER_JOIN_TIMEOUT)
        .expect("server join timeout")
        .expect("server join result");
    joiner.join().expect("join helper thread");
    assert_eq!(
        shutdown_source,
        Some(stream_server::ShutdownSource::External)
    );

    result
}

fn assert_contains(log: &str, needle: &str) {
    assert!(
        log.contains(needle),
        "expected log to contain {needle:?}, got:\n{log}"
    );
}

#[test]
fn transcode_profile_aliases_preserve_encoder_selection_contract() {
    let available = vec![
        "nvenc".to_string(),
        "nvenc:verified".to_string(),
        "qsv".to_string(),
        "qsv:verified".to_string(),
        "vaapi".to_string(),
        "vaapi:verified".to_string(),
        "videotoolbox".to_string(),
        "videotoolbox:verified".to_string(),
        "v4l2m2m".to_string(),
        "v4l2m2m:verified".to_string(),
    ];

    let cases = [
        (Some("hw:nvenc"), "h264_nvenc"),
        (Some("hw:nvidia"), "h264_nvenc"),
        (Some("hw:cuda"), "h264_nvenc"),
        (Some("nvenc"), "h264_nvenc"),
        (Some("nvidia"), "h264_nvenc"),
        (Some("cuda"), "h264_nvenc"),
        (Some("hw:qsv"), "h264_qsv"),
        (Some("hw:intel"), "h264_qsv"),
        (Some("hw:quicksync"), "h264_qsv"),
        (Some("qsv"), "h264_qsv"),
        (Some("intel"), "h264_qsv"),
        (Some("quicksync"), "h264_qsv"),
        (Some("hw:vaapi"), "h264_vaapi"),
        (Some("vaapi"), "h264_vaapi"),
        (Some("hw:videotoolbox"), "h264_videotoolbox"),
        (Some("hw:vt"), "h264_videotoolbox"),
        (Some("hw:apple"), "h264_videotoolbox"),
        (Some("videotoolbox"), "h264_videotoolbox"),
        (Some("vt"), "h264_videotoolbox"),
        (Some("hw:v4l2"), "h264_v4l2m2m"),
        (Some("hw:v4l2m2m"), "h264_v4l2m2m"),
        (Some("v4l2"), "h264_v4l2m2m"),
        (Some("v4l2m2m"), "h264_v4l2m2m"),
        (Some("sw"), "libx264"),
        (Some("software"), "libx264"),
        (Some("cpu"), "libx264"),
        (Some("auto"), "h264_nvenc"),
        (None, "h264_nvenc"),
        (Some("mystery-profile"), "h264_nvenc"),
    ];

    for (profile, expected_encoder) in cases {
        let config = HwAccelConfig::from_transcode_profile(&available, profile);
        assert_eq!(
            config.encoder, expected_encoder,
            "profile {:?} regressed",
            profile
        );
    }
}

#[test]
fn device_and_profiler_routes_preserve_compatibility_shapes() {
    with_fake_ffmpeg("device_probe", |log_path| {
        with_embedded_server(|client, base| {
            let device_info = client
                .get(format!("{base}/device-info"))
                .send()
                .expect("device-info request")
                .error_for_status()
                .expect("device-info status")
                .json::<Value>()
                .expect("device-info json");
            assert_eq!(
                device_info,
                json!({
                    "availableHardwareAccelerations": ["nvenc", "nvenc:verified"]
                })
            );

            let profiler = client
                .get(format!("{base}/hwaccel-profiler"))
                .send()
                .expect("hwaccel-profiler request")
                .error_for_status()
                .expect("hwaccel-profiler status")
                .json::<Value>()
                .expect("hwaccel-profiler json");
            assert_eq!(
                profiler,
                json!({
                    "success": true,
                    "profiles": ["nvenc", "nvenc:verified"]
                })
            );
        });

        let log = read_log(log_path);
        assert_contains(&log, "[-hide_banner][-encoders]");
        assert_contains(&log, "[-c:v][h264_nvenc]");
    });
}

#[test]
fn legacy_hls_and_casting_routes_preserve_current_response_contracts() {
    let _guard = lock_env();
    with_embedded_server(|client, base| {
        let list_devices = client
            .get(format!("{base}/casting"))
            .send()
            .expect("casting devices request")
            .error_for_status()
            .expect("casting devices status")
            .json::<Value>()
            .expect("casting devices json");
        assert_eq!(list_devices, json!([]));

        let missing_device = client
            .get(format!("{base}/casting/missing-device"))
            .send()
            .expect("missing casting device request");
        assert_eq!(missing_device.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(
            missing_device.text().expect("missing device body"),
            "Device missing-device not found"
        );

        let player = client
            .get(format!(
                "{base}/casting/living-room/player?source=http://example/video.mkv&paused=true&time=12.5&volume=0.25&stop=false&audioTrack=7"
            ))
            .send()
            .expect("casting player request")
            .error_for_status()
            .expect("casting player status")
            .json::<Value>()
            .expect("casting player json");
        assert_eq!(
            player,
            json!({
                "deviceId": "living-room",
                "status": "not_implemented",
                "params": {
                    "source": "http://example/video.mkv",
                    "paused": "true",
                    "time": 12.5,
                    "volume": 0.25,
                    "stop": "false",
                    "audio_track": 7
                }
            })
        );

        let hls_v2 = client
            .get(format!("{base}/hlsv2/not-a-converter/stream-0.m3u8"))
            .send()
            .expect("hlsv2 compatibility request");
        assert_eq!(hls_v2.status(), reqwest::StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            hls_v2.json::<Value>().expect("hlsv2 json"),
            json!({
                "error": "hlsv2 arbitrary converter playlist is not implemented"
            })
        );

        let legacy_resource = client
            .get(format!("{base}/not-a-hash/not-an-idx/master.m3u8"))
            .send()
            .expect("legacy hls resource request");
        assert_eq!(legacy_resource.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(
            legacy_resource.text().expect("legacy resource body"),
            "legacy file/url HLS resource not found"
        );

        let legacy_segment = client
            .get(format!("{base}/not-a-hash/not-an-idx/stream/0.ts"))
            .send()
            .expect("legacy hls segment request");
        assert_eq!(legacy_segment.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(
            legacy_segment.text().expect("legacy segment body"),
            "legacy file/url HLS segment not found"
        );
    });
}

#[test]
fn probe_video_retries_until_hls_metadata_is_complete() {
    with_fake_ffmpeg("probe_retry", |log_path| {
        let probe = run_async(HlsEngine::probe_video("sample.mkv")).expect("probe result");

        assert_eq!(probe.container, "matroska");
        assert_eq!(probe.duration, 10.0);
        assert_eq!(probe.streams.len(), 2);
        assert_eq!(probe.streams[0].codec_type, "video");
        assert_eq!(probe.streams[0].codec_name, "hevc");
        assert_eq!(probe.streams[0].profile.as_deref(), Some("Main 10"));
        assert_eq!(probe.streams[0].pix_fmt.as_deref(), Some("yuv420p10le"));
        assert_eq!(probe.streams[0].fps, Some(23.98));
        assert_eq!(probe.streams[1].codec_type, "audio");
        assert_eq!(probe.streams[1].channels, Some(2));

        let log = read_log(log_path);
        assert_contains(&log, "call=1 -analyzeduration 750000 -probesize 512000");
        assert_contains(&log, "call=2 -analyzeduration 2000000 -probesize 2000000");
        assert_contains(&log, "call=3 -analyzeduration 5000000 -probesize 5000000");
    });
}

#[test]
fn transcode_video_segment_software_contract_is_stable() {
    with_fake_ffmpeg("command_log", |log_path| {
        let config = TranscodeConfig::browser();
        let mut process = run_async(HlsEngine::transcode_video_segment(
            "input.mkv",
            0.0,
            4.0,
            &config,
        ))
        .expect("software transcode spawn");
        let status = run_async(process.wait()).expect("software transcode wait");
        assert!(status.success());

        let log = read_log(log_path);
        assert_contains(&log, "[-threads]");
        assert_contains(&log, "[-sc_threshold][0]");
        assert_contains(&log, "[-g][96]");
        assert_contains(&log, "[-keyint_min][96]");
        assert_contains(&log, "[-b:v][15000000]");
        assert_contains(&log, "[-maxrate][15000000]");
        assert_contains(&log, "[-bufsize][30000000]");
        assert_contains(&log, "[-c:v][libx264]");
        assert!(
            !log.contains("[-threads][0]"),
            "software path should not use zero threads:\n{log}"
        );
    });
}

#[test]
fn transcode_video_segment_hardware_contract_is_stable() {
    with_fake_ffmpeg("command_log", |log_path| {
        let config = TranscodeConfig {
            hwaccel: Some(HwAccelConfig::nvenc()),
            ..TranscodeConfig::browser()
        };
        let mut process = run_async(HlsEngine::transcode_video_segment(
            "input.mkv",
            0.0,
            4.0,
            &config,
        ))
        .expect("hardware transcode spawn");
        let status = run_async(process.wait()).expect("hardware transcode wait");
        assert!(status.success());

        let log = read_log(log_path);
        assert_contains(&log, "[-threads][0]");
        assert_contains(&log, "[-c:v][h264_nvenc]");
        assert_contains(&log, "[-g][96]");
        assert_contains(&log, "[-keyint_min][96]");
        assert!(
            !log.contains("[-sc_threshold][0]"),
            "hardware path should not emit sc_threshold:\n{log}"
        );
    });
}

#[test]
fn transcode_audio_segment_contract_is_stable() {
    with_fake_ffmpeg("command_log", |log_path| {
        let config = TranscodeConfig::browser();
        let mut process = run_async(HlsEngine::transcode_audio_segment(
            "input.mkv",
            0.0,
            4.0,
            3,
            &config,
        ))
        .expect("audio transcode spawn");
        let status = run_async(process.wait()).expect("audio transcode wait");
        assert!(status.success());

        let log = read_log(log_path);
        assert_contains(&log, "[-threads][1]");
        assert_contains(&log, "[-map][0:3]");
        assert_contains(&log, "[-c:a][aac]");
        assert_contains(&log, "[-b:a][256k]");
    });
}

#[test]
fn gop_frames_is_four_seconds_only_at_24_fps() {
    let config = TranscodeConfig::browser();
    assert_eq!(config.video_bitrate, "15M");
    assert_eq!(config.audio_bitrate, "256k");
    assert_eq!(config.gop_frames, 96);
    assert_eq!(config.gop_frames as f64 / 24.0, 4.0);
    assert_eq!(config.gop_frames as f64 / 30.0, 3.2);
}

#[ignore = "HLS-024A documents the current 96-frame GOP defect at 30 fps"]
#[test]
fn hls_024a_gop_is_four_seconds_at_30_fps() {
    let config = TranscodeConfig::browser();
    assert_eq!(config.gop_frames as f64 / 30.0, 4.0);
}
