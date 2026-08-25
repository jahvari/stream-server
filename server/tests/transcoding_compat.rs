use std::ffi::OsString;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use enginefs::hls::{HlsEngine, TranscodeConfig};
use enginefs::hwaccel::HwAccelConfig;
use librqbit::{CreateTorrentOptions, create_torrent};
use reqwest::blocking::Client;
use serde_json::{Value, json};

const SERVER_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

struct StatusCase {
    name: &'static str,
    path: String,
    status: reqwest::StatusCode,
    body: &'static str,
}

struct PlaylistCase {
    name: &'static str,
    path: String,
}

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
    fake_release: Option<OsString>,
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
        let fake_release = std::env::var_os("FAKE_FFMPEG_RELEASE");

        let new_path = std::env::join_paths(
            std::iter::once(bin_dir.to_path_buf())
                .chain(path.as_deref().into_iter().flat_map(std::env::split_paths)),
        )
        .expect("join fake ffmpeg PATH");

        set_env_var("PATH", new_path);
        set_env_var("FAKE_FFMPEG_LOG", log_path.as_os_str());
        set_env_var("FAKE_FFMPEG_SCENARIO", scenario);
        set_env_var(
            "FAKE_FFMPEG_RELEASE",
            log_path.with_file_name("release-probe"),
        );
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
            fake_release,
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
        match &self.fake_release {
            Some(value) => set_env_var("FAKE_FFMPEG_RELEASE", value),
            None => remove_env_var("FAKE_FFMPEG_RELEASE"),
        }
    }
}

fn fake_ffmpeg_source() -> &'static str {
    r#"
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

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

fn emit_probe(video_rate_fields: &str) {
    eprintln!("Input #0, matroska,webm, from \"fixture-input\":");
    eprintln!("Duration: 00:00:10.00, start: 0.000000, bitrate: 1200 kb/s");
    eprintln!(
        "Stream #0:0(eng): Video: h264 (High), yuv420p, 1920x1080, {video_rate_fields}"
    );
}

fn read_loopback_until_release(args: &[String]) {
    let input = args
        .windows(2)
        .find(|pair| pair[0] == "-i")
        .map(|pair| pair[1].as_str())
        .expect("probe input argument");
    let rest = input.strip_prefix("http://").expect("numeric loopback HTTP input");
    let (authority, path) = rest.split_once('/').expect("loopback URL path");
    let mut stream = TcpStream::connect(authority).expect("connect loopback stream");
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("set loopback read timeout");
    write!(
        stream,
        "GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )
    .expect("write loopback request");
    stream.flush().expect("flush loopback request");
    append_raw("probe_loopback_read_started");

    let release = PathBuf::from(env::var_os("FAKE_FFMPEG_RELEASE").expect("release path"));
    let mut buffer = [0_u8; 1024];
    while !release.exists() {
        match stream.read(&mut buffer) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("loopback read failed: {error}"),
        }
    }
    append_raw("probe_loopback_read_released");
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
        Ok("probe_ready") => {
            eprintln!("Input #0, matroska,webm, from \"sample.mkv\":");
            eprintln!("Duration: 00:00:10.00, start: 0.000000, bitrate: 1200 kb/s");
            eprintln!("Stream #0:0(eng): Video: hevc (Main 10), yuv420p10le(tv), 3840x2160, 23.98 fps, 24000/1001 tbr, 1k tbn");
            eprintln!("Stream #0:1(jpn): Audio: aac (LC), 48000 Hz, stereo, fltp, 256 kb/s (default)");
        }
        Ok("probe_rate_cfr") => emit_probe("24 fps, 24 tbr, 1k tbn"),
        Ok("probe_rate_conflicting") => emit_probe("24 fps, 30000/1001 tbr, 1k tbn"),
        Ok("probe_rate_nominal_only") => emit_probe("24000/1001 tbr, 1k tbn"),
        Ok("probe_rate_missing") => emit_probe("1k tbn"),
        Ok("probe_loopback_blocked") => read_loopback_until_release(&args),
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
    let ffmpeg_path = bin_dir.join(format!("ffmpeg{}", std::env::consts::EXE_SUFFIX));
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

fn valid_hls_id(info_hash: &str) -> String {
    format!("{info_hash}-0")
}

fn accepted_playlist_cases(info_hash: &str) -> Vec<PlaylistCase> {
    let hls_id = valid_hls_id(info_hash);
    vec![
        PlaylistCase {
            name: "hlsv2 hls alias is accepted",
            path: format!("/hlsv2/{hls_id}/hls.m3u8"),
        },
        PlaylistCase {
            name: "hlsv2 stream playlist alias is accepted",
            path: format!("/hlsv2/{hls_id}/stream-0.m3u8"),
        },
        PlaylistCase {
            name: "legacy master playlist is accepted",
            path: format!("/{info_hash}/0/master.m3u8"),
        },
        PlaylistCase {
            name: "legacy hls playlist is accepted",
            path: format!("/{info_hash}/0/hls.m3u8"),
        },
        PlaylistCase {
            name: "legacy default stream playlist is accepted",
            path: format!("/{info_hash}/0/stream.m3u8"),
        },
        PlaylistCase {
            name: "legacy numbered stream playlist is accepted",
            path: format!("/{info_hash}/0/stream-0.m3u8"),
        },
        PlaylistCase {
            name: "legacy quality stream playlist is accepted",
            path: format!("/{info_hash}/0/stream-q-360p.m3u8"),
        },
    ]
}

fn rejected_resource_cases(info_hash: &str) -> Vec<StatusCase> {
    let hls_id = valid_hls_id(info_hash);
    vec![
        StatusCase {
            name: "hlsv2 master alias stays owned by mediaURL route",
            path: format!("/hlsv2/{hls_id}/master.m3u8"),
            status: reqwest::StatusCode::BAD_REQUEST,
            body: "Missing mediaURL",
        },
        StatusCase {
            name: "hlsv2 init segments stay unsupported",
            path: format!("/hlsv2/{hls_id}/init.mp4"),
            status: reqwest::StatusCode::NOT_IMPLEMENTED,
            body: r#"{"error":"hlsv2 fMP4 media segments is not implemented"}"#,
        },
        StatusCase {
            name: "hlsv2 nonnumeric segment aliases stay unsupported",
            path: format!("/hlsv2/{hls_id}/segmentbogus.ts"),
            status: reqwest::StatusCode::NOT_IMPLEMENTED,
            body: r#"{"error":"hlsv2 fMP4 media segments is not implemented"}"#,
        },
        StatusCase {
            name: "hlsv2 unknown track resources stay 404",
            path: format!("/hlsv2/{hls_id}/captions.vtt"),
            status: reqwest::StatusCode::NOT_FOUND,
            body: "HLS resource not found",
        },
        StatusCase {
            name: "legacy dlna route stays unsupported",
            path: format!("/{info_hash}/0/dlna"),
            status: reqwest::StatusCode::NOT_IMPLEMENTED,
            body: r#"{"error":"legacy HLS DLNA discovery is not implemented"}"#,
        },
        StatusCase {
            name: "legacy subtitle playlists stay unsupported",
            path: format!("/{info_hash}/0/subs-0.m3u8"),
            status: reqwest::StatusCode::NOT_IMPLEMENTED,
            body: r#"{"error":"legacy HLS subtitle playlist is not implemented"}"#,
        },
        StatusCase {
            name: "legacy mp4 resources stay unsupported",
            path: format!("/{info_hash}/0/mp4stream0.ts"),
            status: reqwest::StatusCode::NOT_IMPLEMENTED,
            body: r#"{"error":"legacy HLS MP4 segments is not implemented"}"#,
        },
        StatusCase {
            name: "legacy unknown resources stay 404",
            path: format!("/{info_hash}/0/unknown.bin"),
            status: reqwest::StatusCode::NOT_FOUND,
            body: "legacy HLS resource not found",
        },
    ]
}

fn accepted_segment_variant_cases(info_hash: &str) -> Vec<StatusCase> {
    vec![
        StatusCase {
            name: "legacy stream variant dispatches to segment parser",
            path: format!("/{info_hash}/0/stream/not-a-segment.ts"),
            status: reqwest::StatusCode::BAD_REQUEST,
            body: "Invalid segment",
        },
        StatusCase {
            name: "legacy numbered stream variant dispatches to segment parser",
            path: format!("/{info_hash}/0/stream-0/not-a-segment.ts"),
            status: reqwest::StatusCode::BAD_REQUEST,
            body: "Invalid segment",
        },
        StatusCase {
            name: "legacy quality stream variant dispatches to segment parser",
            path: format!("/{info_hash}/0/stream-q-360p/not-a-segment.ts"),
            status: reqwest::StatusCode::BAD_REQUEST,
            body: "Invalid segment",
        },
        StatusCase {
            name: "legacy mp4 segment variants stay unsupported",
            path: format!("/{info_hash}/0/mp4stream/0.ts"),
            status: reqwest::StatusCode::NOT_IMPLEMENTED,
            body: r#"{"error":"legacy HLS MP4 segments is not implemented"}"#,
        },
        StatusCase {
            name: "legacy unknown segment variants stay unsupported",
            path: format!("/{info_hash}/0/audio/0.ts"),
            status: reqwest::StatusCode::NOT_IMPLEMENTED,
            body: r#"{"error":"legacy HLS segment variant is not implemented"}"#,
        },
    ]
}

fn accepted_numeric_segment_cases(info_hash: &str) -> Vec<PlaylistCase> {
    let hls_id = valid_hls_id(info_hash);
    vec![
        PlaylistCase {
            name: "legacy numeric video resource is accepted",
            path: format!("/{info_hash}/0/0.ts"),
        },
        PlaylistCase {
            name: "legacy numeric video stream segment is accepted",
            path: format!("/{info_hash}/0/stream/0.ts"),
        },
        PlaylistCase {
            name: "legacy numeric audio resource is accepted",
            path: format!("/{info_hash}/0/audio-1-0.ts"),
        },
        PlaylistCase {
            name: "legacy numeric audio stream segment is accepted",
            path: format!("/{info_hash}/0/stream/audio-1-0.ts"),
        },
        PlaylistCase {
            name: "hlsv2 numeric segment alias is accepted",
            path: format!("/hlsv2/{hls_id}/segment0.ts"),
        },
    ]
}

fn create_torrent_hex_fixture() -> (String, String) {
    let fixture_dir = tempfile::tempdir().expect("torrent fixture tempdir");
    let source_file = fixture_dir.path().join("compat-fixture.mkv");
    fs::write(&source_file, b"transcoding compatibility fixture")
        .expect("write torrent fixture file");
    let torrent = run_async(async {
        let spawner = librqbit::spawn_utils::BlockingSpawner::new(1);
        create_torrent(
            &source_file,
            CreateTorrentOptions {
                piece_length: Some(16 * 1024),
                ..Default::default()
            },
            &spawner,
        )
        .await
    })
    .expect("create torrent fixture");

    (
        hex::encode(
            torrent
                .as_bytes()
                .expect("serialize torrent fixture metadata"),
        ),
        torrent.info_hash().as_string(),
    )
}

fn ensure_cold_engine(client: &Client, base: &str) -> String {
    let (torrent_hex, info_hash) = create_torrent_hex_fixture();
    let response = client
        .post(format!("{base}/create"))
        .json(&json!({
            "torrent": torrent_hex
        }))
        .send()
        .expect("create cold engine request")
        .error_for_status()
        .expect("create cold engine status")
        .json::<Value>()
        .expect("create cold engine json");

    assert!(
        response.get("error").is_none(),
        "cold engine creation failed: {response}"
    );

    info_hash
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
fn old_scalar_fps_cannot_distinguish_conflicting_or_missing_nominal_and_average_rates() {
    let cfr = with_fake_ffmpeg("probe_rate_cfr", |_| {
        run_async(HlsEngine::probe_video("sample.mkv")).expect("CFR probe")
    });
    let conflicting = with_fake_ffmpeg("probe_rate_conflicting", |_| {
        run_async(HlsEngine::probe_video("sample.mkv")).expect("conflicting-rate probe")
    });
    let nominal_only = with_fake_ffmpeg("probe_rate_nominal_only", |_| {
        run_async(HlsEngine::probe_video("sample.mkv")).expect("nominal-only probe")
    });
    let no_rates = with_fake_ffmpeg("probe_rate_missing", |_| {
        run_async(HlsEngine::probe_video("sample.mkv")).expect("missing-rate probe")
    });

    // 24/1 nominal + 24/1 average (CFR) and 30000/1001 nominal + 24/1
    // average (conflicting/VFR evidence) collapse to the same scalar.
    assert_eq!(cfr.streams[0].fps, Some(24.0));
    assert_eq!(conflicting.streams[0].fps, cfr.streams[0].fps);

    // A present 24000/1001 nominal rate with missing average and a source with
    // both rates missing also collapse to `None`.
    assert_eq!(nominal_only.streams[0].fps, None);
    assert_eq!(no_rates.streams[0].fps, nominal_only.streams[0].fps);
}

#[test]
fn mp_002a_cold_torrent_loopback_probe_is_pending_without_a_starvation_signal() {
    // Binding MP-002A conclusion: the legacy control flow has no total probe
    // deadline, so a cold source can remain pending indefinitely while its
    // public state exposes neither progress nor a terminal starvation signal.
    // The planned 10-minute default and 30-minute hard ceiling are therefore
    // approved safety bounds, not compatibility regressions.
    with_fake_ffmpeg("probe_loopback_blocked", |log_path| {
        let release_path = log_path.with_file_name("release-probe");
        set_env_var("FAKE_FFMPEG_RELEASE", release_path.as_os_str());

        with_embedded_server(|client, base| {
            let info_hash = ensure_cold_engine(client, &base);
            let probe_url = format!("{base}/hlsv2/{}/hls.m3u8", valid_hls_id(&info_hash));
            let probe_client = Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("probe client");
            let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);

            std::thread::scope(|scope| {
                scope.spawn(|| {
                    let result = probe_client
                        .get(probe_url)
                        .send()
                        .map(|response| response.status());
                    done_tx.send(result).expect("send probe result");
                });

                let started_deadline = std::time::Instant::now() + Duration::from_secs(3);
                while !read_log(log_path).contains("probe_loopback_read_started")
                    && std::time::Instant::now() < started_deadline
                {
                    std::thread::yield_now();
                }
                assert_contains(&read_log(log_path), "probe_loopback_read_started");
                assert!(
                    done_rx.recv_timeout(Duration::from_millis(250)).is_err(),
                    "the real cold loopback probe unexpectedly reached a terminal condition"
                );

                let stats = client
                    .get(format!("{base}/{info_hash}/stats.json"))
                    .send()
                    .expect("cold torrent stats request")
                    .error_for_status()
                    .expect("cold torrent stats status")
                    .json::<Value>()
                    .expect("cold torrent stats json");
                assert_eq!(stats["downloaded"], 0);
                assert_eq!(stats["peers"], 0);
                assert_eq!(stats["files"][0]["downloaded"], 0);
                assert!(stats.get("sourceStarved").is_none());
                assert!(stats.get("probeFailure").is_none());

                fs::write(&release_path, b"release").expect("release blocked fake probe");
                let status = done_rx
                    .recv_timeout(Duration::from_secs(8))
                    .expect("released probe remained hung")
                    .expect("released probe request");
                assert_eq!(status, reqwest::StatusCode::OK);
            });
        });

        let log = read_log(log_path);
        assert_eq!(
            log.matches("probe_loopback_read_started").count(),
            log.matches("probe_loopback_read_released").count(),
            "every probe child must exit before fixture teardown:\n{log}"
        );
        remove_env_var("FAKE_FFMPEG_RELEASE");
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

#[test]
fn hls_resource_parser_tables_cover_current_route_contracts() {
    with_fake_ffmpeg("probe_ready", |log_path| {
        with_embedded_server(|client, base| {
            let info_hash = ensure_cold_engine(client, &base);

            for case in accepted_playlist_cases(&info_hash) {
                let response = client
                    .get(format!("{base}{}", case.path))
                    .send()
                    .expect(case.name);
                assert_eq!(
                    response.status(),
                    reqwest::StatusCode::OK,
                    "{} returned {}",
                    case.name,
                    response.status()
                );
                assert_eq!(
                    response
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some("application/vnd.apple.mpegurl"),
                    "{} content-type regressed",
                    case.name
                );
            }

            for case in rejected_resource_cases(&info_hash) {
                let response = client
                    .get(format!("{base}{}", case.path))
                    .send()
                    .expect(case.name);
                assert_eq!(response.status(), case.status, "{}", case.name);
                assert_eq!(
                    response.text().expect(case.name),
                    case.body,
                    "{}",
                    case.name
                );
            }

            for case in accepted_segment_variant_cases(&info_hash) {
                let response = client
                    .get(format!("{base}{}", case.path))
                    .send()
                    .expect(case.name);
                assert_eq!(response.status(), case.status, "{}", case.name);
                assert_eq!(
                    response.text().expect(case.name),
                    case.body,
                    "{}",
                    case.name
                );
            }

            for case in accepted_numeric_segment_cases(&info_hash) {
                let response = client
                    .get(format!("{base}{}", case.path))
                    .send()
                    .expect(case.name);
                assert_eq!(
                    response.status(),
                    reqwest::StatusCode::OK,
                    "{} returned {}",
                    case.name,
                    response.status()
                );
                assert_eq!(
                    response
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some("video/mp2t"),
                    "{} content-type regressed",
                    case.name
                );
            }
        });

        let log = read_log(log_path);
        assert_contains(&log, "[-analyzeduration][750000]");
    });
}
