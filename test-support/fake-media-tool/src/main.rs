mod mpegts;

use serde::Deserialize;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{self, Command, ExitCode, Stdio};
use std::thread;
use std::time::Duration;

const SCENARIO_FILE: &str = "fake-media-tool.json";
const DEFAULT_VERSION: &str = "ffmpeg version 7.1.4-Jellyfin";
const DEFAULT_PROGRESS_INTERVAL_MS: u64 = 20;
const MAX_PROGRESS_INTERVAL_MS: u64 = 60_000;
const MAX_SEGMENT_NUMBER_WIDTH: usize = 20;
const OVERSIZED_LOG_LINES: usize = 4096;
const OVERLONG_LOG_LINE_BYTES: usize = 16 * 1024 + 1;
const STOP_FILE: &str = "fake-media-tool.stop";

fn main() -> ExitCode {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let scenario = match Scenario::load_from_current_dir() {
        Ok(scenario) => scenario,
        Err(error) => {
            eprintln!("fake_media_error={}", error.safe_code());
            return ExitCode::from(2);
        }
    };

    dispatch(&args, &scenario).unwrap_or_else(|error| {
        eprintln!("fake_media_error={}", error.safe_code());
        ExitCode::from(2)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum Mode {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "startupExit")]
    StartupExit,
    #[serde(rename = "exitAfterOutput")]
    ExitAfterOutput,
    #[serde(rename = "hang")]
    Hang,
    #[serde(rename = "stall")]
    Stall,
    #[serde(rename = "oversizedLog")]
    OversizedLog,
    #[serde(rename = "partialSegment")]
    PartialSegment,
    #[serde(rename = "slowStream")]
    SlowStream,
    #[serde(rename = "spawnDescendant")]
    SpawnDescendant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Scenario {
    mode: Mode,
    version: String,
    exit_code: u8,
    progress_interval_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScenario {
    mode: Option<Mode>,
    version: Option<String>,
    #[serde(rename = "exitCode")]
    exit_code: Option<i64>,
    #[serde(rename = "progressIntervalMs")]
    progress_interval_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeError {
    ScenarioRead,
    ScenarioSchema,
    InvalidExitCode,
    InvalidProgressInterval,
    InvalidArguments,
    UnsafeSegmentPattern,
    Io,
    Spawn,
}

impl FakeError {
    fn safe_code(self) -> &'static str {
        match self {
            Self::ScenarioRead => "scenario_read",
            Self::ScenarioSchema => "scenario_schema",
            Self::InvalidExitCode => "invalid_exit_code",
            Self::InvalidProgressInterval => "invalid_progress_interval",
            Self::InvalidArguments => "invalid_arguments",
            Self::UnsafeSegmentPattern => "unsafe_segment_pattern",
            Self::Io => "io",
            Self::Spawn => "spawn",
        }
    }
}

impl Scenario {
    fn load_from_current_dir() -> Result<Self, FakeError> {
        let cwd = env::current_dir().map_err(|_| FakeError::ScenarioRead)?;
        let exe_dir = env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf));
        Self::load_from_candidate_dirs(&cwd, exe_dir.as_deref())
    }

    #[cfg(test)]
    fn load_from_dir(dir: &Path) -> Result<Self, FakeError> {
        Self::load_from_candidate_dirs(dir, None)
    }

    fn load_from_candidate_dirs(cwd: &Path, adjacent: Option<&Path>) -> Result<Self, FakeError> {
        if let Some(scenario) = Self::load_from_exact_dir(cwd)? {
            return Ok(scenario);
        }

        if let Some(adjacent) = adjacent {
            if adjacent != cwd {
                if let Some(scenario) = Self::load_from_exact_dir(adjacent)? {
                    return Ok(scenario);
                }
            }
        }

        Ok(Self::default())
    }

    fn load_from_exact_dir(dir: &Path) -> Result<Option<Self>, FakeError> {
        let path = dir.join(SCENARIO_FILE);
        match fs::read_to_string(&path) {
            Ok(raw) => Self::parse_str(&raw).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(FakeError::ScenarioRead),
        }
    }

    fn parse_str(raw: &str) -> Result<Self, FakeError> {
        let raw: RawScenario = serde_json::from_str(raw).map_err(|_| FakeError::ScenarioSchema)?;
        let exit_code = match raw.exit_code {
            Some(value @ 0..=255) => value as u8,
            Some(_) => return Err(FakeError::InvalidExitCode),
            None => 0,
        };
        let progress_interval_ms = raw
            .progress_interval_ms
            .unwrap_or(DEFAULT_PROGRESS_INTERVAL_MS);
        if progress_interval_ms == 0 || progress_interval_ms > MAX_PROGRESS_INTERVAL_MS {
            return Err(FakeError::InvalidProgressInterval);
        }

        Ok(Self {
            mode: raw.mode.unwrap_or(Mode::Success),
            version: raw.version.unwrap_or_else(|| DEFAULT_VERSION.to_owned()),
            exit_code,
            progress_interval_ms,
        })
    }
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            mode: Mode::Success,
            version: DEFAULT_VERSION.to_owned(),
            exit_code: 0,
            progress_interval_ms: DEFAULT_PROGRESS_INTERVAL_MS,
        }
    }
}

fn dispatch(args: &[OsString], scenario: &Scenario) -> Result<ExitCode, FakeError> {
    if is_exact_invocation(args, "--fake-child") {
        wait_until_stopped("child")?;
        return Ok(ExitCode::SUCCESS);
    }

    match scenario.mode {
        Mode::Success => {
            if write_query_output(args, scenario)? {
                return Ok(ExitCode::from(scenario.exit_code));
            }
            write_media_output(args, mpegts::valid_segment())?;
            write_progress(args, ProgressFinish::End, &mut io::stderr())?;
            Ok(ExitCode::from(scenario.exit_code))
        }
        Mode::StartupExit => Ok(ExitCode::from(nonzero_exit_code(scenario.exit_code))),
        Mode::ExitAfterOutput => {
            if !write_query_output(args, scenario)? {
                write_media_output(args, mpegts::valid_segment())?;
                write_progress(args, ProgressFinish::End, &mut io::stderr())?;
            }
            Ok(ExitCode::from(nonzero_exit_code(scenario.exit_code)))
        }
        Mode::Hang => {
            write_media_output(args, mpegts::valid_segment())?;
            write_progress(args, ProgressFinish::ContinueOnly, &mut io::stderr())?;
            wait_until_stopped("hang")?;
            Ok(ExitCode::from(scenario.exit_code))
        }
        Mode::Stall => {
            wait_until_stopped("stall")?;
            Ok(ExitCode::from(scenario.exit_code))
        }
        Mode::OversizedLog => {
            write_oversized_log(&mut io::stderr())?;
            Ok(ExitCode::from(scenario.exit_code))
        }
        Mode::PartialSegment => {
            write_media_output(args, mpegts::partial_segment())?;
            write_progress(args, ProgressFinish::End, &mut io::stderr())?;
            Ok(ExitCode::from(scenario.exit_code))
        }
        Mode::SlowStream => {
            write_slow_stream(
                args,
                scenario.progress_interval_ms,
                &mut io::stdout(),
                &mut io::stderr(),
            )?;
            Ok(ExitCode::from(scenario.exit_code))
        }
        Mode::SpawnDescendant => {
            let exe = env::current_exe().map_err(|_| FakeError::Spawn)?;
            let cwd = env::current_dir().map_err(|_| FakeError::Spawn)?;
            spawn_descendant(&exe, &cwd)?;
            wait_until_stopped("parent")?;
            Ok(ExitCode::from(scenario.exit_code))
        }
    }
}

fn write_query_output(args: &[OsString], scenario: &Scenario) -> Result<bool, FakeError> {
    let Some(output) = query_output(args, scenario) else {
        return Ok(false);
    };

    io::stdout()
        .write_all(output.as_bytes())
        .map_err(|_| FakeError::Io)?;
    Ok(true)
}

fn query_output(args: &[OsString], scenario: &Scenario) -> Option<String> {
    if is_inventory_query(args, "-version") {
        return Some(version_output(&scenario.version));
    }
    if is_inventory_query(args, "-buildconf") {
        return Some(buildconf_output(&scenario.version));
    }
    if is_inventory_query(args, "-hwaccels") {
        return Some(HWACCELS.to_owned());
    }
    if is_inventory_query(args, "-encoders") {
        return Some(ENCODERS.to_owned());
    }
    if is_inventory_query(args, "-decoders") {
        return Some(DECODERS.to_owned());
    }
    if is_inventory_query(args, "-filters") {
        return Some(FILTERS.to_owned());
    }
    if requests_json_probe(args) {
        return Some(PROBE_JSON.to_owned());
    }
    None
}

fn is_exact_invocation(args: &[OsString], flag: &str) -> bool {
    matches!(args, [only] if only == flag)
}

fn is_inventory_query(args: &[OsString], query: &str) -> bool {
    is_exact_invocation(args, query)
        || matches!(args, [hide_banner, requested]
            if hide_banner == "-hide_banner" && requested == query)
}

fn requests_json_probe(args: &[OsString]) -> bool {
    let mut has_json_output = false;
    let mut has_show_request = false;
    let mut index = 0;

    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            break;
        }
        if [
            "-of",
            "-print_format",
            "-v",
            "-loglevel",
            "-select_streams",
            "-show_entries",
            "-analyzeduration",
            "-probesize",
            "-read_intervals",
            "-i",
        ]
        .iter()
        .any(|option| argument == option)
        {
            let Some(value) = args.get(index + 1) else {
                return false;
            };
            if (argument == "-of" || argument == "-print_format") && value == "json" {
                has_json_output = true;
            }
            index += 2;
            continue;
        }

        if ["-show_format", "-show_streams", "-show_chapters"]
            .iter()
            .any(|option| argument == option)
        {
            has_show_request = true;
            index += 1;
            continue;
        }

        if argument == "-hide_banner"
            || argument == "-count_frames"
            || argument == "-count_packets"
            || argument == "-sexagesimal"
            || argument == "-pretty"
            || argument == "-"
            || !argument.to_string_lossy().starts_with('-')
        {
            index += 1;
            continue;
        }

        return false;
    }

    has_json_output && has_show_request
}

fn version_output(version: &str) -> String {
    format!(
        "{version}\nbuilt with rust fake-media-tool\nconfiguration: --enable-gpl --enable-libx264 --enable-nvenc --enable-libmfx --enable-vaapi --enable-amf --enable-videotoolbox\nlibavutil      59. 39.100 / 59. 39.100\nlibavcodec     61. 19.101 / 61. 19.101\nlibavformat    61.  7.100 / 61.  7.100\n"
    )
}

fn buildconf_output(version: &str) -> String {
    format!(
        "{version}\nconfiguration:\n  --enable-gpl\n  --enable-libx264\n  --enable-libx265\n  --enable-libmfx\n  --enable-nvenc\n  --enable-cuda\n  --enable-vaapi\n  --enable-amf\n  --enable-videotoolbox\n  --enable-v4l2-m2m\n"
    )
}

const HWACCELS: &str = "\
Hardware acceleration methods:
vdpau
cuda
vaapi
qsv
drm
opencl
vulkan
d3d11va
dxva2
videotoolbox
";

const ENCODERS: &str = "\
Encoders:
 V..... h264_qsv             H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10 (Intel Quick Sync Video)
 V..... hevc_qsv             H.265 / HEVC (Intel Quick Sync Video)
 V..... h264_nvenc           NVIDIA NVENC H.264 encoder
 V..... hevc_nvenc           NVIDIA NVENC HEVC encoder
 V..... h264_vaapi           H.264/AVC (VAAPI)
 V..... hevc_vaapi           H.265/HEVC (VAAPI)
 V..... h264_amf             AMD AMF H.264 encoder
 V..... hevc_amf             AMD AMF HEVC encoder
 V..... h264_videotoolbox    VideoToolbox H.264 encoder
 V..... h264_v4l2m2m         V4L2 mem2mem H.264 encoder wrapper
 V..... libx264              libx264 H.264 / AVC
 V..... libx265              libx265 H.265 / HEVC
";

const DECODERS: &str = "\
Decoders:
 V..... h264                  H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10
 V..... hevc                  H.265 / HEVC
 V..... h264_qsv             H264 video (Intel Quick Sync Video acceleration)
 V..... hevc_qsv             HEVC video (Intel Quick Sync Video acceleration)
 V..... h264_cuvid           Nvidia CUVID H264 decoder
 V..... hevc_cuvid           Nvidia CUVID HEVC decoder
 V..... h264_v4l2m2m         V4L2 mem2mem H.264 decoder wrapper
";

const FILTERS: &str = "\
Filters:
 ... scale             Scale the input video size and/or convert the image format.
 ... scale_qsv         Quick Sync Video scaling and format conversion.
 ... scale_cuda        GPU accelerated video resizer.
 ... scale_vaapi       VAAPI video scaling and format conversion.
 ... hwupload          Upload a normal frame to a hardware frame.
 ... hwdownload        Download a hardware frame to a normal frame.
 ... format            Convert the input video to one of the specified pixel formats.
 ... subtitles         Render text subtitles onto input video using the libass library.
";

const PROBE_JSON: &str = r#"{
  "streams": [
    {
      "index": 0,
      "codec_name": "h264",
      "codec_type": "video",
      "width": 1920,
      "height": 1080,
      "r_frame_rate": "30000/1001",
      "avg_frame_rate": "30000/1001",
      "time_base": "1/90000",
      "duration": "60.000000",
      "bit_rate": "4000000"
    },
    {
      "index": 1,
      "codec_name": "aac",
      "codec_type": "audio",
      "sample_rate": "48000",
      "channels": 2,
      "channel_layout": "stereo",
      "time_base": "1/48000",
      "duration": "60.000000",
      "bit_rate": "128000"
    }
  ],
  "chapters": [
    {
      "id": 0,
      "time_base": "1/1000",
      "start": 0,
      "start_time": "0.000000",
      "end": 60000,
      "end_time": "60.000000",
      "tags": {
        "title": "Chapter 1"
      }
    }
  ],
  "format": {
    "filename": "fixture-input",
    "nb_streams": 2,
    "nb_programs": 0,
    "format_name": "matroska,webm",
    "duration": "60.000000",
    "size": "12000000",
    "bit_rate": "4128000"
  }
}
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgressFinish {
    ContinueOnly,
    End,
}

fn write_progress(
    args: &[OsString],
    finish: ProgressFinish,
    stderr: &mut dyn Write,
) -> Result<(), FakeError> {
    if !requests_progress_pipe(args) {
        return Ok(());
    }

    stderr
        .write_all(progress_record("continue").as_bytes())
        .map_err(|_| FakeError::Io)?;
    if finish == ProgressFinish::End {
        stderr
            .write_all(progress_record("end").as_bytes())
            .map_err(|_| FakeError::Io)?;
    }
    Ok(())
}

fn requests_progress_pipe(args: &[OsString]) -> bool {
    args.windows(2)
        .any(|pair| pair[0] == "-progress" && pair[1] == "pipe:2")
}

fn progress_record(status: &str) -> String {
    format!(
        "frame=1\nfps=0.00\nstream_0_0_q=0.0\nbitrate=N/A\ntotal_size=564\nout_time_us=20000\nout_time_ms=20000\nout_time=00:00:00.020000\ndup_frames=0\ndrop_frames=0\nspeed=1.00x\nprogress={status}\n"
    )
}

fn write_media_output(args: &[OsString], bytes: &[u8]) -> Result<(), FakeError> {
    if let Some(request) = segment_request(args)? {
        publish_segment(
            &env::current_dir().map_err(|_| FakeError::Io)?,
            &request.pattern,
            request.start_number,
            bytes,
        )
    } else {
        io::stdout().write_all(bytes).map_err(|_| FakeError::Io)
    }
}

fn write_slow_stream(
    args: &[OsString],
    interval_ms: u64,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), FakeError> {
    if let Some(request) = segment_request(args)? {
        publish_segment(
            &env::current_dir().map_err(|_| FakeError::Io)?,
            &request.pattern,
            request.start_number,
            mpegts::valid_segment(),
        )?;
        write_progress(args, ProgressFinish::End, stderr)?;
        return Ok(());
    }

    for chunk in mpegts::valid_segment().chunks(mpegts::PACKET_SIZE) {
        stdout.write_all(chunk).map_err(|_| FakeError::Io)?;
        stdout.flush().map_err(|_| FakeError::Io)?;
        if requests_progress_pipe(args) {
            stderr
                .write_all(progress_record("continue").as_bytes())
                .map_err(|_| FakeError::Io)?;
        }
        thread::sleep(Duration::from_millis(interval_ms));
    }
    if requests_progress_pipe(args) {
        stderr
            .write_all(progress_record("end").as_bytes())
            .map_err(|_| FakeError::Io)?;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct SegmentRequest {
    pattern: String,
    start_number: u64,
}

fn segment_request(args: &[OsString]) -> Result<Option<SegmentRequest>, FakeError> {
    let mut pattern = None;
    let mut start_number = 0;

    let mut index = 0;
    while index < args.len() {
        if args[index] == "-hls_segment_filename" {
            let value = args.get(index + 1).ok_or(FakeError::InvalidArguments)?;
            pattern = Some(os_to_string(value)?);
            index += 2;
            continue;
        }

        if args[index] == "-start_number" {
            let value = args.get(index + 1).ok_or(FakeError::InvalidArguments)?;
            start_number = os_to_string(value)?
                .parse::<u64>()
                .map_err(|_| FakeError::InvalidArguments)?;
            index += 2;
            continue;
        }

        index += 1;
    }

    pattern
        .map(|pattern| {
            Ok(SegmentRequest {
                pattern,
                start_number,
            })
        })
        .transpose()
}

fn os_to_string(value: &OsString) -> Result<String, FakeError> {
    value
        .to_str()
        .map(|value| value.to_owned())
        .ok_or(FakeError::InvalidArguments)
}

fn publish_segment(
    base_dir: &Path,
    pattern: &str,
    start_number: u64,
    bytes: &[u8],
) -> Result<(), FakeError> {
    let filename = render_segment_filename(pattern, start_number)?;
    let final_path = confined_child_path(base_dir, &filename)?;
    let temp_name = format!(".{}.{}.tmp", filename, process::id());
    let temp_path = confined_child_path(base_dir, &temp_name)?;

    fs::write(&temp_path, bytes).map_err(|_| FakeError::Io)?;
    fs::rename(&temp_path, &final_path).map_err(|_| {
        let _ = fs::remove_file(&temp_path);
        FakeError::Io
    })?;
    Ok(())
}

fn render_segment_filename(pattern: &str, number: u64) -> Result<String, FakeError> {
    reject_path_components(pattern)?;

    let percent = pattern.find('%').ok_or(FakeError::UnsafeSegmentPattern)?;
    let suffix_start = parse_number_placeholder(pattern, percent)?;
    let (head, placeholder_and_tail) = pattern.split_at(percent);
    let tail = &placeholder_and_tail[suffix_start - percent..];
    if tail.contains('%') {
        return Err(FakeError::UnsafeSegmentPattern);
    }
    let placeholder = &pattern[percent..suffix_start];
    let number = if let Some(width) = placeholder
        .strip_prefix("%0")
        .and_then(|value| value.strip_suffix('d'))
        .filter(|value| !value.is_empty())
    {
        let width = width
            .parse::<usize>()
            .map_err(|_| FakeError::UnsafeSegmentPattern)?;
        if width > MAX_SEGMENT_NUMBER_WIDTH {
            return Err(FakeError::UnsafeSegmentPattern);
        }
        format!("{number:0width$}")
    } else {
        number.to_string()
    };

    let rendered = format!("{head}{number}{tail}");
    reject_path_components(&rendered)?;
    Ok(rendered)
}

fn parse_number_placeholder(pattern: &str, percent: usize) -> Result<usize, FakeError> {
    let rest = &pattern[percent..];
    if rest.starts_with("%d") {
        return Ok(percent + 2);
    }

    let Some(after_zero) = rest.strip_prefix("%0") else {
        return Err(FakeError::UnsafeSegmentPattern);
    };
    let digits = after_zero
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .count();
    if digits == 0 || !after_zero[digits..].starts_with('d') {
        return Err(FakeError::UnsafeSegmentPattern);
    }
    Ok(percent + 3 + digits)
}

fn confined_child_path(base_dir: &Path, filename: &str) -> Result<PathBuf, FakeError> {
    reject_path_components(filename)?;
    Ok(base_dir.join(filename))
}

fn reject_path_components(value: &str) -> Result<(), FakeError> {
    let path = Path::new(value);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) if !path.is_absolute() => Ok(()),
        _ => Err(FakeError::UnsafeSegmentPattern),
    }
}

fn write_oversized_log(stderr: &mut dyn Write) -> Result<(), FakeError> {
    stderr
        .write_all(&[b'x'; OVERLONG_LOG_LINE_BYTES])
        .map_err(|_| FakeError::Io)?;
    stderr.write_all(b"\n").map_err(|_| FakeError::Io)?;
    stderr
        .write_all(b"fake_media_malformed_utf8=\xff\xfe\n")
        .map_err(|_| FakeError::Io)?;
    for index in 0..OVERSIZED_LOG_LINES {
        writeln!(
            stderr,
            "fake_media_diagnostic line={index:04} category=oversized-log message=deterministic-fixture-no-secret"
        )
        .map_err(|_| FakeError::Io)?;
    }
    Ok(())
}

fn spawn_descendant(exe: &Path, cwd: &Path) -> Result<process::Child, FakeError> {
    Command::new(exe)
        .arg("--fake-child")
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| FakeError::Spawn)
}

fn wait_until_stopped(role: &str) -> Result<(), FakeError> {
    ignore_graceful_termination();
    let cwd = env::current_dir().map_err(|_| FakeError::Io)?;
    fs::write(
        cwd.join(format!("fake-media-{role}.pid")),
        process::id().to_string(),
    )
    .map_err(|_| FakeError::Io)?;

    loop {
        if cwd.join(STOP_FILE).exists() {
            fs::write(cwd.join(format!("fake-media-{role}.exited")), b"exited")
                .map_err(|_| FakeError::Io)?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn ignore_graceful_termination() {
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
}

#[cfg(not(unix))]
fn ignore_graceful_termination() {}

fn nonzero_exit_code(exit_code: u8) -> u8 {
    if exit_code == 0 {
        1
    } else {
        exit_code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_valid_scenario_with_explicit_values() {
        let scenario = Scenario::parse_str(
            r#"{
                "mode": "startupExit",
                "version": "ffmpeg version test-fixture",
                "exitCode": 7,
                "progressIntervalMs": 25
            }"#,
        )
        .expect("valid scenario parses");

        assert_eq!(scenario.mode, Mode::StartupExit);
        assert_eq!(scenario.version, "ffmpeg version test-fixture");
        assert_eq!(scenario.exit_code, 7);
        assert_eq!(scenario.progress_interval_ms, 25);
    }

    #[test]
    fn parses_all_closed_mode_values() {
        let modes = [
            ("success", Mode::Success),
            ("startupExit", Mode::StartupExit),
            ("exitAfterOutput", Mode::ExitAfterOutput),
            ("hang", Mode::Hang),
            ("stall", Mode::Stall),
            ("oversizedLog", Mode::OversizedLog),
            ("partialSegment", Mode::PartialSegment),
            ("slowStream", Mode::SlowStream),
            ("spawnDescendant", Mode::SpawnDescendant),
        ];

        for (raw, expected) in modes {
            let scenario = Scenario::parse_str(&format!(r#"{{ "mode": "{raw}" }}"#))
                .expect("closed mode value parses");
            assert_eq!(scenario.mode, expected);
        }
    }

    #[test]
    fn absent_scenario_file_uses_deterministic_defaults() {
        let dir = tempdir().expect("temp dir");
        let scenario = Scenario::load_from_dir(dir.path()).expect("absent scenario defaults");

        assert_eq!(scenario, Scenario::default());
    }

    #[test]
    fn adjacent_scenario_is_used_when_current_directory_file_is_absent() {
        let cwd = tempdir().expect("current temp dir");
        let adjacent = tempdir().expect("adjacent temp dir");
        fs::write(
            adjacent.path().join(SCENARIO_FILE),
            r#"{ "mode": "oversizedLog", "exitCode": 9 }"#,
        )
        .expect("write adjacent scenario");

        let scenario =
            Scenario::load_from_candidate_dirs(cwd.path(), Some(adjacent.path())).expect("load");

        assert_eq!(scenario.mode, Mode::OversizedLog);
        assert_eq!(scenario.exit_code, 9);
    }

    #[test]
    fn rejects_unknown_scenario_fields_without_echoing_field_name() {
        let error = Scenario::parse_str(r#"{ "mode": "success", "unexpected": true }"#)
            .expect_err("unknown fields are rejected");

        assert_eq!(error.safe_code(), "scenario_schema");
        assert!(!error.safe_code().contains("unexpected"));
    }

    #[test]
    fn rejects_impossible_exit_codes() {
        for exit_code in [-1, 256] {
            let error = Scenario::parse_str(&format!(r#"{{ "exitCode": {exit_code} }}"#))
                .expect_err("invalid exit code rejected");
            assert_eq!(error.safe_code(), "invalid_exit_code");
        }
    }

    #[test]
    fn rejects_zero_or_unbounded_progress_interval() {
        for interval in [0, MAX_PROGRESS_INTERVAL_MS + 1] {
            let error = Scenario::parse_str(&format!(r#"{{ "progressIntervalMs": {interval} }}"#))
                .expect_err("invalid progress interval rejected");
            assert_eq!(error.safe_code(), "invalid_progress_interval");
        }
    }

    #[test]
    fn query_dispatch_uses_os_arguments_and_never_echoes_input_paths() {
        let args = os_args([
            "-v",
            "quiet",
            "-of",
            "json",
            "-show_streams",
            "C:\\private\\movie.mkv",
        ]);
        let output = query_output(&args, &Scenario::default()).expect("probe query output");
        let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid JSON probe");

        assert_eq!(parsed["streams"][0]["codec_type"], "video");
        assert_eq!(parsed["streams"][0]["r_frame_rate"], "30000/1001");
        assert_eq!(parsed["format"]["filename"], "fixture-input");
        assert!(!output.contains("private"));
        assert!(!output.contains("movie.mkv"));
    }

    #[test]
    fn probe_control_tokens_used_as_input_values_are_not_dispatched_as_queries() {
        for input_value in ["-show_streams", "-show_format", "-show_chapters"] {
            let args = os_args(["-of", "json", "-i", input_value]);
            assert_eq!(
                query_output(&args, &Scenario::default()),
                None,
                "input value {input_value} activated JSON probe mode"
            );
        }

        let after_option_delimiter = os_args(["-of", "json", "--", "-show_streams"]);
        assert_eq!(
            query_output(&after_option_delimiter, &Scenario::default()),
            None
        );
    }

    #[test]
    fn print_format_probe_with_value_options_is_recognized() {
        let args = os_args([
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_streams",
            "-select_streams",
            "s",
            "fixture-input",
        ]);

        assert!(query_output(&args, &Scenario::default()).is_some());
    }

    #[test]
    fn inventory_outputs_include_representative_hardware_names() {
        let scenario = Scenario {
            version: "ffmpeg version custom".to_owned(),
            ..Scenario::default()
        };

        let version = query_output(&os_args(["-version"]), &scenario).expect("version output");
        let hwaccels = query_output(&os_args(["-hwaccels"]), &scenario).expect("hwaccel output");
        let encoders = query_output(&os_args(["-encoders"]), &scenario).expect("encoder output");

        assert!(version.contains("ffmpeg version custom"));
        assert!(hwaccels.contains("qsv"));
        assert!(hwaccels.contains("cuda"));
        assert!(hwaccels.contains("vaapi"));
        assert!(encoders.contains("h264_nvenc"));
        assert!(encoders.contains("h264_amf"));
        assert!(encoders.contains("h264_videotoolbox"));
        assert!(encoders.contains("h264_v4l2m2m"));
    }

    #[test]
    fn progress_records_are_deterministic_and_terminated() {
        let args = os_args(["-progress", "pipe:2"]);
        let mut stderr = Vec::new();

        write_progress(&args, ProgressFinish::End, &mut stderr).expect("progress writes");

        let output = String::from_utf8(stderr).expect("utf8 progress");
        assert_eq!(output.matches("progress=continue").count(), 1);
        assert_eq!(output.matches("progress=end").count(), 1);
        assert!(output.ends_with("progress=end\n"));
    }

    #[test]
    fn oversized_log_contains_bounded_capture_and_decoder_stressors() {
        let mut stderr = Vec::new();

        write_oversized_log(&mut stderr).expect("oversized log writes");

        assert!(stderr.len() > 256 * 1024);
        assert!(
            stderr
                .split(|byte| *byte == b'\n')
                .any(|line| line.len() > 16 * 1024),
            "fixture must exercise overlong diagnostic lines"
        );
        assert!(
            std::str::from_utf8(&stderr).is_err(),
            "fixture must exercise malformed UTF-8 diagnostics"
        );
    }

    #[test]
    fn hls_segment_pattern_uses_start_number_and_atomic_sibling_publish() {
        let dir = tempdir().expect("temp dir");

        publish_segment(dir.path(), "segment_%03d.ts", 42, mpegts::valid_segment())
            .expect("segment published");

        let final_path = dir.path().join("segment_042.ts");
        assert_eq!(
            fs::read(&final_path).expect("segment bytes"),
            mpegts::valid_segment()
        );
        let entries = fs::read_dir(dir.path()).expect("read temp dir").count();
        assert_eq!(entries, 1);
    }

    #[test]
    fn hls_segment_pattern_rejects_absolute_traversal_or_missing_number() {
        for pattern in [
            "../segment_%d.ts",
            "nested/segment_%d.ts",
            "/tmp/segment_%d.ts",
            "segment.ts",
            "segment_%03d_%d.ts",
            "segment_%03d_%.ts",
            "segment_%03d%",
            "segment_%021d.ts",
        ] {
            let error = render_segment_filename(pattern, 0).expect_err("unsafe pattern rejected");
            assert_eq!(error, FakeError::UnsafeSegmentPattern);
        }
    }

    #[test]
    fn slow_stream_writes_bounded_chunks_and_final_progress() {
        let args = os_args(["-progress", "pipe:2"]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        write_slow_stream(&args, 1, &mut stdout, &mut stderr).expect("slow stream writes");

        assert_eq!(stdout, mpegts::valid_segment());
        let progress = String::from_utf8(stderr).expect("utf8 progress");
        assert!(progress.contains("progress=continue"));
        assert!(progress.ends_with("progress=end\n"));
    }

    #[test]
    fn startup_and_failure_modes_normalize_zero_exit_code() {
        assert_eq!(nonzero_exit_code(0), 1);
        assert_eq!(nonzero_exit_code(17), 17);
    }

    fn os_args<const N: usize>(values: [&str; N]) -> Vec<OsString> {
        values.into_iter().map(OsString::from).collect()
    }
}
