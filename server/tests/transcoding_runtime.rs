use std::{fs, path::Path};

fn forbidden_runtime_payload(path: &Path, bytes: &[u8]) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        file_name.as_str(),
        "ffmpeg" | "ffmpeg.exe" | "ffprobe" | "ffprobe.exe"
    ) {
        return true;
    }
    if normalized.split('/').any(|component| {
        component == "runtimes"
            || component == "staging"
            || component.starts_with("install-v")
            || component.starts_with("archive-v")
    }) {
        return true;
    }
    let archive = [".zip", ".7z", ".tar", ".tar.gz", ".tgz"]
        .iter()
        .any(|extension| normalized.ends_with(extension));
    if archive && (normalized.contains("ffmpeg") || bytes.starts_with(b"PK\x03\x04")) {
        return true;
    }
    bytes.starts_with(b"MZ")
        && [
            b"ffmpeg version".as_slice(),
            b"ffprobe version",
            b"jellyfin-ffmpeg",
        ]
        .iter()
        .any(|marker| {
            bytes
                .windows(marker.len())
                .any(|window| window.eq_ignore_ascii_case(marker))
        })
}

fn candidate_tree_is_safe(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if metadata.is_dir() {
        fs::read_dir(path).is_ok_and(|entries| {
            entries
                .filter_map(Result::ok)
                .all(|entry| candidate_tree_is_safe(&entry.path()))
        })
    } else {
        fs::read(path).is_ok_and(|bytes| !forbidden_runtime_payload(path, &bytes))
    }
}

fn explicit_package_source_is_safe(source: &str) -> bool {
    !source.contains(['*', '?', '[', ']'])
        && !source.ends_with(['/', '\\'])
        && !forbidden_runtime_payload(Path::new(source), b"")
}

fn package_declaration_tokens(document: &str) -> impl Iterator<Item = String> + '_ {
    document
        .split(|character: char| {
            character.is_ascii_whitespace()
                || matches!(
                    character,
                    '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | ','
                )
        })
        .map(|token| {
            token
                .trim_matches(|character: char| matches!(character, ':' | ';'))
                .replace('\\', "/")
                .to_ascii_lowercase()
        })
        .filter(|token| !token.is_empty())
}

#[test]
fn release_package_inputs_never_include_ffmpeg_executables_or_runtime_archives() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root");
    let package_inputs = [
        repository.join("server/wix/main.wxs"),
        repository.join("server/Cargo.toml"),
        repository.join(".github/workflows/release.yml"),
    ];
    for input in package_inputs {
        let document = fs::read_to_string(&input).expect("read release package input");
        for normalized in package_declaration_tokens(&document) {
            let file_name = normalized.rsplit('/').next().unwrap_or_default();
            let executable = matches!(
                file_name,
                "ffmpeg" | "ffmpeg.exe" | "ffprobe" | "ffprobe.exe"
            );
            let archive = (normalized.contains("ffmpeg") || normalized.contains("ffprobe"))
                && [".zip", ".7z", ".tar", ".tar.gz", ".tgz"]
                    .iter()
                    .any(|extension| normalized.ends_with(extension));
            assert!(
                !executable && !archive,
                "release package input {} includes forbidden runtime payload token {normalized:?}",
                input.display()
            );
        }
    }

    // Concrete sources currently copied into Windows, Debian, AppImage and Arch packages.
    for source in [
        "target/release/server",
        "target/release/settings-gui",
        "target/x86_64-pc-windows-msvc/release/server.exe",
        "target/x86_64-pc-windows-msvc/release/settings-gui.exe",
        "target/x86_64-pc-windows-msvc/release/stremio-runtime.exe",
        "target/x86_64-pc-windows-msvc/release/stream-server-updater.exe",
    ] {
        assert!(explicit_package_source_is_safe(source));
    }
}

#[test]
fn release_candidate_scanner_rejects_globs_directories_renames_archives_and_staging() {
    let directory = tempfile::tempdir().expect("release scanner fixture");
    let staged = directory
        .path()
        .join("runtimes/staging/install-v7.1.4-3-6f92c7b2-2f42-48f5-b334-01d19d842ad8");
    fs::create_dir_all(&staged).expect("create generated staging tree");
    let renamed = staged.join("codec-helper.exe");
    fs::write(&renamed, b"MZ....ffmpeg version 7.1.4-Jellyfin").expect("write renamed runtime PE");
    assert!(forbidden_runtime_payload(
        &renamed,
        &fs::read(&renamed).unwrap()
    ));
    assert!(forbidden_runtime_payload(
        Path::new("payload/runtime.zip"),
        b"PK\x03\x04archive"
    ));
    assert!(!candidate_tree_is_safe(directory.path()));
    assert!(!explicit_package_source_is_safe("release/**/*"));
    assert!(!explicit_package_source_is_safe("target/release/"));
    assert!(!forbidden_runtime_payload(
        Path::new("server.exe"),
        b"MZserver"
    ));
    assert!(!forbidden_runtime_payload(
        Path::new("vendor/native/ffmpeg_api_source.cpp"),
        b"source only"
    ));
}
