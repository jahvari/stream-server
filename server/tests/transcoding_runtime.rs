use std::{fs, path::Path};

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
        for token in document.split(|character: char| {
            character.is_ascii_whitespace()
                || matches!(
                    character,
                    '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | ','
                )
        }) {
            let normalized = token
                .trim_matches(|character: char| matches!(character, ':' | ';'))
                .replace('\\', "/")
                .to_ascii_lowercase();
            let file_name = normalized.rsplit('/').next().unwrap_or_default();
            let is_runtime_executable = matches!(
                file_name,
                "ffmpeg" | "ffmpeg.exe" | "ffprobe" | "ffprobe.exe"
            );
            let is_runtime_archive = (normalized.contains("ffmpeg")
                || normalized.contains("ffprobe"))
                && [".zip", ".7z", ".tar", ".tar.gz", ".tgz"]
                    .iter()
                    .any(|extension| normalized.ends_with(extension));
            assert!(
                !is_runtime_executable && !is_runtime_archive,
                "release package input {} includes forbidden runtime payload token {token:?}",
                input.display()
            );
        }
    }
}
