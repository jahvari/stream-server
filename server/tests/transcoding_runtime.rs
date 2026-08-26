use std::{collections::BTreeSet, fs, path::Path};

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
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        return false;
    }
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

fn validate_declaration(source: &str) -> Result<String, &'static str> {
    let normalized = source.trim_matches(['"', '\'']).replace('\\', "/");
    if normalized.is_empty()
        || normalized.contains(['*', '?', '[', ']'])
        || normalized.ends_with('/')
        || normalized.split('/').any(|component| component == "..")
    {
        return Err("broad or unsafe package source");
    }
    if forbidden_runtime_payload(Path::new(&normalized), b"") {
        return Err("forbidden runtime source name");
    }
    Ok(normalized)
}

fn enumerate_authoritative_sources(
    wix: &str,
    cargo: &str,
    workflow: &str,
) -> Result<Vec<String>, &'static str> {
    let mut sources = BTreeSet::new();

    let mut remainder = wix;
    while let Some(start) = remainder.find("Source='") {
        remainder = &remainder[start + "Source='".len()..];
        let end = remainder.find('\'').ok_or("unterminated WiX source")?;
        sources.insert(validate_declaration(&remainder[..end])?);
        remainder = &remainder[end + 1..];
    }

    let mut in_assets = false;
    for line in cargo.lines() {
        let line = line.trim();
        if line == "assets = [" {
            in_assets = true;
            continue;
        }
        if in_assets && line == "]" {
            in_assets = false;
            continue;
        }
        if in_assets && line.starts_with("[\"") {
            let source = line[2..].split('"').next().ok_or("malformed Cargo asset")?;
            sources.insert(validate_declaration(source)?);
        }
    }

    for line in workflow.lines().map(str::trim) {
        let source = if let Some(rest) = line.strip_prefix("cp target/") {
            Some(format!(
                "target/{}",
                rest.split_ascii_whitespace().next().ok_or("malformed cp")?
            ))
        } else if ["target/", "payload/", "vendor/", "runtimes/"]
            .iter()
            .any(|prefix| line.starts_with(prefix))
        {
            Some(line.to_owned())
        } else {
            None
        };
        if let Some(source) = source {
            sources.insert(validate_declaration(&source)?);
        }
    }

    if sources.is_empty() {
        return Err("no authoritative package sources");
    }
    Ok(sources.into_iter().collect())
}

fn resolved_declarations_are_safe(repository: &Path, sources: &[String]) -> bool {
    sources.iter().all(|source| {
        if source.contains("$(var.CargoTargetBinDir)") {
            return true;
        }
        let candidate = repository.join(source);
        !candidate.exists() || candidate_tree_is_safe(&candidate)
    })
}

#[test]
fn authoritative_release_declarations_enumerate_only_safe_runtime_free_inputs() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root");
    let wix =
        fs::read_to_string(repository.join("server/wix/main.wxs")).expect("read WiX declaration");
    let cargo =
        fs::read_to_string(repository.join("server/Cargo.toml")).expect("read Cargo declaration");
    let workflow = fs::read_to_string(repository.join(".github/workflows/release.yml"))
        .expect("read release workflow");

    let sources = enumerate_authoritative_sources(&wix, &cargo, &workflow)
        .expect("enumerate authoritative sources");
    assert!(
        sources.len() >= 6,
        "package declaration enumeration is unexpectedly incomplete"
    );
    assert!(resolved_declarations_are_safe(repository, &sources));
}

#[test]
fn mutated_authoritative_declarations_reject_broad_and_renamed_runtime_inputs() {
    let wix = "<File Source='target/release/server.exe'/>";
    let cargo = "assets = [\n[\"target/release/server\", \"usr/bin/server\", \"755\"],\n]";
    let workflow = "path: |\n  target/release/server.exe";
    assert!(enumerate_authoritative_sources(wix, cargo, workflow).is_ok());

    let globbed = "path: |\n  payload/**/*";
    assert!(enumerate_authoritative_sources(wix, cargo, globbed).is_err());
    let directory = "assets = [\n[\"target/release/\", \"usr/bin\", \"755\"],\n]";
    assert!(enumerate_authoritative_sources(wix, directory, workflow).is_err());

    let repository = tempfile::tempdir().expect("generated package staging");
    fs::create_dir_all(repository.path().join("payload")).expect("create payload directory");
    fs::write(
        repository.path().join("payload/codec-helper.exe"),
        b"MZ...ffmpeg version 7.1.4-Jellyfin",
    )
    .expect("write renamed runtime payload");
    let renamed_workflow = "path: |\n  payload/codec-helper.exe";
    let renamed = enumerate_authoritative_sources(wix, cargo, renamed_workflow)
        .expect("enumerate renamed fixture");
    assert!(!resolved_declarations_are_safe(repository.path(), &renamed));

    fs::write(repository.path().join("server.exe"), b"MZserver").expect("write server control");
    fs::create_dir_all(repository.path().join("vendor/native"))
        .expect("create vendored source control");
    fs::write(
        repository
            .path()
            .join("vendor/native/ffmpeg_api_source.cpp"),
        b"source only",
    )
    .expect("write source control");
    assert!(!forbidden_runtime_payload(
        Path::new("server.exe"),
        b"MZserver"
    ));
    assert!(!forbidden_runtime_payload(
        Path::new("vendor/native/ffmpeg_api_source.cpp"),
        b"source only"
    ));
}
