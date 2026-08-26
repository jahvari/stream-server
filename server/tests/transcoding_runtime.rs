use quick_xml::{Reader, XmlVersion, events::Event};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const ALLOWED_APPLICATION_PE: &[&str] = &[
    "target/x86_64-pc-windows-msvc/release/server.exe",
    "target/x86_64-pc-windows-msvc/release/settings-gui.exe",
    "target/x86_64-pc-windows-msvc/release/stremio-runtime.exe",
    "target/x86_64-pc-windows-msvc/release/stream-server-updater.exe",
];

fn normalized(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_matches(['"', '\''])
        .to_ascii_lowercase()
}

fn archive_magic(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08")
    ) || bytes.starts_with(b"7z\xBC\xAF\x27\x1C")
        || bytes.starts_with(&[0x1f, 0x8b])
        || bytes.get(257..262) == Some(b"ustar")
}

fn forbidden_runtime_payload(path: &Path, bytes: &[u8]) -> bool {
    let path = normalized(path);
    let file_name = path.rsplit('/').next().unwrap_or_default();
    if matches!(
        file_name,
        "ffmpeg" | "ffmpeg.exe" | "ffprobe" | "ffprobe.exe"
    ) {
        return true;
    }
    if path.split('/').any(|component| {
        component == "runtimes"
            || component == "staging"
            || component.starts_with("install-v")
            || component.starts_with("archive-v")
    }) {
        return true;
    }
    if archive_magic(bytes) {
        return true;
    }
    bytes.starts_with(b"MZ")
        && !ALLOWED_APPLICATION_PE
            .iter()
            .any(|allowed| path == *allowed || path.ends_with(&format!("/{allowed}")))
}

#[cfg(windows)]
fn metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

fn candidate_tree_is_safe(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() || metadata_is_reparse(&metadata) {
        return false;
    }
    if metadata.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        entries
            .filter_map(Result::ok)
            .all(|entry| candidate_tree_is_safe(&entry.path()))
    } else if metadata.is_file() {
        fs::read(path).is_ok_and(|bytes| !forbidden_runtime_payload(path, &bytes))
    } else {
        false
    }
}

fn validate_exact_source(source: &str) -> Result<String, &'static str> {
    let source = source.trim().trim_matches(['"', '\'']).replace('\\', "/");
    if source.is_empty()
        || source.contains(['*', '?', '[', ']'])
        || source.ends_with('/')
        || source.starts_with('/')
        || source.split('/').any(|component| component == "..")
        || source.contains("${{")
        || source.contains("$(")
    {
        return Err("broad, unresolved, or unsafe package source");
    }
    Ok(source)
}

fn wix_sources(wix: &str) -> Result<BTreeSet<String>, &'static str> {
    let mut reader = Reader::from_str(wix);
    reader.config_mut().trim_text(true);
    let mut sources = BTreeSet::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(element) | Event::Empty(element))
                if element.name().as_ref() == b"File" =>
            {
                for attribute in element.attributes() {
                    let attribute = attribute.map_err(|_| "malformed WiX attribute")?;
                    if attribute.key.as_ref() != b"Source" {
                        continue;
                    }
                    let value = attribute
                        .decoded_and_normalized_value(XmlVersion::Explicit1_0, reader.decoder())
                        .map_err(|_| "malformed WiX source")?;
                    let value = value.replace('\\', "/");
                    let relative = value
                        .strip_prefix("$(var.CargoTargetBinDir)/")
                        .ok_or("unknown WiX source variable")?;
                    let relative = validate_exact_source(relative)?;
                    sources.insert(format!("target/x86_64-pc-windows-msvc/release/{relative}"));
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err("malformed WiX XML"),
        }
    }
    if sources.is_empty() {
        return Err("no WiX package sources");
    }
    Ok(sources)
}

fn cargo_deb_sources(cargo: &str) -> Result<BTreeSet<String>, &'static str> {
    let document = toml::from_str::<toml::Value>(cargo).map_err(|_| "malformed Cargo TOML")?;
    let assets = document
        .get("package")
        .and_then(|value| value.get("metadata"))
        .and_then(|value| value.get("deb"))
        .and_then(|value| value.get("assets"))
        .and_then(toml::Value::as_array)
        .ok_or("missing Cargo deb assets")?;
    let mut sources = BTreeSet::new();
    for asset in assets {
        let fields = asset.as_array().ok_or("Cargo asset is not an array")?;
        if fields.len() != 3 {
            return Err("Cargo asset schema changed");
        }
        let source = fields[0]
            .as_str()
            .ok_or("Cargo asset source is not a string")?;
        sources.insert(validate_exact_source(source)?);
    }
    if sources.is_empty() {
        return Err("no Cargo deb sources");
    }
    Ok(sources)
}

#[derive(Debug)]
struct WorkflowStep {
    name: String,
    uses: Option<String>,
    artifact_name: Option<String>,
    paths: Vec<String>,
    run: Option<String>,
}

fn block_value(lines: &[&str], start: usize, indent: usize) -> (String, usize) {
    let mut value = String::new();
    let mut index = start + 1;
    while index < lines.len() {
        let line = lines[index];
        let leading = line.len() - line.trim_start().len();
        if !line.trim().is_empty() && leading <= indent {
            break;
        }
        if line.len() >= indent + 2 {
            value.push_str(&line[indent + 2..]);
        }
        value.push('\n');
        index += 1;
    }
    (value, index)
}

fn workflow_steps(workflow: &str) -> Result<Vec<WorkflowStep>, &'static str> {
    let lines = workflow.lines().collect::<Vec<_>>();
    let mut steps = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if !line.starts_with("      - name:") {
            index += 1;
            continue;
        }
        let name = line
            .split_once("name:")
            .map(|(_, name)| name.trim().trim_matches(['"', '\'']).to_owned())
            .ok_or("malformed workflow step name")?;
        let start = index;
        index += 1;
        while index < lines.len() && !lines[index].starts_with("      - ") {
            index += 1;
        }
        let end = index;
        let mut step = WorkflowStep {
            name,
            uses: None,
            artifact_name: None,
            paths: Vec::new(),
            run: None,
        };
        let mut cursor = start + 1;
        while cursor < end {
            let current = lines[cursor];
            let trimmed = current.trim();
            if let Some(value) = trimmed.strip_prefix("uses:") {
                step.uses = Some(value.trim().to_owned());
            } else if current.starts_with("          name:") {
                step.artifact_name = Some(
                    trimmed
                        .strip_prefix("name:")
                        .expect("prefix checked")
                        .trim()
                        .trim_matches(['"', '\''])
                        .to_owned(),
                );
            } else if current.starts_with("          path:") {
                let value = trimmed
                    .strip_prefix("path:")
                    .expect("prefix checked")
                    .trim();
                if value == "|" {
                    let (block, next) = block_value(&lines, cursor, 10);
                    step.paths.extend(
                        block
                            .lines()
                            .map(str::trim)
                            .filter(|line| !line.is_empty())
                            .map(ToOwned::to_owned),
                    );
                    cursor = next;
                    continue;
                }
                step.paths.push(value.to_owned());
            } else if current.starts_with("        run:") {
                let value = trimmed.strip_prefix("run:").expect("prefix checked").trim();
                if value == "|" {
                    let (block, next) = block_value(&lines, cursor, 8);
                    step.run = Some(block);
                    cursor = next;
                    continue;
                }
                step.run = Some(value.to_owned());
            }
            cursor += 1;
        }
        steps.push(step);
    }
    Ok(steps)
}

fn shell_words(line: &str) -> Vec<String> {
    line.split_ascii_whitespace()
        .map(|word| word.trim_matches(['"', '\'', ';']).to_owned())
        .collect()
}

fn appimage_sources(run: &str) -> Result<BTreeSet<String>, &'static str> {
    let mut sources = BTreeSet::new();
    let mut heredoc = false;
    for line in run.lines().map(str::trim) {
        if heredoc {
            if line == "EOF" {
                heredoc = false;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("cat > ") && line.ends_with("<< EOF") {
            heredoc = true;
        } else if line.starts_with("cp ") {
            let words = shell_words(line);
            if words.len() != 3 || !words[2].starts_with("AppDir/") {
                return Err("unknown AppImage copy command");
            }
            sources.insert(validate_exact_source(&words[1])?);
        } else if !(line.starts_with("wget ")
            || line.starts_with("chmod ")
            || line.starts_with("mkdir -p AppDir/")
            || line.starts_with("convert ")
            || line.starts_with("./linuxdeploy-x86_64.AppImage "))
        {
            return Err("unknown AppImage staging command");
        }
    }
    if heredoc || sources != BTreeSet::from(["target/release/server".to_owned()]) {
        return Err("incomplete AppImage staging declaration");
    }
    Ok(sources)
}

fn arch_sources(run: &str) -> Result<BTreeSet<String>, &'static str> {
    let mut copied = BTreeSet::new();
    let mut declared = BTreeSet::new();
    let mut installed = BTreeSet::new();
    let mut heredoc = false;
    for line in run.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("cat > pkg/PKGBUILD") && line.ends_with("<< 'EOF'") {
            heredoc = true;
        } else if heredoc && line == "EOF" {
            heredoc = false;
        } else if heredoc {
            if let Some(values) = line
                .strip_prefix("source=(")
                .and_then(|v| v.strip_suffix(')'))
            {
                for value in shell_words(values) {
                    declared.insert(value);
                }
            } else if line.starts_with("install -Dm755 ") {
                let words = shell_words(line);
                let source = words
                    .get(2)
                    .and_then(|word| word.strip_prefix("$srcdir/"))
                    .ok_or("unknown PKGBUILD install source")?;
                installed.insert(source.to_owned());
            } else if !(line.starts_with("pkgname=")
                || line.starts_with("pkgver=")
                || line.starts_with("pkgrel=")
                || line.starts_with("pkgdesc=")
                || line.starts_with("arch=")
                || line.starts_with("url=")
                || line.starts_with("license=")
                || line.starts_with("depends=")
                || line.starts_with("sha256sums=")
                || line == "package() {"
                || line == "}")
            {
                return Err("unknown PKGBUILD declaration or command");
            }
        } else if line == "mkdir -p pkg" {
        } else if line.starts_with("cp ") {
            let words = shell_words(line);
            if words.len() != 3 || !words[2].starts_with("pkg/") {
                return Err("unknown Arch copy command");
            }
            let destination = words[2].trim_start_matches("pkg/");
            copied.insert((destination.to_owned(), validate_exact_source(&words[1])?));
        } else {
            return Err("unknown Arch staging command");
        }
    }
    let copied_names = copied
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    if heredoc || declared != installed || declared != copied_names || declared.is_empty() {
        return Err("Arch source/install/copy declarations disagree");
    }
    Ok(copied.into_iter().map(|(_, source)| source).collect())
}

fn prepare_release_calls(run: &str) -> Result<Vec<(String, String, String)>, &'static str> {
    let mut calls = Vec::new();
    let mut function: Option<(&str, Vec<String>)> = None;
    for line in run.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if matches!(line, "copy_file() {" | "copy_latest() {") {
            if function.is_some() {
                return Err("nested release helper declaration");
            }
            function = Some((line, Vec::new()));
            continue;
        }
        if let Some((name, body)) = &mut function {
            if line == "}" {
                let expected = if *name == "copy_file() {" {
                    vec![
                        "src=\"$1\"",
                        "dest=\"$2\"",
                        "[ -f \"$src\" ] || return 0",
                        "cp \"$src\" \"release/${dest}\"",
                    ]
                } else {
                    vec![
                        "source_dir=\"$1\"",
                        "pattern=\"$2\"",
                        "dest=\"$3\"",
                        "[ -d \"$source_dir\" ] || return 0",
                        "src=\"$(find \"$source_dir\" -maxdepth 1 -type f -name \"$pattern\" | sort -V | tail -n 1)\"",
                        "[ -n \"$src\" ] || return 0",
                        "cp \"$src\" \"release/${dest}\"",
                    ]
                };
                if body.iter().map(String::as_str).collect::<Vec<_>>() != expected {
                    return Err("release helper grammar changed");
                }
                function = None;
            } else {
                body.push(line.to_owned());
            }
            continue;
        }
        if line.starts_with("copy_file ") || line.starts_with("copy_latest ") {
            let words = shell_words(line);
            let expected = if words[0] == "copy_file" { 3 } else { 4 };
            if words.len() != expected {
                return Err("malformed release copy call");
            }
            let source = words[1]
                .strip_prefix("artifacts/")
                .ok_or("release source outside artifacts")?;
            let (artifact, pattern) = if words[0] == "copy_file" {
                let (artifact, member) =
                    source.split_once('/').ok_or("malformed artifact source")?;
                (artifact, member.to_owned())
            } else {
                if source.contains('/') {
                    return Err("copy_latest source must be one artifact directory");
                }
                (source, words[2].clone())
            };
            calls.push((
                artifact.to_owned(),
                pattern,
                words.last().expect("nonempty").clone(),
            ));
        } else if !(line == "mkdir -p release"
            || line.starts_with("(cd release && sha256sum ")
            || line == "ls -la release/")
        {
            return Err("unknown release staging command");
        }
    }
    if function.is_some() || calls.is_empty() {
        return Err("incomplete release assembly grammar");
    }
    Ok(calls)
}

#[derive(Debug)]
struct ReleaseInventory {
    exact_sources: BTreeSet<String>,
    final_sources: BTreeSet<String>,
    generated_trees: BTreeSet<String>,
}

fn enumerate_authoritative_sources(
    wix: &str,
    cargo: &str,
    workflow: &str,
) -> Result<ReleaseInventory, &'static str> {
    let wix = wix_sources(wix)?;
    let deb = cargo_deb_sources(cargo)?;
    let steps = workflow_steps(workflow)?;
    let appimage = steps
        .iter()
        .find(|step| step.name == "Build AppImage")
        .and_then(|step| step.run.as_deref())
        .ok_or("missing AppImage build step")
        .and_then(appimage_sources)?;
    let arch = steps
        .iter()
        .find(|step| step.name == "Create PKGBUILD")
        .and_then(|step| step.run.as_deref())
        .ok_or("missing Arch staging step")
        .and_then(arch_sources)?;

    let mut artifacts = BTreeMap::<String, BTreeSet<String>>::new();
    let mut exact_sources = wix.clone();
    exact_sources.extend(deb.iter().cloned());
    exact_sources.extend(appimage.iter().cloned());
    exact_sources.extend(arch.iter().cloned());
    for step in steps.iter().filter(|step| {
        step.uses
            .as_deref()
            .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
    }) {
        let artifact = step
            .artifact_name
            .clone()
            .ok_or("upload missing artifact name")?;
        if step.paths.is_empty() || artifacts.contains_key(&artifact) {
            return Err("upload artifact schema changed");
        }
        let mut members = BTreeSet::new();
        for path in &step.paths {
            let path = path.trim_matches(['"', '\'']).replace('\\', "/");
            if path.contains(['*', '?', '[', ']']) {
                let expected_tie = match artifact.as_str() {
                    "server-windows-msi" if path == "target/wix/*.msi" => &wix,
                    "server-linux-deb" if path == "target/debian/*.deb" => &deb,
                    "server-linux-appimage" if path == "*.AppImage" => &appimage,
                    "server-arch-pkg" if path == "pkg/*.pkg.tar.zst" => &arch,
                    _ => return Err("untied package artifact glob"),
                };
                if expected_tie.is_empty() {
                    return Err("package glob has no enumerated upstream inputs");
                }
                members.insert(path.rsplit('/').next().expect("nonempty path").to_owned());
            } else {
                let path = validate_exact_source(&path)?;
                let member = Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or("upload source has no file name")?
                    .to_owned();
                exact_sources.insert(path);
                members.insert(member);
            }
        }
        artifacts.insert(artifact, members);
    }

    let calls = steps
        .iter()
        .find(|step| step.name == "Prepare release files")
        .and_then(|step| step.run.as_deref())
        .ok_or("missing release assembly step")
        .and_then(prepare_release_calls)?;
    let mut consumed = BTreeMap::<String, BTreeSet<String>>::new();
    let mut final_sources = BTreeSet::new();
    for (artifact, member, destination) in calls {
        let declared = artifacts
            .get(&artifact)
            .ok_or("release uses unknown artifact")?;
        let tied = declared.contains(&member)
            || (artifact == "server-arch-pkg"
                && declared.contains("*.pkg.tar.zst")
                && member == "stream-server-[0-9]*.pkg.tar.zst");
        if !tied {
            return Err("release source is not tied to its upload declaration");
        }
        let consumed_member =
            if artifact == "server-arch-pkg" && member == "stream-server-[0-9]*.pkg.tar.zst" {
                "*.pkg.tar.zst".to_owned()
            } else {
                member.clone()
            };
        consumed
            .entry(artifact.clone())
            .or_default()
            .insert(consumed_member);
        final_sources.insert(format!(
            "artifacts/{artifact}/{member} -> release/{destination}"
        ));
    }
    if consumed != artifacts {
        return Err("not every uploaded package input reaches final assembly");
    }
    Ok(ReleaseInventory {
        exact_sources,
        final_sources,
        generated_trees: BTreeSet::from([
            "AppDir".to_owned(),
            "pkg".to_owned(),
            "artifacts".to_owned(),
            "release".to_owned(),
        ]),
    })
}

fn resolved_sources_are_safe(repository: &Path, inventory: &ReleaseInventory) -> bool {
    inventory.exact_sources.iter().all(|source| {
        let path = repository.join(source);
        if !path.exists() {
            return true;
        }
        fs::symlink_metadata(&path).is_ok_and(|metadata| {
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && !metadata_is_reparse(&metadata)
                && candidate_tree_is_safe(&path)
        })
    }) && inventory.generated_trees.iter().all(|tree| {
        let path = repository.join(tree);
        !path.exists() || candidate_tree_is_safe(&path)
    })
}

fn repository_inputs() -> (PathBuf, String, String, String) {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root")
        .to_path_buf();
    let wix =
        fs::read_to_string(repository.join("server/wix/main.wxs")).expect("read WiX declaration");
    let cargo =
        fs::read_to_string(repository.join("server/Cargo.toml")).expect("read Cargo declaration");
    let workflow = fs::read_to_string(repository.join(".github/workflows/release.yml"))
        .expect("read release workflow");
    (repository, wix, cargo, workflow)
}

#[test]
fn authoritative_release_declarations_structurally_enumerate_all_safe_inputs() {
    let (repository, wix, cargo, workflow) = repository_inputs();
    let inventory = enumerate_authoritative_sources(&wix, &cargo, &workflow)
        .expect("structurally enumerate authoritative package sources");
    assert!(inventory.exact_sources.len() >= 6);
    assert_eq!(inventory.final_sources.len(), 10);
    assert!(resolved_sources_are_safe(&repository, &inventory));
}

#[test]
fn structural_parsers_accept_double_quotes_and_multiline_xml_and_toml() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let wix = wix.replace(
        "Source='$(var.CargoTargetBinDir)\\server.exe'",
        "Source =\n                                \"$(var.CargoTargetBinDir)\\server.exe\"",
    );
    let cargo = cargo.replace(
        "[\"target/release/server\", \"usr/bin/stream-server\", \"755\"]",
        "[\n        \"target/release/server\",\n        \"usr/bin/stream-server\",\n        \"755\"\n    ]",
    );
    enumerate_authoritative_sources(&wix, &cargo, &workflow)
        .expect("structural XML and TOML parsing accepts formatting variants");
}

#[test]
fn actual_declaration_mutations_reject_directories_globs_and_unknown_staging() {
    let (_, wix, cargo, workflow) = repository_inputs();
    for mutated in [
        workflow.replace(
            "target/x86_64-pc-windows-msvc/release/server.exe",
            "target/x86_64-pc-windows-msvc/release/",
        ),
        workflow.replace("target/release/server", "target/release/server*"),
        workflow.replace(
            "cp target/release/server AppDir/usr/bin/stream-server",
            "cp target/release/server AppDir/usr/bin/stream-server\n          cp payload/codec AppDir/usr/bin/codec",
        ),
        workflow.replace(
            "mkdir -p release",
            "mkdir -p release\n          cp payload/codec release/codec",
        ),
    ] {
        assert!(enumerate_authoritative_sources(&wix, &cargo, &mutated).is_err());
    }
    let cargo_directory = cargo.replace("target/release/server\"", "target/release/\"");
    assert!(enumerate_authoritative_sources(&wix, &cargo_directory, &workflow).is_err());
    let wix_variable = wix.replace("$(var.CargoTargetBinDir)", "$(var.UnknownBinDir)");
    assert!(enumerate_authoritative_sources(&wix_variable, &cargo, &workflow).is_err());
}

#[test]
fn every_final_assembly_source_is_tied_to_an_upstream_upload() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let inventory =
        enumerate_authoritative_sources(&wix, &cargo, &workflow).expect("baseline release inputs");
    for final_source in inventory.final_sources {
        let source = final_source
            .split_once(" -> ")
            .expect("rendered final source")
            .0;
        let mutated = if workflow.contains(source) {
            workflow.replacen(source, "artifacts/untracked/renamed-runtime.bin", 1)
        } else {
            let member = source
                .strip_prefix("artifacts/")
                .and_then(|source| source.split_once('/'))
                .map(|(_, member)| member)
                .expect("artifact member");
            workflow.replacen(member, "renamed-runtime.bin", 1)
        };
        assert!(
            enumerate_authoritative_sources(&wix, &cargo, &mutated).is_err(),
            "accepted untied final assembly mutation for {source}"
        );
    }
}

#[test]
fn renamed_pe_and_archive_magic_fail_while_application_and_vendor_controls_pass() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let repository = tempfile::tempdir().expect("generated package staging");
    let cases = [
        ("payload/codec-helper.bin", b"MZrenamed runtime".as_slice()),
        ("payload/codec.zip.bin", b"PK\x03\x04renamed zip"),
        (
            "payload/codec.7z.bin",
            b"7z\xBC\xAF\x27\x1Crenamed seven zip",
        ),
        ("payload/codec.tar.bin", &[0_u8; 262]),
        ("payload/codec.gz.bin", &[0x1f, 0x8b, 0x08]),
    ];
    for (name, bytes) in cases {
        let path = repository.path().join(name);
        fs::create_dir_all(path.parent().expect("payload parent")).expect("payload directory");
        let mut bytes = bytes.to_vec();
        if name.contains("tar") {
            bytes[257..262].copy_from_slice(b"ustar");
        }
        fs::write(&path, bytes).expect("write renamed payload");
        assert!(
            !candidate_tree_is_safe(&path),
            "accepted renamed payload {name}"
        );

        let file_name = Path::new(name)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("payload file name");
        let mutated = workflow
            .replacen("target/x86_64-pc-windows-msvc/release/server.exe", name, 1)
            .replacen(
                "artifacts/server-windows-amd64/server.exe",
                &format!("artifacts/server-windows-amd64/{file_name}"),
                1,
            );
        let inventory = enumerate_authoritative_sources(&wix, &cargo, &mutated)
            .expect("mutated exact source remains structurally enumerable");
        assert!(
            !resolved_sources_are_safe(repository.path(), &inventory),
            "actual release declaration admitted renamed payload {name}"
        );
    }
    let directory_source = repository.path().join("payload-directory");
    fs::create_dir_all(&directory_source).expect("create declared directory fixture");
    fs::write(directory_source.join("ordinary.txt"), b"ordinary")
        .expect("write safe directory child");
    let directory_workflow = workflow
        .replacen(
            "target/x86_64-pc-windows-msvc/release/server.exe",
            "payload-directory",
            1,
        )
        .replacen(
            "artifacts/server-windows-amd64/server.exe",
            "artifacts/server-windows-amd64/payload-directory",
            1,
        );
    let directory_inventory = enumerate_authoritative_sources(&wix, &cargo, &directory_workflow)
        .expect("directory mutation remains structurally enumerable");
    assert!(
        !resolved_sources_are_safe(repository.path(), &directory_inventory),
        "declared directory was accepted as an exact release input"
    );
    assert!(!forbidden_runtime_payload(
        Path::new("target/x86_64-pc-windows-msvc/release/server.exe"),
        b"MZapplication"
    ));
    assert!(!forbidden_runtime_payload(
        Path::new("vendor/native/ffmpeg_api_source.cpp"),
        b"source only"
    ));
}
