use quick_xml::{Reader, XmlVersion, events::Event};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{self, TryRecvError},
    thread,
    time::{Duration, Instant},
};

const ALLOWED_APPLICATION_PE: &[&str] = &[
    "target/x86_64-pc-windows-msvc/release/server.exe",
    "target/x86_64-pc-windows-msvc/release/settings-gui.exe",
    "target/x86_64-pc-windows-msvc/release/stremio-runtime.exe",
    "target/x86_64-pc-windows-msvc/release/stream-server-updater.exe",
    "artifacts/server-windows-amd64/server.exe",
    "artifacts/server-windows-amd64/settings-gui.exe",
    "artifacts/server-windows-amd64/stremio-runtime.exe",
    "artifacts/server-windows-amd64/stream-server-updater.exe",
    "release/stream-server-windows-amd64.exe",
    "release/stream-server-settings-windows-amd64.exe",
    "release/stremio-runtime-windows-amd64.exe",
    "release/stream-server-updater-windows-amd64.exe",
];

const EXPECTED_EXACT_SOURCES: &[&str] = &[
    "stream-server-linux-amd64.AppImage",
    "target/release/server",
    "target/release/settings-gui",
    "target/x86_64-pc-windows-msvc/release/server.exe",
    "target/x86_64-pc-windows-msvc/release/settings-gui.exe",
    "target/x86_64-pc-windows-msvc/release/stremio-runtime.exe",
    "target/x86_64-pc-windows-msvc/release/stream-server-updater.exe",
];

const EXPECTED_RELEASE_DESTINATIONS: &[&str] = &[
    "stream-server-windows-amd64.exe",
    "stream-server-settings-windows-amd64.exe",
    "stremio-runtime-windows-amd64.exe",
    "stream-server-updater-windows-amd64.exe",
    "stream-server-windows-amd64.msi",
    "stream-server-linux-amd64",
    "stream-server-settings-linux-amd64",
    "stream-server-linux-amd64.deb",
    "stream-server-linux-amd64.AppImage",
    "stream-server-arch-x86_64.pkg.tar.zst",
];
const MAX_WORKFLOW_OBJECT_BYTES: usize = 1024 * 1024;
const WORKFLOW_GIT_TIMEOUT: Duration = Duration::from_secs(10);

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

fn forbidden_runtime_payload(repository: &Path, path: &Path, bytes: &[u8]) -> bool {
    let Ok(relative) = path.strip_prefix(repository) else {
        return true;
    };
    let path = normalized(relative);
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
            .any(|allowed| path == *allowed)
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

fn scan_candidate_tree_with<F>(
    repository: &Path,
    path: &Path,
    read_children: &mut F,
) -> Result<(), &'static str>
where
    F: FnMut(&Path) -> std::io::Result<Vec<PathBuf>>,
{
    path.strip_prefix(repository)
        .map_err(|_| "package input is outside the repository")?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "package input metadata unavailable")?;
    if metadata.file_type().is_symlink() || metadata_is_reparse(&metadata) {
        return Err("package input is a link or reparse point");
    }
    if metadata.is_dir() {
        for child in read_children(path).map_err(|_| "package directory enumeration failed")? {
            scan_candidate_tree_with(repository, &child, read_children)?;
        }
        Ok(())
    } else if metadata.is_file() {
        let bytes = fs::read(path).map_err(|_| "package input could not be read")?;
        if forbidden_runtime_payload(repository, path, &bytes) {
            Err("forbidden runtime payload in package input")
        } else {
            Ok(())
        }
    } else {
        Err("package input is not a regular file or directory")
    }
}

fn candidate_tree_is_safe(repository: &Path, path: &Path) -> Result<(), &'static str> {
    scan_candidate_tree_with(repository, path, &mut |directory| {
        fs::read_dir(directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect()
    })
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
    job: String,
    ordinal: usize,
    name: Option<String>,
    uses: Option<String>,
    artifact_name: Option<String>,
    paths: Vec<String>,
    release_files: Vec<String>,
    run: Option<String>,
    condition: Option<String>,
    id: Option<String>,
    environment: BTreeMap<String, String>,
    fields: BTreeSet<String>,
    inputs: BTreeMap<String, Vec<String>>,
}

#[derive(Debug)]
struct WorkflowJob {
    name: String,
    metadata: String,
}

#[derive(Debug)]
struct ParsedWorkflow {
    jobs: Vec<WorkflowJob>,
    steps: Vec<WorkflowStep>,
}

fn yaml_indent(line: &str) -> Result<usize, &'static str> {
    let whitespace = line.len() - line.trim_start().len();
    if line[..whitespace].contains('\t') {
        return Err("tabs are not accepted in release workflow indentation");
    }
    Ok(whitespace)
}

fn yaml_scalar(value: &str) -> Result<String, &'static str> {
    let value = value.trim();
    if value.is_empty()
        || value
            .chars()
            .next()
            .is_some_and(|value| matches!(value, '&' | '*' | '!' | '{' | '[' | '|' | '>'))
    {
        return Err("unsupported workflow scalar shape");
    }
    if let Some(quote) = value
        .chars()
        .next()
        .filter(|value| matches!(value, '"' | '\''))
    {
        if value.len() < 2 || !value.ends_with(quote) {
            return Err("unterminated workflow scalar");
        }
        return Ok(value[1..value.len() - 1].to_owned());
    }
    Ok(value.to_owned())
}

fn yaml_field(value: &str) -> Option<(&str, &str)> {
    let (key, value) = value.split_once(':')?;
    (!key.is_empty()
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_')))
    .then_some((key, value.trim()))
}

#[derive(Clone, Copy, Debug)]
struct YamlMappingEntry<'a> {
    key: &'a str,
    start: usize,
    end: usize,
}

fn yaml_mapping_entries<'a>(
    lines: &'a [&'a str],
    start: usize,
    end: usize,
    entry_indent: usize,
) -> Result<Vec<YamlMappingEntry<'a>>, &'static str> {
    let mut entries = Vec::new();
    let mut keys = BTreeSet::new();
    let mut cursor = start;
    while cursor < end {
        if lines[cursor].trim().is_empty() {
            cursor += 1;
            continue;
        }
        if yaml_indent(lines[cursor])? != entry_indent {
            return Err("workflow mapping contains malformed or unconsumed indentation");
        }
        let (key, _) = yaml_field(lines[cursor].trim())
            .ok_or("workflow mapping key must be an unquoted plain scalar")?;
        if !keys.insert(key) {
            return Err("duplicate workflow mapping key");
        }
        let mut entry_end = cursor + 1;
        while entry_end < end {
            if lines[entry_end].trim().is_empty() {
                entry_end += 1;
                continue;
            }
            let indent = yaml_indent(lines[entry_end])?;
            if indent < entry_indent {
                return Err("workflow mapping escaped its parent indentation");
            }
            if indent == entry_indent {
                break;
            }
            entry_end += 1;
        }
        entries.push(YamlMappingEntry {
            key,
            start: cursor,
            end: entry_end,
        });
        cursor = entry_end;
    }
    Ok(entries)
}

fn canonical_mapping_entry(
    lines: &[&str],
    entry: YamlMappingEntry<'_>,
    base_indent: usize,
) -> Result<String, &'static str> {
    lines[entry.start..entry.end]
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let indent = yaml_indent(line)?;
            if indent < base_indent {
                return Err("workflow mapping content escaped its declaration");
            }
            Ok(line[base_indent..].trim_end())
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|lines| lines.join("\n"))
}

fn block_value(
    lines: &[&str],
    start: usize,
    parent_indent: usize,
    limit: usize,
) -> Result<(String, usize), &'static str> {
    let mut index = start + 1;
    let mut end = index;
    let mut content_indent = usize::MAX;
    while end < limit {
        let line = lines[end];
        let indent = yaml_indent(line)?;
        if !line.trim().is_empty() && indent <= parent_indent {
            break;
        }
        if !line.trim().is_empty() {
            content_indent = content_indent.min(indent);
        }
        end += 1;
    }
    if content_indent == usize::MAX {
        return Err("empty workflow block scalar");
    }
    let mut value = String::new();
    while index < end {
        let line = lines[index];
        if line.trim().is_empty() {
            value.push('\n');
        } else {
            let indent = yaml_indent(line)?;
            if indent < content_indent {
                return Err("malformed workflow block indentation");
            }
            value.push_str(&line[content_indent..]);
            value.push('\n');
        }
        index += 1;
    }
    Ok((value, end))
}

fn allowed_action_inputs(action: &str) -> Option<&'static [&'static str]> {
    match action {
        "actions/checkout@v7" => Some(&["fetch-depth", "persist-credentials"]),
        "dtolnay/rust-toolchain@1.98.0" => Some(&["components", "targets"]),
        "taiki-e/install-action@v2" => Some(&["tool"]),
        "actions/cache@v6" => Some(&["path", "key", "restore-keys"]),
        "actions/github-script@v9" => Some(&["script"]),
        "lukka/run-vcpkg@v11" => Some(&[
            "vcpkgGitCommitId",
            "vcpkgDirectory",
            "vcpkgJsonGlob",
            "runVcpkgInstall",
        ]),
        "actions/upload-artifact@v7" => Some(&["name", "path"]),
        "actions/download-artifact@v8" => Some(&["path"]),
        "softprops/action-gh-release@v3" => {
            Some(&["files", "body_path", "generate_release_notes", "prerelease"])
        }
        _ => None,
    }
}

fn validate_workflow_step_shape(step: &WorkflowStep) -> Result<(), &'static str> {
    match (step.uses.as_deref(), step.run.as_deref()) {
        (Some(_), Some(_)) | (None, None) => {
            return Err("workflow step must declare exactly one action or run command");
        }
        (Some(action), None) => {
            let allowed = allowed_action_inputs(action).ok_or("unknown workflow action")?;
            if step
                .inputs
                .keys()
                .any(|input| !allowed.contains(&input.as_str()))
            {
                return Err("unknown workflow action input");
            }
            if step.fields.iter().any(|field| field == "run") {
                return Err("action step includes a run field");
            }
        }
        (None, Some(_)) => {
            if step.fields.contains("with")
                || !step.inputs.is_empty()
                || step
                    .fields
                    .iter()
                    .any(|field| matches!(field.as_str(), "uses" | "id"))
            {
                return Err("run step includes action-only fields");
            }
        }
    }
    Ok(())
}

fn validate_workflow_digest(workflow: &str) -> Result<(), &'static str> {
    // The structural parser below assigns semantics to every mapping entry. This reviewed-source
    // fingerprint is the final full-consumption guard for comments, blank-line placement, and
    // nested text that YAML treats as non-semantic or that a bounded grammar could otherwise skip.
    // It authenticates repository declaration text only, not mutable marketplace action tags.
    const EXPECTED_WORKFLOW_SHA256: &str =
        "76d04e105cab2a09b1ef9ac504e31044153217b5718925043e68263b3c189bfc";
    let normalized_workflow = workflow.replace("\r\n", "\n");
    if hex::encode(Sha256::digest(normalized_workflow.as_bytes())) != EXPECTED_WORKFLOW_SHA256 {
        return Err("release workflow declaration digest changed");
    }
    Ok(())
}

fn workflow_steps(workflow: &str) -> Result<ParsedWorkflow, &'static str> {
    let lines = workflow.lines().collect::<Vec<_>>();
    if lines
        .iter()
        .any(|line| matches!(line.trim(), "---" | "..."))
    {
        return Err("workflow document markers are not accepted");
    }
    for line in &lines {
        yaml_indent(line)?;
    }
    let top = yaml_mapping_entries(&lines, 0, lines.len(), 0)?;
    if top.iter().map(|entry| entry.key).collect::<Vec<_>>()
        != ["name", "on", "permissions", "env", "jobs"]
    {
        return Err("top-level workflow mapping changed");
    }
    let expected_top = [
        "name: Release Build",
        "on:\n  push:\n    branches: [ \"master\" ]\n    tags: [ \"v*\" ]\n  pull_request:\n    branches: [ \"master\" ]\n  workflow_dispatch:",
        "permissions:\n  contents: read",
        "env:\n  CARGO_TERM_COLOR: always\n  CARGO_NET_RETRY: 10\n  CARGO_HTTP_MULTIPLEXING: false",
    ];
    for (entry, expected) in top.iter().take(4).zip(expected_top) {
        if canonical_mapping_entry(&lines, *entry, 0)? != expected {
            return Err("top-level workflow authority changed");
        }
    }
    let jobs_entry = *top.last().ok_or("workflow jobs mapping missing")?;
    let job_entries = yaml_mapping_entries(&lines, jobs_entry.start + 1, jobs_entry.end, 2)?;
    if job_entries
        .iter()
        .map(|entry| entry.key)
        .collect::<Vec<_>>()
        != [
            "check",
            "check-windows",
            "build-windows",
            "build-linux",
            "build-arch",
            "release",
        ]
    {
        return Err("workflow job inventory changed");
    }
    let mut parsed_jobs = Vec::new();
    let mut steps = Vec::new();
    for job_entry in job_entries {
        let job = job_entry.key.to_owned();
        let job_fields = yaml_mapping_entries(&lines, job_entry.start + 1, job_entry.end, 4)?;
        let step_mappings = job_fields
            .iter()
            .filter(|entry| entry.key == "steps")
            .collect::<Vec<_>>();
        if step_mappings.len() != 1 {
            return Err("workflow job must contain one steps sequence");
        }
        let steps_mapping = *step_mappings[0];
        let metadata = job_fields
            .iter()
            .filter(|entry| entry.key != "steps")
            .map(|entry| canonical_mapping_entry(&lines, *entry, 4))
            .collect::<Result<Vec<_>, _>>()?
            .join("\n");
        parsed_jobs.push(WorkflowJob {
            name: job.clone(),
            metadata,
        });
        let sequence_end = steps_mapping.end;
        let list_indent = 6;
        let mut cursor = steps_mapping.start + 1;
        let mut ordinal = 0;
        while cursor < sequence_end {
            if lines[cursor].trim().is_empty() {
                cursor += 1;
                continue;
            }
            if yaml_indent(lines[cursor])? != list_indent
                || !lines[cursor].trim_start().starts_with('-')
            {
                return Err("malformed workflow step sequence");
            }
            let start = cursor;
            cursor += 1;
            while cursor < sequence_end
                && (lines[cursor].trim().is_empty()
                    || yaml_indent(lines[cursor])? > list_indent
                    || !lines[cursor].trim_start().starts_with('-'))
            {
                cursor += 1;
            }
            let end = cursor;
            let mut step = WorkflowStep {
                job: job.clone(),
                ordinal,
                name: None,
                uses: None,
                artifact_name: None,
                paths: Vec::new(),
                release_files: Vec::new(),
                run: None,
                condition: None,
                id: None,
                environment: BTreeMap::new(),
                fields: BTreeSet::new(),
                inputs: BTreeMap::new(),
            };
            ordinal += 1;
            let first = lines[start]
                .trim_start()
                .strip_prefix('-')
                .expect("step marker checked")
                .trim();
            let field_indent = lines[start + 1..end]
                .iter()
                .filter(|line| !line.trim().is_empty())
                .filter_map(|line| {
                    let indent = yaml_indent(line).ok()?;
                    yaml_field(line.trim()).map(|_| indent)
                })
                .min();
            let mut fields = Vec::<(usize, &str, &str)>::new();
            if !first.is_empty() {
                let (key, value) = yaml_field(first).ok_or("malformed inline workflow step")?;
                fields.push((start, key, value));
            }
            if let Some(field_indent) = field_indent {
                for (index, line) in lines.iter().enumerate().take(end).skip(start + 1) {
                    if yaml_indent(line)? == field_indent {
                        let (key, value) = yaml_field(line.trim())
                            .ok_or("unsupported workflow step field shape")?;
                        fields.push((index, key, value));
                    }
                }
            }
            for (index, key, value) in fields {
                if !matches!(key, "name" | "uses" | "with" | "run" | "env" | "id" | "if") {
                    return Err("unknown workflow step field");
                }
                if !step.fields.insert(key.to_owned()) {
                    return Err("duplicate workflow step field");
                }
                match key {
                    "name" => {
                        if step.name.replace(yaml_scalar(value)?).is_some() {
                            return Err("duplicate workflow step name");
                        }
                    }
                    "uses" => {
                        if step.uses.replace(yaml_scalar(value)?).is_some() {
                            return Err("duplicate workflow action declaration");
                        }
                    }
                    "run" => {
                        let value = if value == "|" {
                            block_value(&lines, index, yaml_indent(lines[index])?, end)?.0
                        } else {
                            yaml_scalar(value)?
                        };
                        if step.run.replace(value).is_some() {
                            return Err("duplicate workflow run declaration");
                        }
                    }
                    "with" => {
                        if !value.is_empty() {
                            return Err("inline workflow action inputs are not accepted");
                        }
                        let with_indent = yaml_indent(lines[index])?;
                        let with_end = (index + 1..end)
                            .find(|child| {
                                !lines[*child].trim().is_empty()
                                    && yaml_indent(lines[*child]).ok() == Some(with_indent)
                            })
                            .unwrap_or(end);
                        let child_indent = lines[index + 1..with_end]
                            .iter()
                            .filter(|line| !line.trim().is_empty())
                            .map(|line| yaml_indent(line))
                            .collect::<Result<Vec<_>, _>>()?
                            .into_iter()
                            .filter(|indent| *indent > with_indent)
                            .min()
                            .ok_or("workflow action inputs are empty")?;
                        let mut child = index + 1;
                        while child < with_end {
                            if lines[child].trim().is_empty() {
                                child += 1;
                                continue;
                            }
                            if yaml_indent(lines[child])? != child_indent {
                                return Err("unconsumed workflow action input content");
                            }
                            let (input, value) = yaml_field(lines[child].trim())
                                .ok_or("unsupported workflow action input shape")?;
                            let (values, next_child) = if value == "|" {
                                let (block, block_end) = block_value(
                                    &lines,
                                    child,
                                    yaml_indent(lines[child])?,
                                    with_end,
                                )?;
                                (
                                    block
                                        .lines()
                                        .map(str::trim)
                                        .filter(|line| !line.is_empty())
                                        .map(yaml_scalar)
                                        .collect::<Result<Vec<_>, _>>()?,
                                    block_end,
                                )
                            } else {
                                (vec![yaml_scalar(value)?], child + 1)
                            };
                            if step
                                .inputs
                                .insert(input.to_owned(), values.clone())
                                .is_some()
                            {
                                return Err("duplicate workflow action input");
                            }
                            match input {
                                "name" if values.len() == 1 => {
                                    if step.artifact_name.replace(values[0].clone()).is_some() {
                                        return Err("duplicate workflow artifact name");
                                    }
                                }
                                "path" => step.paths.extend(values),
                                "files" => step.release_files.extend(values),
                                _ => {}
                            }
                            child = next_child;
                        }
                    }
                    "env" => {
                        if !value.is_empty() {
                            return Err("inline workflow environment is not accepted");
                        }
                        let env_indent = yaml_indent(lines[index])?;
                        let env_end = (index + 1..end)
                            .find(|child| {
                                !lines[*child].trim().is_empty()
                                    && yaml_indent(lines[*child]).ok() == Some(env_indent)
                            })
                            .unwrap_or(end);
                        let mut variables = BTreeSet::new();
                        for line in lines.iter().take(env_end).skip(index + 1) {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            if trimmed.starts_with('#') {
                                return Err("workflow environment comments are not accepted");
                            }
                            let (variable, value) = yaml_field(trimmed)
                                .ok_or("unsupported workflow environment shape")?;
                            if !variables.insert(variable) {
                                return Err("duplicate workflow environment key");
                            }
                            step.environment
                                .insert(variable.to_owned(), yaml_scalar(value)?);
                        }
                    }
                    "id" => {
                        if step.id.replace(yaml_scalar(value)?).is_some() {
                            return Err("duplicate workflow step id");
                        }
                    }
                    "if" => {
                        if step.condition.replace(yaml_scalar(value)?).is_some() {
                            return Err("duplicate workflow condition");
                        }
                    }
                    _ => unreachable!("workflow step field allowlist checked"),
                }
            }
            validate_workflow_step_shape(&step)?;
            steps.push(step);
        }
    }
    Ok(ParsedWorkflow {
        jobs: parsed_jobs,
        steps,
    })
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
            || line == "./linuxdeploy-x86_64.AppImage --appdir AppDir --output appimage"
            || line
                == "generated_appimage=\"$(find . -maxdepth 1 -type f -name '*.AppImage' ! -name 'linuxdeploy-x86_64.AppImage' -print -quit)\""
            || line == "[ -n \"$generated_appimage\" ]"
            || line == "mv \"$generated_appimage\" stream-server-linux-amd64.AppImage")
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

fn expected_artifacts() -> BTreeMap<String, BTreeSet<String>> {
    BTreeMap::from([
        (
            "server-windows-amd64".to_owned(),
            BTreeSet::from([
                "server.exe".to_owned(),
                "settings-gui.exe".to_owned(),
                "stremio-runtime.exe".to_owned(),
                "stream-server-updater.exe".to_owned(),
            ]),
        ),
        (
            "server-windows-msi".to_owned(),
            BTreeSet::from(["*.msi".to_owned()]),
        ),
        (
            "server-linux-amd64".to_owned(),
            BTreeSet::from(["server".to_owned(), "settings-gui".to_owned()]),
        ),
        (
            "server-linux-deb".to_owned(),
            BTreeSet::from(["*.deb".to_owned()]),
        ),
        (
            "server-linux-appimage".to_owned(),
            BTreeSet::from(["stream-server-linux-amd64.AppImage".to_owned()]),
        ),
        (
            "server-arch-pkg".to_owned(),
            BTreeSet::from(["*.pkg.tar.zst".to_owned()]),
        ),
    ])
}

fn expected_artifact_job(artifact: &str) -> Option<&'static str> {
    match artifact {
        "server-windows-amd64" | "server-windows-msi" => Some("build-windows"),
        "server-linux-amd64" | "server-linux-deb" | "server-linux-appimage" => Some("build-linux"),
        "server-arch-pkg" => Some("build-arch"),
        _ => None,
    }
}

struct ClassifiedWorkflowRuns {
    assembly: Vec<(String, String, String)>,
    package_completion: BTreeMap<String, usize>,
    assembly_ordinal: usize,
}

fn require_step_fields(step: &WorkflowStep, expected: &[&str]) -> Result<(), &'static str> {
    let expected = expected
        .iter()
        .map(|field| (*field).to_owned())
        .collect::<BTreeSet<_>>();
    (step.fields == expected)
        .then_some(())
        .ok_or("release-affecting workflow step fields changed")
}

fn classify_package_and_release_runs(
    steps: &[WorkflowStep],
) -> Result<ClassifiedWorkflowRuns, &'static str> {
    let mut wix = 0;
    let mut deb = 0;
    let mut appimage = 0;
    let mut arch_stage = 0;
    let mut arch_build = 0;
    let mut assembly = Vec::new();
    let mut package_completion = BTreeMap::new();
    let mut assembly_ordinal = None;
    for step in steps {
        let Some(run) = step.run.as_deref() else {
            continue;
        };
        if run.contains("cargo wix") {
            wix += 1;
            if step.job != "build-windows"
                || run.trim()
                    != "cargo wix --package server --no-build --nocapture --target x86_64-pc-windows-msvc"
            {
                return Err("unrecognized WiX package declaration");
            }
            require_step_fields(step, &["name", "run", "env"])?;
            package_completion.insert(step.job.clone(), step.ordinal);
        } else if run.contains("cargo deb") {
            deb += 1;
            if step.job != "build-linux" || run.trim() != "cargo deb --package server --no-build" {
                return Err("unrecognized DEB package declaration");
            }
            require_step_fields(step, &["name", "run"])?;
            package_completion
                .entry(step.job.clone())
                .and_modify(|ordinal| *ordinal = (*ordinal).max(step.ordinal))
                .or_insert(step.ordinal);
        } else if run.contains("PKGBUILD") {
            arch_stage += 1;
            if step.job != "build-arch" {
                return Err("Arch staging declared outside build-arch");
            }
            require_step_fields(step, &["name", "run"])?;
            arch_sources(run)?;
        } else if run.contains("AppDir/") || run.contains("linuxdeploy-x86_64.AppImage") {
            appimage += 1;
            if step.job != "build-linux" {
                return Err("AppImage staging declared outside build-linux");
            }
            require_step_fields(step, &["name", "run"])?;
            appimage_sources(run)?;
            package_completion
                .entry(step.job.clone())
                .and_modify(|ordinal| *ordinal = (*ordinal).max(step.ordinal))
                .or_insert(step.ordinal);
        } else if run.contains("makepkg") {
            arch_build += 1;
            let commands = run
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect::<Vec<_>>();
            if step.job != "build-arch"
                || commands
                    != [
                        "cd pkg",
                        "useradd -m builder",
                        "chown -R builder:builder .",
                        "su builder -c \"makepkg -sf --noconfirm\"",
                    ]
            {
                return Err("unrecognized Arch package declaration");
            }
            require_step_fields(step, &["name", "run"])?;
            package_completion.insert(step.job.clone(), step.ordinal);
        } else if run.contains("copy_file()") || run.contains("copy_latest()") {
            if step.job != "release" || !assembly.is_empty() {
                return Err("duplicate or misplaced release assembly declaration");
            }
            require_step_fields(step, &["name", "run"])?;
            assembly = prepare_release_calls(run)?;
            assembly_ordinal = Some(step.ordinal);
        } else if [
            "actions/upload-artifact",
            "actions/download-artifact",
            "action-gh-release",
            "target/wix/*.msi",
            "target/debian/*.deb",
            "pkg/*.pkg.tar.zst",
            "release/*",
        ]
        .iter()
        .any(|marker| run.contains(marker))
        {
            return Err("unrecognized package or release command");
        }
    }
    if (wix, deb, appimage, arch_stage, arch_build) != (1, 1, 1, 1, 1) || assembly.is_empty() {
        return Err("package/release workflow declarations are incomplete or duplicated");
    }
    if package_completion
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != ["build-arch", "build-linux", "build-windows"]
    {
        return Err("package completion ordinals are incomplete");
    }
    Ok(ClassifiedWorkflowRuns {
        assembly,
        package_completion,
        assembly_ordinal: assembly_ordinal.ok_or("release assembly ordinal missing")?,
    })
}

fn validate_post_build_gate_steps(
    steps: &[WorkflowStep],
) -> Result<BTreeMap<String, usize>, &'static str> {
    let test = "cargo test -p server --test transcoding_runtime --features librqbit --no-default-features authoritative_post_build_package_gate -- --ignored --exact";
    let expected = BTreeMap::from([
        (
            "build-windows",
            format!("$env:STREAM_SERVER_RELEASE_GATE_STAGE = \"windows\"\n{test}"),
        ),
        (
            "build-linux",
            format!("STREAM_SERVER_RELEASE_GATE_STAGE=linux {test}"),
        ),
        (
            "build-arch",
            format!("STREAM_SERVER_RELEASE_GATE_STAGE=arch {test}"),
        ),
        (
            "release",
            format!("STREAM_SERVER_RELEASE_GATE_STAGE=release {test}"),
        ),
    ]);
    let observed_steps = steps
        .iter()
        .filter_map(|step| {
            step.run
                .as_deref()
                .filter(|run| {
                    run.contains("authoritative_post_build_package_gate")
                        || run.contains("STREAM_SERVER_RELEASE_GATE_STAGE")
                })
                .map(|run| (step.job.as_str(), (run.trim().to_owned(), step.ordinal)))
        })
        .collect::<Vec<_>>();
    let observed = observed_steps
        .iter()
        .map(|(job, (run, _))| (*job, run.clone()))
        .collect::<BTreeMap<_, _>>();
    if observed_steps.len() != expected.len() || observed != expected {
        return Err("post-build package gates are incomplete, duplicated, or changed");
    }
    let mut ordinals = BTreeMap::new();
    for step in steps.iter().filter(|step| {
        step.run.as_deref().is_some_and(|run| {
            run.contains("authoritative_post_build_package_gate")
                || run.contains("STREAM_SERVER_RELEASE_GATE_STAGE")
        })
    }) {
        require_step_fields(step, &["name", "run"])?;
        ordinals.insert(step.job.clone(), step.ordinal);
    }
    Ok(ordinals)
}

const LINUX_NATIVE_PACKAGE_GATE_DEPENDENCIES: &str = "sudo sed -i 's|http://azure.archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' /etc/apt/apt-mirrors.txt
sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update
sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y build-essential cmake curl pkg-config libssl-dev libfuse2 libboost-dev libclang-dev libgtk-3-dev libayatana-appindicator3-dev";

fn require_action_inputs(step: &WorkflowStep, expected: &[&str]) -> Result<(), &'static str> {
    let expected = expected
        .iter()
        .map(|input| (*input).to_owned())
        .collect::<BTreeSet<_>>();
    (step.inputs.keys().cloned().collect::<BTreeSet<_>>() == expected)
        .then_some(())
        .ok_or("release-affecting action input set changed")
}

enum ExpectedWorkflowStepKind {
    Action {
        uses: &'static str,
        inputs: &'static [(&'static str, &'static [&'static str])],
    },
    Run {
        sha256: &'static str,
    },
}

// These exact refs and body digests detect reviewed workflow changes. Marketplace tags remain
// mutable upstream references; this contract is not a substitute for pinning actions to commits.
struct ExpectedWorkflowStep {
    name: Option<&'static str>,
    fields: &'static [&'static str],
    id: Option<&'static str>,
    condition: Option<&'static str>,
    environment: &'static [(&'static str, &'static str)],
    kind: ExpectedWorkflowStepKind,
}

fn action_contract(
    name: Option<&'static str>,
    fields: &'static [&'static str],
    uses: &'static str,
    inputs: &'static [(&'static str, &'static [&'static str])],
) -> ExpectedWorkflowStep {
    ExpectedWorkflowStep {
        name,
        fields,
        id: None,
        condition: None,
        environment: &[],
        kind: ExpectedWorkflowStepKind::Action { uses, inputs },
    }
}

fn run_contract(
    name: &'static str,
    fields: &'static [&'static str],
    sha256: &'static str,
) -> ExpectedWorkflowStep {
    ExpectedWorkflowStep {
        name: Some(name),
        fields,
        id: None,
        condition: None,
        environment: &[],
        kind: ExpectedWorkflowStepKind::Run { sha256 },
    }
}

const WINDOWS_BUILD_ENV: &[(&str, &str)] = &[
    (
        "PKG_CONFIG_PATH",
        "${{ github.workspace }}\\vcpkg_installed\\x64-windows-v3-static-md-release\\lib\\pkgconfig",
    ),
    ("VCPKGRS_TRIPLET", "x64-windows-v3-static-md-release"),
    (
        "VCPKG_INSTALLED_DIR",
        "${{ github.workspace }}\\vcpkg_installed",
    ),
    ("VCPKG_ROOT", "${{ github.workspace }}\\vcpkg"),
];

fn expected_packaging_steps(job: &str) -> Option<Vec<ExpectedWorkflowStep>> {
    let checkout = || {
        action_contract(
            None,
            &["uses", "with"],
            "actions/checkout@v7",
            &[("fetch-depth", &["0"]), ("persist-credentials", &["false"])],
        )
    };
    let shallow_checkout = || {
        action_contract(
            None,
            &["uses", "with"],
            "actions/checkout@v7",
            &[("persist-credentials", &["false"])],
        )
    };
    let cargo_chef_cache = || {
        action_contract(
            Some("Cargo Chef Cache"),
            &["name", "uses", "with"],
            "actions/cache@v6",
            &[
                (
                    "key",
                    &["${{ runner.os }}-cargo-chef-${{ hashFiles('recipe.json') }}"],
                ),
                ("path", &["target"]),
                ("restore-keys", &["${{ runner.os }}-cargo-chef-"]),
            ],
        )
    };
    match job {
        "check" => Some(vec![
            checkout(),
            action_contract(
                Some("Setup Rust"),
                &["name", "uses", "with"],
                "dtolnay/rust-toolchain@1.98.0",
                &[("components", &["clippy"])],
            ),
            action_contract(
                Some("Install cargo-chef"),
                &["name", "uses", "with"],
                "taiki-e/install-action@v2",
                &[("tool", &["cargo-chef"])],
            ),
            run_contract(
                "Install System Dependencies",
                &["name", "run"],
                "dec83f6f9886e3baa4cf53f471988cbffadf7996108ddca581eccf981fbd7b8d",
            ),
            run_contract(
                "Install libtorrent 2.1.1",
                &["name", "run"],
                "76f3af92afe15b45fe9102a4947fb200dd9d3fd0511f5575fa35ea5c0dfed7d3",
            ),
            run_contract(
                "Cargo Chef Prepare",
                &["name", "run"],
                "c6b1ac40a713e18000d525ae4eb8e6cab4377d32f90c2a5cf58ab378d2a1f14e",
            ),
            action_contract(
                Some("Cargo Chef Cache"),
                &["name", "uses", "with"],
                "actions/cache@v6",
                &[
                    (
                        "key",
                        &["${{ runner.os }}-check-cargo-chef-${{ hashFiles('recipe.json') }}"],
                    ),
                    ("path", &["target"]),
                    ("restore-keys", &["${{ runner.os }}-check-cargo-chef-"]),
                ],
            ),
            run_contract(
                "Cargo Chef Cook",
                &["name", "run"],
                "0acd01d41da6c5bf2e3166f9058eeb286d35371d9f1f574e36bcc568d390e2cc",
            ),
            run_contract(
                "Restore Source Code",
                &["name", "run"],
                "4bda61bee0859f911423f15bfc2b6334a840095263d3a611eea746fbb6b29230",
            ),
            run_contract(
                "Check libtorrent and native FFI targets",
                &["name", "run"],
                "c0b994a70f6239bbbb6bd6f1d7f32130ecb88600dbe253c03bbd3fede6142fbc",
            ),
            run_contract(
                "Run Clippy for libtorrent and native FFI targets",
                &["name", "run"],
                "cafac56c536c9835b5f17ac91b72230c539d95e998624e7a059b4a910166b802",
            ),
            run_contract(
                "Check librqbit and native FFI targets",
                &["name", "run"],
                "04a4ae3b677fd4e7df8ade2dc6903e9db9dc016bae8b4c74173b75cac6f42ca5",
            ),
            run_contract(
                "Run Clippy for librqbit backend",
                &["name", "run"],
                "70b53af1e4c740f80e061fce6b50f240b215e8e1c5df1c7bde3c08839a8468e4",
            ),
            run_contract(
                "Run Tests",
                &["name", "run"],
                "ebedc1f3dd5003292f91380ba144e9a733e950174c656739d032035f22295fa3",
            ),
            run_contract(
                "Test librqbit backend",
                &["name", "run"],
                "b3876eb1195ee67af7f3e186192dc1fb186d364d26153a243f4335f81dbb78cb",
            ),
        ]),
        "check-windows" => Some(vec![
            shallow_checkout(),
            action_contract(
                Some("Setup Rust"),
                &["name", "uses", "with"],
                "dtolnay/rust-toolchain@1.98.0",
                &[("components", &["clippy"])],
            ),
            run_contract(
                "Check librqbit and native FFI targets",
                &["name", "run"],
                "04a4ae3b677fd4e7df8ade2dc6903e9db9dc016bae8b4c74173b75cac6f42ca5",
            ),
            run_contract(
                "Run Clippy for librqbit and native FFI targets",
                &["name", "run"],
                "70b53af1e4c740f80e061fce6b50f240b215e8e1c5df1c7bde3c08839a8468e4",
            ),
            run_contract(
                "Test repeated Windows shutdown",
                &["name", "run"],
                "ee3e3c4b6c32e558d06f0826d727768a9de61582de2f76f702642d86641b28d8",
            ),
        ]),
        "build-windows" => {
            let mut setup_vcpkg = action_contract(
                Some("Setup vcpkg"),
                &["env", "if", "name", "uses", "with"],
                "lukka/run-vcpkg@v11",
                &[
                    ("runVcpkgInstall", &["true"]),
                    ("vcpkgDirectory", &["${{ github.workspace }}/vcpkg"]),
                    (
                        "vcpkgGitCommitId",
                        &["9e593bb18ea69cc5095e012465dcd675a822ed0d"],
                    ),
                    ("vcpkgJsonGlob", &["vcpkg.json"]),
                ],
            );
            setup_vcpkg.condition = Some("steps.vcpkg-cache.outputs.cache-hit != 'true'");
            setup_vcpkg.environment = &[
                ("VCPKG_DEFAULT_TRIPLET", "x64-windows-v3-static-md-release"),
                (
                    "VCPKG_INSTALLED_DIR",
                    "${{ github.workspace }}/vcpkg_installed",
                ),
                (
                    "VCPKG_OVERLAY_PORTS",
                    "${{ github.workspace }}/vcpkg-overlays",
                ),
                ("VCPKG_OVERLAY_TRIPLETS", "${{ github.workspace }}/triplets"),
            ];
            let mut vcpkg_cache = action_contract(
                Some("Cache vcpkg installed packages"),
                &["id", "name", "uses", "with"],
                "actions/cache@v6",
                &[
                    (
                        "key",
                        &[
                            "Windows-vcpkg-x86-64-v3-static-md-release-v1-${{ hashFiles('vcpkg.json','triplets/**','vcpkg-overlays/**') }}",
                        ],
                    ),
                    ("path", &["vcpkg_installed"]),
                    (
                        "restore-keys",
                        &[
                            "Windows-vcpkg-x86-64-v3-static-md-release-v1-",
                            "Windows-vcpkg-x86-64-v3-static-md-release-",
                        ],
                    ),
                ],
            );
            vcpkg_cache.id = Some("vcpkg-cache");
            let mut chef_cook = run_contract(
                "Cargo Chef Cook",
                &["env", "name", "run"],
                "29f29d0535c8f3c137489672ae7d7a0529354cf3332d69b478dbeae9bd41cb76",
            );
            chef_cook.environment = WINDOWS_BUILD_ENV;
            let mut build_release = run_contract(
                "Build Release",
                &["env", "name", "run"],
                "f1517d35b1a3ebba293eb7e94e148f19cd618605fd21da52b356ddda5f1422fa",
            );
            build_release.environment = WINDOWS_BUILD_ENV;
            let mut wix = run_contract(
                "Build MSI Installer",
                &["env", "name", "run"],
                "9ea8fa24c7d6e4a3ba4b8e32bd26230ed34866603547726b376d3374e977bf76",
            );
            wix.environment = WINDOWS_BUILD_ENV;
            let mut diagnostic = run_contract(
                "Debug VCPKG Location",
                &["if", "name", "run"],
                "85010132de2cc626799258201c395bc9f79074614862335de05948b81edc3d44",
            );
            diagnostic.condition = Some("always()");
            Some(vec![
                checkout(),
                action_contract(
                    Some("Setup Rust"),
                    &["name", "uses", "with"],
                    "dtolnay/rust-toolchain@1.98.0",
                    &[("targets", &["x86_64-pc-windows-msvc"])],
                ),
                action_contract(
                    Some("Install cargo-chef and cargo-wix"),
                    &["name", "uses", "with"],
                    "taiki-e/install-action@v2",
                    &[("tool", &["cargo-chef,cargo-wix"])],
                ),
                action_contract(
                    Some("Cargo Registry Cache"),
                    &["name", "uses", "with"],
                    "actions/cache@v6",
                    &[
                        (
                            "key",
                            &["Windows-cargo-registry-${{ hashFiles('**/Cargo.lock') }}"],
                        ),
                        (
                            "path",
                            &[
                                "C:\\Users\\runneradmin\\.cargo\\registry",
                                "C:\\Users\\runneradmin\\.cargo\\git",
                            ],
                        ),
                        ("restore-keys", &["Windows-cargo-registry-"]),
                    ],
                ),
                action_contract(
                    Some("Export GitHub Actions cache env for vcpkg"),
                    &["name", "uses", "with"],
                    "actions/github-script@v9",
                    &[(
                        "script",
                        &[
                            "core.exportVariable('ACTIONS_CACHE_URL', process.env.ACTIONS_CACHE_URL);",
                            "core.exportVariable('ACTIONS_RUNTIME_TOKEN', process.env.ACTIONS_RUNTIME_TOKEN);",
                        ],
                    )],
                ),
                vcpkg_cache,
                setup_vcpkg,
                run_contract(
                    "Cargo Chef Prepare",
                    &["name", "run"],
                    "c6b1ac40a713e18000d525ae4eb8e6cab4377d32f90c2a5cf58ab378d2a1f14e",
                ),
                cargo_chef_cache(),
                chef_cook,
                run_contract(
                    "Restore Source Code",
                    &["name", "run"],
                    "4bda61bee0859f911423f15bfc2b6334a840095263d3a611eea746fbb6b29230",
                ),
                build_release,
                wix,
                run_contract(
                    "Verify Windows package outputs",
                    &["name", "run"],
                    "a67e81930f427e8135ba6499edb06664aeb9bb5d72f8a7c6af4eecd9b007536d",
                ),
                action_contract(
                    Some("Upload EXE"),
                    &["name", "uses", "with"],
                    "actions/upload-artifact@v7",
                    &[
                        ("name", &["server-windows-amd64"]),
                        (
                            "path",
                            &[
                                "target/x86_64-pc-windows-msvc/release/server.exe",
                                "target/x86_64-pc-windows-msvc/release/settings-gui.exe",
                                "target/x86_64-pc-windows-msvc/release/stremio-runtime.exe",
                                "target/x86_64-pc-windows-msvc/release/stream-server-updater.exe",
                            ],
                        ),
                    ],
                ),
                action_contract(
                    Some("Upload MSI"),
                    &["name", "uses", "with"],
                    "actions/upload-artifact@v7",
                    &[
                        ("name", &["server-windows-msi"]),
                        ("path", &["target/wix/*.msi"]),
                    ],
                ),
                diagnostic,
            ])
        }
        "build-linux" => Some(vec![
            checkout(),
            action_contract(
                Some("Setup Rust"),
                &["name", "uses"],
                "dtolnay/rust-toolchain@1.98.0",
                &[],
            ),
            action_contract(
                Some("Install cargo-chef and cargo-deb"),
                &["name", "uses", "with"],
                "taiki-e/install-action@v2",
                &[("tool", &["cargo-chef,cargo-deb"])],
            ),
            run_contract(
                "Install System Dependencies",
                &["name", "run"],
                "dec83f6f9886e3baa4cf53f471988cbffadf7996108ddca581eccf981fbd7b8d",
            ),
            run_contract(
                "Install libtorrent 2.1.1",
                &["name", "run"],
                "76f3af92afe15b45fe9102a4947fb200dd9d3fd0511f5575fa35ea5c0dfed7d3",
            ),
            run_contract(
                "Cargo Chef Prepare",
                &["name", "run"],
                "c6b1ac40a713e18000d525ae4eb8e6cab4377d32f90c2a5cf58ab378d2a1f14e",
            ),
            cargo_chef_cache(),
            run_contract(
                "Cargo Chef Cook",
                &["name", "run"],
                "92886be0eb5912f4d712014a8671b43f6361124b847a6ebe39bb5abe7979479e",
            ),
            run_contract(
                "Restore Source Code",
                &["name", "run"],
                "0f70544612144d3e9b62a52af72a97af1b786b7fe1f1fe9eccbb5c39520971ff",
            ),
            run_contract(
                "Build Release",
                &["name", "run"],
                "1aa014a51366982f83476ef476780ba696a884b6222c043410b194f19af979a0",
            ),
            run_contract(
                "Build DEB Package",
                &["name", "run"],
                "40bdac12b73ccf8a82832a96f761a267a54d4248bd98b71b200729516d6eed10",
            ),
            run_contract(
                "Build AppImage",
                &["name", "run"],
                "d7f06905910d4852347f69d1e994ba90631af02db2dc6b6b14d6bdd9037dbff8",
            ),
            run_contract(
                "Verify Linux package outputs",
                &["name", "run"],
                "b001aa192422dde960d2d22810b06869bd7ab4c2d9cef041837a0d5f0092d072",
            ),
            action_contract(
                Some("Upload Binary"),
                &["name", "uses", "with"],
                "actions/upload-artifact@v7",
                &[
                    ("name", &["server-linux-amd64"]),
                    (
                        "path",
                        &["target/release/server", "target/release/settings-gui"],
                    ),
                ],
            ),
            action_contract(
                Some("Upload DEB"),
                &["name", "uses", "with"],
                "actions/upload-artifact@v7",
                &[
                    ("name", &["server-linux-deb"]),
                    ("path", &["target/debian/*.deb"]),
                ],
            ),
            action_contract(
                Some("Upload AppImage"),
                &["name", "uses", "with"],
                "actions/upload-artifact@v7",
                &[
                    ("name", &["server-linux-appimage"]),
                    ("path", &["stream-server-linux-amd64.AppImage"]),
                ],
            ),
        ]),
        "build-arch" => Some(vec![
            checkout(),
            run_contract(
                "Install dependencies",
                &["name", "run"],
                "ee970bab560461f7a944fc9279961b66f116984a5df63bfb1b670197fb0e5587",
            ),
            run_contract(
                "Install Rust 1.98.0",
                &["name", "run"],
                "4c98b0be1963212e20387ed4a5f4f5925a18715c5ac0da14bfd01b60dcc62b6e",
            ),
            run_contract(
                "Install libtorrent 2.1.1",
                &["name", "run"],
                "76f3af92afe15b45fe9102a4947fb200dd9d3fd0511f5575fa35ea5c0dfed7d3",
            ),
            action_contract(
                Some("Cargo Cache"),
                &["name", "uses", "with"],
                "actions/cache@v6",
                &[
                    ("key", &["arch-cargo-${{ hashFiles('**/Cargo.lock') }}"]),
                    (
                        "path",
                        &["target", "/root/.cargo/registry", "/root/.cargo/git"],
                    ),
                    ("restore-keys", &["arch-cargo-"]),
                ],
            ),
            run_contract(
                "Build binary",
                &["name", "run"],
                "1aa014a51366982f83476ef476780ba696a884b6222c043410b194f19af979a0",
            ),
            run_contract(
                "Create PKGBUILD",
                &["name", "run"],
                "5e7a98c4d64256f1652e657aa04129e9488f1198d2f6b4e1d3ffff2da51dba67",
            ),
            run_contract(
                "Build package",
                &["name", "run"],
                "78aa73723705b9ec25fbcd8cf0487216a069011b320ee9c7bf7e2ede468738bd",
            ),
            run_contract(
                "Verify Arch package outputs",
                &["name", "run"],
                "c4350327d83d977d6369bba4c71170c6754c2138497fae6790d25adea586ab01",
            ),
            action_contract(
                Some("Upload Arch Package"),
                &["name", "uses", "with"],
                "actions/upload-artifact@v7",
                &[
                    ("name", &["server-arch-pkg"]),
                    ("path", &["pkg/*.pkg.tar.zst"]),
                ],
            ),
        ]),
        "release" => Some(vec![
            action_contract(
                None,
                &["uses", "with"],
                "actions/checkout@v7",
                &[("fetch-depth", &["0"]), ("persist-credentials", &["false"])],
            ),
            action_contract(
                Some("Setup Rust for package gate"),
                &["name", "uses"],
                "dtolnay/rust-toolchain@1.98.0",
                &[],
            ),
            run_contract(
                "Install package gate dependencies",
                &["name", "run"],
                "dec83f6f9886e3baa4cf53f471988cbffadf7996108ddca581eccf981fbd7b8d",
            ),
            action_contract(
                Some("Download all artifacts"),
                &["name", "uses", "with"],
                "actions/download-artifact@v8",
                &[("path", &["artifacts"])],
            ),
            run_contract(
                "Prepare release files",
                &["name", "run"],
                "dce2b7f66919e560183eb0f43e553bf54e62a15f86bf222de03521e57372c97b",
            ),
            run_contract(
                "Generate release description",
                &["name", "run"],
                "15a262dd2230df45fa633bc211eb7659ff2670824d6e30a6d5b41287557bb5ab",
            ),
            run_contract(
                "Verify final release outputs",
                &["name", "run"],
                "0f3550f13b64796dee5e5e9f9bbd91af05138c049c274e5dbb1339da1bb05a12",
            ),
            action_contract(
                Some("Create GitHub Release"),
                &["name", "uses", "with"],
                "softprops/action-gh-release@v3",
                &[
                    ("body_path", &["${{ github.workspace }}/RELEASE_BODY.md"]),
                    ("files", &["release/*"]),
                    ("generate_release_notes", &["false"]),
                    (
                        "prerelease",
                        &[
                            "${{ contains(github.ref, 'beta') || contains(github.ref, 'alpha') || contains(github.ref, 'rc') }}",
                        ],
                    ),
                ],
            ),
        ]),
        _ => None,
    }
}

fn exact_string_map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn exact_values_map(entries: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    entries
        .iter()
        .map(|(key, values)| {
            (
                (*key).to_owned(),
                values.iter().map(|value| (*value).to_owned()).collect(),
            )
        })
        .collect()
}

fn validate_exact_packaging_step(
    actual: &WorkflowStep,
    expected: &ExpectedWorkflowStep,
) -> Result<(), &'static str> {
    let expected_fields = expected
        .fields
        .iter()
        .map(|field| (*field).to_owned())
        .collect::<BTreeSet<_>>();
    if actual.name.as_deref() != expected.name
        || actual.fields != expected_fields
        || actual.id.as_deref() != expected.id
        || actual.condition.as_deref() != expected.condition
        || actual.environment != exact_string_map(expected.environment)
    {
        return Err("packaging workflow step metadata changed");
    }
    match &expected.kind {
        ExpectedWorkflowStepKind::Action { uses, inputs } => {
            if actual.uses.as_deref() != Some(*uses)
                || actual.run.is_some()
                || actual.inputs != exact_values_map(inputs)
            {
                return Err("packaging workflow action contract changed");
            }
        }
        ExpectedWorkflowStepKind::Run { sha256 } => {
            let run = actual.run.as_deref().ok_or("packaging run step missing")?;
            if actual.uses.is_some()
                || !actual.inputs.is_empty()
                || hex::encode(Sha256::digest(run.trim().as_bytes())) != *sha256
            {
                return Err("packaging workflow run contract changed");
            }
        }
    }
    Ok(())
}

fn expected_packaging_job_metadata(job: &str) -> Option<&'static str> {
    match job {
        "check" => Some(
            "name: Check\nruns-on: ubuntu-24.04\nif: github.event_name == 'pull_request' || (github.event_name == 'push' && !startsWith(github.ref, 'refs/tags/v'))\nenv:\n  LIBTORRENT_STATIC: \"1\"\n  PKG_CONFIG_PATH: /usr/local/lib/pkgconfig",
        ),
        "check-windows" => Some(
            "name: Check Windows native FFI and shutdown\nruns-on: windows-2022\nif: github.event_name == 'pull_request' || (github.event_name == 'push' && !startsWith(github.ref, 'refs/tags/v'))\nenv:\n  LIBCLANG_PATH: C:\\Program Files\\LLVM\\bin",
        ),
        "build-windows" => Some(
            "name: Build Windows\nruns-on: windows-2022\nif: startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch'\nenv:\n  VCPKG_BINARY_SOURCES: \"clear;x-gha,readwrite\"",
        ),
        "build-linux" => Some(
            "name: Build Linux\nruns-on: ubuntu-24.04\nif: startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch'\nenv:\n  LIBTORRENT_STATIC: \"1\"\n  PKG_CONFIG_PATH: /usr/local/lib/pkgconfig",
        ),
        "build-arch" => Some(
            "name: Build Arch Linux\nruns-on: ubuntu-latest\nif: startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch'\ncontainer: archlinux:latest\nenv:\n  LIBTORRENT_STATIC: \"1\"\n  PKG_CONFIG_PATH: /usr/local/lib/pkgconfig",
        ),
        "release" => Some(
            "name: Create Release\nneeds: [build-windows, build-linux, build-arch]\nruns-on: ubuntu-latest\nif: startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch'\npermissions:\n  contents: write",
        ),
        _ => None,
    }
}

fn validate_packaging_job_contract(parsed: &ParsedWorkflow) -> Result<(), &'static str> {
    for job in [
        "check",
        "check-windows",
        "build-windows",
        "build-linux",
        "build-arch",
        "release",
    ] {
        let metadata = parsed
            .jobs
            .iter()
            .find(|candidate| candidate.name == job)
            .ok_or("packaging workflow job missing")?;
        if Some(metadata.metadata.as_str()) != expected_packaging_job_metadata(job) {
            return Err("packaging workflow job metadata changed");
        }
        let actual = parsed
            .steps
            .iter()
            .filter(|step| step.job == job)
            .collect::<Vec<_>>();
        let expected = expected_packaging_steps(job).ok_or("packaging step contract missing")?;
        if actual.len() != expected.len() {
            return Err("packaging workflow step count changed");
        }
        for (actual, expected) in actual.into_iter().zip(&expected) {
            validate_exact_packaging_step(actual, expected)?;
        }
    }
    Ok(())
}

fn validate_workflow_semantics(workflow: &str) -> Result<ParsedWorkflow, &'static str> {
    let parsed = workflow_steps(workflow)?;
    validate_packaging_job_contract(&parsed)?;
    Ok(parsed)
}

fn validate_authoritative_workflow_with_loader<F>(
    workspace: &str,
    github_actions: Option<&str>,
    post_build_stage: Option<&str>,
    workflow_sha: Option<&str>,
    loader: F,
) -> Result<String, &'static str>
where
    F: FnOnce(&str) -> Result<Vec<u8>, &'static str>,
{
    if github_actions != Some("true") && post_build_stage.is_none() {
        return Ok(workspace.to_owned());
    }
    let workflow_sha = workflow_sha.ok_or("GITHUB_WORKFLOW_SHA is required")?;
    let workflow_sha = normalize_workflow_sha(workflow_sha)?;
    let immutable_bytes = loader(&workflow_sha)?;
    if immutable_bytes.len() > MAX_WORKFLOW_OBJECT_BYTES {
        return Err("release workflow commit object exceeds size limit");
    }
    let immutable = String::from_utf8(immutable_bytes)
        .map_err(|_| "release workflow commit object is not UTF-8")?;
    validate_workflow_digest(&immutable)?;
    validate_workflow_semantics(&immutable)?;
    if workspace.replace("\r\n", "\n") != immutable.replace("\r\n", "\n") {
        return Err("workspace release workflow differs from commit object");
    }
    Ok(immutable)
}

fn normalize_workflow_sha(workflow_sha: &str) -> Result<String, &'static str> {
    if workflow_sha.len() != 40 || !workflow_sha.bytes().all(|value| value.is_ascii_hexdigit()) {
        return Err("GITHUB_WORKFLOW_SHA must be 40 hexadecimal characters");
    }
    Ok(workflow_sha.to_ascii_lowercase())
}

fn run_bounded_workflow_command(
    command: &mut Command,
    timeout: Duration,
) -> Result<Vec<u8>, &'static str> {
    run_bounded_workflow_command_with_reader(command, timeout, |stdout, sender| {
        thread::Builder::new()
            .name("release-workflow-git-reader".to_owned())
            .spawn(move || {
                let mut bytes = Vec::new();
                let result = stdout
                    .take((MAX_WORKFLOW_OBJECT_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map(|_| bytes)
                    .map_err(|_| "workflow Git object read failed");
                let _ = sender.send(result);
            })
    })
}

fn cleanup_workflow_command(
    mut child: std::process::Child,
    reader: Option<thread::JoinHandle<()>>,
    terminate_if_running: bool,
) -> Result<std::process::ExitStatus, &'static str> {
    let mut lifecycle_failed = false;
    let running = match child.try_wait() {
        Ok(Some(_)) => false,
        Ok(None) => true,
        Err(_) => {
            lifecycle_failed = true;
            true
        }
    };
    if terminate_if_running && running && child.kill().is_err() {
        lifecycle_failed = true;
    }
    let waited = child.wait();
    let reader_panicked = reader.is_some_and(|reader| reader.join().is_err());
    if reader_panicked {
        return Err("workflow Git object read failed");
    }
    if lifecycle_failed {
        return Err("workflow Git object command failed");
    }
    waited.map_err(|_| "workflow Git object command failed")
}

fn run_bounded_workflow_command_with_reader<S>(
    command: &mut Command,
    timeout: Duration,
    spawn_reader: S,
) -> Result<Vec<u8>, &'static str>
where
    S: FnOnce(
        std::process::ChildStdout,
        mpsc::SyncSender<Result<Vec<u8>, &'static str>>,
    ) -> std::io::Result<thread::JoinHandle<()>>,
{
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "workflow Git tool unavailable")?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            cleanup_workflow_command(child, None, true)?;
            return Err("workflow Git stdout unavailable");
        }
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = match spawn_reader(stdout, sender) {
        Ok(reader) => reader,
        Err(_) => {
            cleanup_workflow_command(child, None, true)?;
            return Err("workflow Git reader unavailable");
        }
    };
    let deadline = Instant::now() + timeout;
    let mut output = None;
    loop {
        match receiver.try_recv() {
            Ok(Ok(bytes)) if bytes.len() > MAX_WORKFLOW_OBJECT_BYTES => {
                cleanup_workflow_command(child, Some(reader), true)?;
                return Err("release workflow commit object exceeds size limit");
            }
            Ok(Ok(bytes)) => output = Some(bytes),
            Ok(Err(error)) => {
                cleanup_workflow_command(child, Some(reader), true)?;
                return Err(error);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) if output.is_none() => {
                cleanup_workflow_command(child, Some(reader), true)?;
                return Err("workflow Git object read failed");
            }
            Err(TryRecvError::Disconnected) => {}
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                let result = match output {
                    Some(bytes) => Ok(bytes),
                    None => match receiver.recv() {
                        Ok(result) => result,
                        Err(_) => Err("workflow Git object read failed"),
                    },
                };
                let status = cleanup_workflow_command(child, Some(reader), false)?;
                if !status.success() {
                    return Err("workflow Git object command failed");
                }
                let bytes = result?;
                if bytes.len() > MAX_WORKFLOW_OBJECT_BYTES {
                    return Err("release workflow commit object exceeds size limit");
                }
                return Ok(bytes);
            }
            Ok(None) => {}
            Err(_) => {
                cleanup_workflow_command(child, Some(reader), true)?;
                return Err("workflow Git object command failed");
            }
        }
        if Instant::now() >= deadline {
            cleanup_workflow_command(child, Some(reader), true)?;
            return Err("workflow Git object command timed out");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn load_git_workflow_object(
    repository: &Path,
    workflow_sha: &str,
) -> Result<Vec<u8>, &'static str> {
    let workflow_sha = normalize_workflow_sha(workflow_sha)?;
    let object = format!("{workflow_sha}:.github/workflows/release.yml");
    let command = &mut Command::new("git");
    command
        .current_dir(repository)
        .args(["cat-file", "blob", &object])
        .stdin(Stdio::null());
    run_bounded_workflow_command(command, WORKFLOW_GIT_TIMEOUT)
}

fn authoritative_workflow_for_current_environment(
    repository: &Path,
    workspace: &str,
) -> Result<String, &'static str> {
    let github_actions = std::env::var_os("GITHUB_ACTIONS");
    let post_build_stage = std::env::var_os("STREAM_SERVER_RELEASE_GATE_STAGE");
    let workflow_sha = if github_actions.is_some() || post_build_stage.is_some() {
        std::env::var("GITHUB_WORKFLOW_SHA").ok()
    } else {
        None
    };
    validate_authoritative_workflow_with_loader(
        workspace,
        github_actions.as_ref().map(|_| "true"),
        post_build_stage.as_ref().map(|_| "set"),
        workflow_sha.as_deref(),
        |sha| load_git_workflow_object(repository, sha),
    )
}

fn expected_package_upload_suffix(job: &str) -> Option<&'static [&'static str]> {
    match job {
        "build-windows" => Some(&["server-windows-amd64", "server-windows-msi"]),
        "build-linux" => Some(&[
            "server-linux-amd64",
            "server-linux-deb",
            "server-linux-appimage",
        ]),
        "build-arch" => Some(&["server-arch-pkg"]),
        _ => None,
    }
}

const WINDOWS_POST_UPLOAD_DIAGNOSTIC: &str = "Get-ChildItem -Path . -Force
if (Test-Path vcpkg) { Get-ChildItem -Path vcpkg -Force }
if (Test-Path vcpkg_installed) { Get-ChildItem -Path vcpkg_installed -Force }";

fn validate_post_upload_tail(job: &str, tail: &[&WorkflowStep]) -> Result<(), &'static str> {
    match job {
        "build-windows" if tail.len() == 1 => {
            let diagnostic = tail[0];
            require_step_fields(diagnostic, &["name", "if", "run"])?;
            if diagnostic.name.as_deref() != Some("Debug VCPKG Location")
                || diagnostic.condition.as_deref() != Some("always()")
                || diagnostic.run.as_deref().map(str::trim) != Some(WINDOWS_POST_UPLOAD_DIAGNOSTIC)
            {
                return Err("Windows post-upload diagnostic changed");
            }
            Ok(())
        }
        "build-linux" | "build-arch" if tail.is_empty() => Ok(()),
        _ => Err("post-upload workflow tail changed"),
    }
}

fn validate_workflow_order_and_prerequisites(
    steps: &[WorkflowStep],
    classified: &ClassifiedWorkflowRuns,
    gates: &BTreeMap<String, usize>,
) -> Result<(), &'static str> {
    for job in ["build-windows", "build-linux", "build-arch"] {
        let completion = classified
            .package_completion
            .get(job)
            .ok_or("package completion ordinal missing")?;
        let gate = gates.get(job).ok_or("package verifier ordinal missing")?;
        if completion + 1 != *gate {
            return Err("package verifier does not immediately follow package creation");
        }
        let job_steps = steps
            .iter()
            .filter(|step| step.job == job)
            .collect::<Vec<_>>();
        let gate_index = job_steps
            .iter()
            .position(|step| step.ordinal == *gate)
            .ok_or("package verifier step missing")?;
        let expected_uploads =
            expected_package_upload_suffix(job).ok_or("package upload suffix missing")?;
        let suffix_end = gate_index + 1 + expected_uploads.len();
        let uploads = job_steps
            .get(gate_index + 1..suffix_end)
            .ok_or("package upload suffix is incomplete")?;
        for (upload, expected_artifact) in uploads.iter().zip(expected_uploads) {
            require_step_fields(upload, &["name", "uses", "with"])?;
            require_action_inputs(upload, &["name", "path"])?;
            if upload.uses.as_deref() != Some("actions/upload-artifact@v7")
                || upload.artifact_name.as_deref() != Some(*expected_artifact)
            {
                return Err("package publication suffix changed");
            }
        }
        validate_post_upload_tail(job, &job_steps[suffix_end..])?;
    }

    let release_gate = *gates
        .get("release")
        .ok_or("release verifier ordinal missing")?;
    let downloads = steps
        .iter()
        .filter(|step| step.uses.as_deref() == Some("actions/download-artifact@v8"))
        .collect::<Vec<_>>();
    let publications = steps
        .iter()
        .filter(|step| step.uses.as_deref() == Some("softprops/action-gh-release@v3"))
        .collect::<Vec<_>>();
    if downloads.len() != 1 || publications.len() != 1 {
        return Err("release action order is ambiguous");
    }
    let download = downloads[0];
    let publication = publications[0];
    let release_steps = steps
        .iter()
        .filter(|step| step.job == "release")
        .collect::<Vec<_>>();
    require_step_fields(download, &["name", "uses", "with"])?;
    require_action_inputs(download, &["path"])?;
    require_step_fields(publication, &["name", "uses", "with"])?;
    require_action_inputs(
        publication,
        &["files", "body_path", "generate_release_notes", "prerelease"],
    )?;
    if publication.inputs.get("body_path")
        != Some(&vec!["${{ github.workspace }}/RELEASE_BODY.md".to_owned()])
        || publication.inputs.get("generate_release_notes") != Some(&vec!["false".to_owned()])
        || publication.inputs.get("prerelease")
            != Some(&vec![
                "${{ contains(github.ref, 'beta') || contains(github.ref, 'alpha') || contains(github.ref, 'rc') }}"
                    .to_owned(),
            ])
    {
        return Err("final release action semantics changed");
    }
    if publication.job != "release"
        || !(download.ordinal < classified.assembly_ordinal
            && classified.assembly_ordinal < release_gate)
        || publication.ordinal != release_gate + 1
        || publication.ordinal + 1 != release_steps.len()
    {
        return Err("final assembly, verifier, and publication order changed");
    }

    let linux_dependencies = steps
        .iter()
        .filter(|step| {
            step.job == "build-linux" && step.name.as_deref() == Some("Install System Dependencies")
        })
        .collect::<Vec<_>>();
    let release_dependencies = steps
        .iter()
        .filter(|step| {
            step.job == "release"
                && step.name.as_deref() == Some("Install package gate dependencies")
        })
        .collect::<Vec<_>>();
    if linux_dependencies.len() != 1 || release_dependencies.len() != 1 {
        return Err("Linux package gate prerequisites are incomplete");
    }
    for dependency in [linux_dependencies[0], release_dependencies[0]] {
        require_step_fields(dependency, &["name", "run"])?;
        if dependency.run.as_deref().map(str::trim) != Some(LINUX_NATIVE_PACKAGE_GATE_DEPENDENCIES)
        {
            return Err("Linux package gate prerequisite set changed");
        }
    }
    if release_dependencies[0].ordinal >= release_gate {
        return Err("release package gate prerequisites follow verification");
    }
    let rust_setup = steps
        .iter()
        .filter(|step| {
            step.job == "release" && step.name.as_deref() == Some("Setup Rust for package gate")
        })
        .collect::<Vec<_>>();
    if rust_setup.len() != 1 || rust_setup[0].ordinal >= release_gate {
        return Err("release Rust prerequisite is missing or late");
    }
    require_step_fields(rust_setup[0], &["name", "uses"])?;
    Ok(())
}

#[derive(Debug)]
struct ReleaseInventory {
    exact_sources: BTreeSet<String>,
    final_sources: BTreeSet<String>,
    generated_trees: BTreeSet<String>,
    package_globs: BTreeSet<String>,
    artifact_exact_outputs: BTreeSet<String>,
    artifact_glob_outputs: BTreeSet<String>,
    release_outputs: BTreeSet<String>,
}

fn enumerate_authoritative_sources(
    wix: &str,
    cargo: &str,
    workflow: &str,
) -> Result<ReleaseInventory, &'static str> {
    validate_workflow_digest(workflow)?;
    enumerate_authoritative_sources_semantically(wix, cargo, workflow)
}

fn enumerate_authoritative_sources_semantically(
    wix: &str,
    cargo: &str,
    workflow: &str,
) -> Result<ReleaseInventory, &'static str> {
    let wix = wix_sources(wix)?;
    let deb = cargo_deb_sources(cargo)?;
    let parsed = validate_workflow_semantics(workflow)?;
    let steps = parsed.steps;
    let appimage_run = steps
        .iter()
        .find_map(|step| {
            step.run.as_deref().filter(|run| {
                run.contains("AppDir/") || run.contains("linuxdeploy-x86_64.AppImage")
            })
        })
        .ok_or("missing AppImage build step")?;
    let arch_run = steps
        .iter()
        .find_map(|step| step.run.as_deref().filter(|run| run.contains("PKGBUILD")))
        .ok_or("missing Arch staging step")?;
    let appimage = appimage_sources(appimage_run)?;
    let arch = arch_sources(arch_run)?;
    let classified = classify_package_and_release_runs(&steps)?;
    let gate_ordinals = validate_post_build_gate_steps(&steps)?;
    validate_workflow_order_and_prerequisites(&steps, &classified, &gate_ordinals)?;
    let calls = classified.assembly;

    let mut artifacts = BTreeMap::<String, BTreeSet<String>>::new();
    let mut exact_sources = wix.clone();
    let mut package_globs = BTreeSet::new();
    let mut artifact_exact_outputs = BTreeSet::new();
    let mut artifact_glob_outputs = BTreeSet::new();
    exact_sources.extend(deb.iter().cloned());
    exact_sources.extend(appimage.iter().cloned());
    exact_sources.extend(arch.iter().cloned());
    let mut downloads = 0;
    let mut releases = 0;
    for step in &steps {
        let Some(uses) = step.uses.as_deref() else {
            continue;
        };
        if uses == "actions/download-artifact@v8" {
            downloads += 1;
            if step.job != "release" || step.paths != ["artifacts"] || step.artifact_name.is_some()
            {
                return Err("download artifact declaration changed");
            }
            continue;
        }
        if uses == "softprops/action-gh-release@v3" {
            releases += 1;
            if step.job != "release" || step.release_files != ["release/*"] {
                return Err("final release publication declaration changed");
            }
            continue;
        }
        if uses != "actions/upload-artifact@v7" {
            if step.artifact_name.is_some() || !step.release_files.is_empty() {
                return Err("unrecognized artifact or release action inputs");
            }
            if uses.contains("upload-artifact")
                || uses.contains("download-artifact")
                || uses.contains("action-gh-release")
            {
                return Err("unrecognized artifact or release action");
            }
            continue;
        }
        let artifact = step
            .artifact_name
            .clone()
            .ok_or("upload missing artifact name")?;
        if expected_artifact_job(&artifact) != Some(step.job.as_str()) {
            return Err("upload artifact declared in unexpected job");
        }
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
                let member = path.rsplit('/').next().expect("nonempty path").to_owned();
                package_globs.insert(path);
                artifact_glob_outputs.insert(format!("artifacts/{artifact}/{member}"));
                members.insert(member);
            } else {
                let path = validate_exact_source(&path)?;
                let member = Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or("upload source has no file name")?
                    .to_owned();
                exact_sources.insert(path.clone());
                artifact_exact_outputs.insert(format!("artifacts/{artifact}/{member}"));
                members.insert(member);
            }
        }
        artifacts.insert(artifact, members);
    }
    if downloads != 1 || releases != 1 || artifacts != expected_artifacts() {
        return Err("artifact/release action set is incomplete or duplicated");
    }

    let mut consumed = BTreeMap::<String, BTreeSet<String>>::new();
    let mut final_sources = BTreeSet::new();
    let mut final_destinations = BTreeSet::new();
    let mut release_outputs = BTreeSet::new();
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
        release_outputs.insert(format!("release/{destination}"));
        if !final_destinations.insert(destination) {
            return Err("duplicate final release destination");
        }
    }
    if consumed != artifacts
        || final_destinations
            != EXPECTED_RELEASE_DESTINATIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
    {
        return Err("not every uploaded package input reaches final assembly");
    }
    let exact_sources_expected = EXPECTED_EXACT_SOURCES
        .iter()
        .map(|source| (*source).to_owned())
        .collect::<BTreeSet<_>>();
    if exact_sources != exact_sources_expected {
        return Err("exact release source contract changed");
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
        package_globs,
        artifact_exact_outputs,
        artifact_glob_outputs,
        release_outputs,
    })
}

#[derive(Clone, Copy, Debug)]
enum PostBuildStage {
    Windows,
    Linux,
    Arch,
    Release,
}

fn package_glob_matches(pattern: &str, name: &str) -> bool {
    match pattern {
        "*.msi" => name.ends_with(".msi"),
        "*.deb" => name.ends_with(".deb"),
        "*.AppImage" => name.ends_with(".AppImage"),
        "*.pkg.tar.zst" => name.ends_with(".pkg.tar.zst"),
        "stream-server-[0-9]*.pkg.tar.zst" => name
            .strip_prefix("stream-server-")
            .and_then(|value| value.strip_suffix(".pkg.tar.zst"))
            .is_some_and(|version| {
                version
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_digit())
            }),
        _ => false,
    }
}

fn scan_required_glob(repository: &Path, declaration: &str) -> Result<(), &'static str> {
    let declaration = Path::new(declaration);
    let pattern = declaration
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("package glob has no file name")?;
    let parent = declaration.parent().unwrap_or_else(|| Path::new(""));
    let parent = repository.join(parent);
    let metadata = fs::symlink_metadata(&parent).map_err(|_| "package glob parent is missing")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata_is_reparse(&metadata) {
        return Err("package glob parent is not a direct regular directory");
    }
    let mut matches = 0;
    for entry in fs::read_dir(&parent).map_err(|_| "package glob enumeration failed")? {
        let entry = entry.map_err(|_| "package glob entry could not be enumerated")?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or("package glob entry is not UTF-8")?
            .to_owned();
        if package_glob_matches(pattern, &name) {
            candidate_tree_is_safe(repository, &entry.path())?;
            matches += 1;
        }
    }
    if matches == 0 {
        return Err("required package output is missing");
    }
    Ok(())
}

fn direct_directory_members(path: &Path) -> Result<BTreeSet<String>, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "package output directory is missing")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata_is_reparse(&metadata) {
        return Err("package output directory is not a direct regular directory");
    }
    fs::read_dir(path)
        .map_err(|_| "package output directory enumeration failed")?
        .map(|entry| {
            entry
                .map_err(|_| "package output directory entry unavailable")?
                .file_name()
                .into_string()
                .map_err(|_| "package output directory entry is not UTF-8")
        })
        .collect()
}

fn validate_post_build_outputs(
    repository: &Path,
    inventory: &ReleaseInventory,
    stage: PostBuildStage,
) -> Result<(), &'static str> {
    if matches!(stage, PostBuildStage::Release) {
        let expected = inventory
            .release_outputs
            .iter()
            .filter_map(|path| Path::new(path).file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .chain(["SHA256SUMS.txt".to_owned()])
            .collect::<BTreeSet<_>>();
        if direct_directory_members(&repository.join("release"))? != expected {
            return Err("final release directory contains an unenumerated publication");
        }
    }
    let exact = match stage {
        PostBuildStage::Windows => inventory
            .exact_sources
            .iter()
            .filter(|path| path.starts_with("target/x86_64-pc-windows-msvc/"))
            .cloned()
            .collect::<BTreeSet<_>>(),
        PostBuildStage::Linux | PostBuildStage::Arch => inventory
            .exact_sources
            .iter()
            .filter(|path| {
                path.starts_with("target/release/")
                    || (matches!(stage, PostBuildStage::Linux)
                        && *path == "stream-server-linux-amd64.AppImage")
            })
            .cloned()
            .collect(),
        PostBuildStage::Release => inventory
            .artifact_exact_outputs
            .iter()
            .chain(inventory.release_outputs.iter())
            .cloned()
            .chain(["release/SHA256SUMS.txt".to_owned()])
            .collect(),
    };
    for path in exact {
        let path = repository.join(path);
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "required package output is missing")?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata_is_reparse(&metadata)
        {
            return Err("required package output is not a direct regular file");
        }
        candidate_tree_is_safe(repository, &path)?;
    }

    let globs = match stage {
        PostBuildStage::Windows => inventory
            .package_globs
            .iter()
            .filter(|path| path.starts_with("target/wix/"))
            .cloned()
            .collect::<BTreeSet<_>>(),
        PostBuildStage::Linux => inventory
            .package_globs
            .iter()
            .filter(|path| *path == "target/debian/*.deb" || *path == "*.AppImage")
            .cloned()
            .collect(),
        PostBuildStage::Arch => inventory
            .package_globs
            .iter()
            .filter(|path| path.starts_with("pkg/"))
            .cloned()
            .collect(),
        PostBuildStage::Release => inventory.artifact_glob_outputs.clone(),
    };
    for declaration in globs {
        scan_required_glob(repository, &declaration)?;
    }

    let trees = match stage {
        PostBuildStage::Windows => Vec::new(),
        PostBuildStage::Linux => vec!["AppDir"],
        PostBuildStage::Arch => vec!["pkg"],
        PostBuildStage::Release => vec!["artifacts", "release"],
    };
    for tree in trees {
        if !inventory.generated_trees.contains(tree) {
            return Err("post-build tree is not tied to structural inventory");
        }
        candidate_tree_is_safe(repository, &repository.join(tree))?;
    }
    Ok(())
}

fn read_authoritative_release_workflow(workflows: &Path) -> Result<String, &'static str> {
    let mut declarations = BTreeMap::new();
    for entry in fs::read_dir(workflows).map_err(|_| "workflow directory unavailable")? {
        let entry = entry.map_err(|_| "workflow directory entry unavailable")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| "workflow metadata unavailable")?;
        if metadata.file_type().is_symlink() || metadata_is_reparse(&metadata) {
            return Err("workflow declaration is a link or reparse point");
        }
        if !metadata.is_file() {
            continue;
        }
        let extension = path.extension().and_then(|value| value.to_str());
        if !matches!(extension, Some("yml" | "yaml")) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("workflow file name is not UTF-8")?
            .to_owned();
        let value = fs::read_to_string(path).map_err(|_| "workflow declaration unreadable")?;
        declarations.insert(name, value);
    }
    if declarations.keys().map(String::as_str).collect::<Vec<_>>() != ["release.yml"] {
        return Err("authoritative workflow file set changed");
    }
    declarations
        .remove("release.yml")
        .ok_or("release workflow missing")
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
    let workspace_workflow =
        read_authoritative_release_workflow(&repository.join(".github/workflows"))
            .expect("read closed authoritative release workflow set");
    let workflow = authoritative_workflow_for_current_environment(&repository, &workspace_workflow)
        .expect("authenticate authoritative release workflow identity");
    (repository, wix, cargo, workflow)
}

fn write_safe_fixture(root: &Path, relative: &str) -> PathBuf {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
    fs::write(&path, b"ordinary application package output").expect("write safe fixture");
    path
}

fn materialize_glob_fixture(root: &Path, declaration: &str) -> PathBuf {
    let declaration = Path::new(declaration);
    let pattern = declaration
        .file_name()
        .and_then(|name| name.to_str())
        .expect("fixture glob name");
    let name = match pattern {
        "*.msi" => "stream-server.msi",
        "*.deb" => "stream-server.deb",
        "*.AppImage" => "stream-server.AppImage",
        "*.pkg.tar.zst" | "stream-server-[0-9]*.pkg.tar.zst" => "stream-server-1.pkg.tar.zst",
        _ => panic!("unexpected fixture glob {pattern}"),
    };
    write_safe_fixture(
        root,
        &declaration
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(name)
            .to_string_lossy(),
    )
}

fn populate_post_build_fixture(
    root: &Path,
    inventory: &ReleaseInventory,
    stage: PostBuildStage,
) -> Vec<PathBuf> {
    let mut outputs = Vec::new();
    let exact = match stage {
        PostBuildStage::Windows => inventory
            .exact_sources
            .iter()
            .filter(|path| path.starts_with("target/x86_64-pc-windows-msvc/"))
            .cloned()
            .collect::<BTreeSet<_>>(),
        PostBuildStage::Linux | PostBuildStage::Arch => inventory
            .exact_sources
            .iter()
            .filter(|path| {
                path.starts_with("target/release/")
                    || (matches!(stage, PostBuildStage::Linux)
                        && *path == "stream-server-linux-amd64.AppImage")
            })
            .cloned()
            .collect(),
        PostBuildStage::Release => inventory
            .artifact_exact_outputs
            .iter()
            .chain(inventory.release_outputs.iter())
            .cloned()
            .chain(["release/SHA256SUMS.txt".to_owned()])
            .collect(),
    };
    outputs.extend(exact.iter().map(|path| write_safe_fixture(root, path)));
    let globs = match stage {
        PostBuildStage::Windows => inventory
            .package_globs
            .iter()
            .filter(|path| path.starts_with("target/wix/"))
            .cloned()
            .collect::<BTreeSet<_>>(),
        PostBuildStage::Linux => inventory
            .package_globs
            .iter()
            .filter(|path| *path == "target/debian/*.deb" || *path == "*.AppImage")
            .cloned()
            .collect(),
        PostBuildStage::Arch => inventory
            .package_globs
            .iter()
            .filter(|path| path.starts_with("pkg/"))
            .cloned()
            .collect(),
        PostBuildStage::Release => inventory.artifact_glob_outputs.clone(),
    };
    outputs.extend(
        globs
            .iter()
            .map(|glob| materialize_glob_fixture(root, glob)),
    );
    for tree in match stage {
        PostBuildStage::Windows => Vec::new(),
        PostBuildStage::Linux => vec!["AppDir"],
        PostBuildStage::Arch => vec!["pkg"],
        PostBuildStage::Release => vec!["artifacts", "release"],
    } {
        let tree = root.join(tree);
        fs::create_dir_all(&tree).expect("create generated tree");
        if fs::read_dir(&tree)
            .expect("read generated tree")
            .next()
            .is_none()
        {
            outputs.push(write_safe_fixture(&tree, "ordinary.txt"));
        }
    }
    outputs
}

#[test]
fn authoritative_release_declarations_structurally_enumerate_all_safe_inputs() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let inventory = enumerate_authoritative_sources(&wix, &cargo, &workflow)
        .expect("structurally enumerate authoritative package sources");
    assert!(inventory.exact_sources.len() >= 6);
    assert_eq!(inventory.final_sources.len(), 10);
    assert_eq!(inventory.package_globs.len(), 3);
    assert_eq!(inventory.artifact_exact_outputs.len(), 7);
    assert_eq!(inventory.artifact_glob_outputs.len(), 3);
    assert_eq!(inventory.release_outputs.len(), 10);
}

#[test]
fn workflow_directory_contract_rejects_an_extra_workflow_file() {
    let (_, _, _, workflow) = repository_inputs();
    let directory = tempfile::tempdir().expect("workflow directory fixture");
    fs::write(directory.path().join("release.yml"), workflow).expect("write release workflow");
    fs::write(
        directory.path().join("shadow-release.yaml"),
        "jobs:\n  shadow:\n    steps:\n      - uses: softprops/action-gh-release@v3\n",
    )
    .expect("write shadow workflow");
    assert!(read_authoritative_release_workflow(directory.path()).is_err());
}

#[test]
fn post_build_gate_requires_every_declared_output_and_scans_no_follow() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let inventory = enumerate_authoritative_sources(&wix, &cargo, &workflow)
        .expect("enumerate post-build contract");
    for stage in [
        PostBuildStage::Windows,
        PostBuildStage::Linux,
        PostBuildStage::Arch,
        PostBuildStage::Release,
    ] {
        let directory = tempfile::tempdir().expect("post-build fixture");
        let outputs = populate_post_build_fixture(directory.path(), &inventory, stage);
        validate_post_build_outputs(directory.path(), &inventory, stage)
            .unwrap_or_else(|error| panic!("complete {stage:?} fixture failed: {error}"));
        fs::remove_file(outputs.first().expect("stage has expected output"))
            .expect("remove one expected output");
        assert!(
            validate_post_build_outputs(directory.path(), &inventory, stage).is_err(),
            "missing {stage:?} output passed"
        );
    }
}

#[test]
fn downloaded_linuxdeploy_tool_cannot_stand_in_for_the_built_appimage() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let inventory = enumerate_authoritative_sources(&wix, &cargo, &workflow)
        .expect("enumerate AppImage output contract");
    let directory = tempfile::tempdir().expect("AppImage output fixture");
    let outputs = populate_post_build_fixture(directory.path(), &inventory, PostBuildStage::Linux);
    let generated = outputs
        .iter()
        .find(|path| {
            path.parent() == Some(directory.path())
                && path.ends_with("stream-server-linux-amd64.AppImage")
        })
        .expect("generated AppImage fixture");
    fs::remove_file(generated).expect("remove generated AppImage");
    write_safe_fixture(directory.path(), "linuxdeploy-x86_64.AppImage");
    assert!(
        validate_post_build_outputs(directory.path(), &inventory, PostBuildStage::Linux).is_err(),
        "downloaded linuxdeploy tool satisfied the application output contract"
    );
}

#[test]
fn release_gate_rejects_an_unenumerated_safe_publication_file() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let inventory = enumerate_authoritative_sources(&wix, &cargo, &workflow)
        .expect("enumerate final publication contract");
    let directory = tempfile::tempdir().expect("final publication fixture");
    populate_post_build_fixture(directory.path(), &inventory, PostBuildStage::Release);
    write_safe_fixture(directory.path(), "release/operator-note.txt");
    assert!(
        validate_post_build_outputs(directory.path(), &inventory, PostBuildStage::Release).is_err(),
        "release wildcard admitted an unenumerated safe file"
    );
}

#[cfg(windows)]
#[test]
fn post_build_gate_rejects_a_dangling_reparse_input() {
    use std::os::windows::fs::symlink_file;

    let (_, wix, cargo, workflow) = repository_inputs();
    let inventory = enumerate_authoritative_sources(&wix, &cargo, &workflow)
        .expect("enumerate post-build contract");
    let directory = tempfile::tempdir().expect("dangling output fixture");
    populate_post_build_fixture(directory.path(), &inventory, PostBuildStage::Windows);
    let output = directory
        .path()
        .join("target/x86_64-pc-windows-msvc/release/server.exe");
    fs::remove_file(&output).expect("remove regular fixture");
    symlink_file("missing-server.exe", &output).expect("create dangling output link");
    assert!(
        validate_post_build_outputs(directory.path(), &inventory, PostBuildStage::Windows).is_err()
    );
}

#[test]
fn candidate_tree_propagates_directory_enumeration_errors() {
    let directory = tempfile::tempdir().expect("enumeration error fixture");
    let blocked = directory.path().join("blocked");
    fs::create_dir(&blocked).expect("create blocked directory");
    fs::write(blocked.join("ordinary.txt"), b"ordinary").expect("write blocked child");
    let mut reader = |path: &Path| {
        if path == blocked {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected directory entry failure",
            ));
        }
        fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect()
    };
    assert!(scan_candidate_tree_with(directory.path(), directory.path(), &mut reader).is_err());
}

#[test]
#[ignore = "post-build gate: set STREAM_SERVER_RELEASE_GATE_STAGE=windows|linux|arch|release after that job builds"]
fn authoritative_post_build_package_gate() {
    let (repository, wix, cargo, workflow) = repository_inputs();
    let inventory = enumerate_authoritative_sources(&wix, &cargo, &workflow)
        .expect("enumerate post-build contract");
    let stage = match std::env::var("STREAM_SERVER_RELEASE_GATE_STAGE").as_deref() {
        Ok("windows") => PostBuildStage::Windows,
        Ok("linux") => PostBuildStage::Linux,
        Ok("arch") => PostBuildStage::Arch,
        Ok("release") => PostBuildStage::Release,
        _ => panic!("set STREAM_SERVER_RELEASE_GATE_STAGE for the completed release job"),
    };
    validate_post_build_outputs(&repository, &inventory, stage)
        .unwrap_or_else(|error| panic!("post-build package gate failed: {error}"));
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
        assert!(enumerate_authoritative_sources_semantically(&wix, &cargo, &mutated).is_err());
    }
    let cargo_directory = cargo.replace("target/release/server\"", "target/release/\"");
    assert!(enumerate_authoritative_sources(&wix, &cargo_directory, &workflow).is_err());
    let wix_variable = wix.replace("$(var.CargoTargetBinDir)", "$(var.UnknownBinDir)");
    assert!(enumerate_authoritative_sources(&wix_variable, &cargo, &workflow).is_err());
}

#[test]
fn workflow_contract_rejects_unnamed_duplicate_and_changed_release_declarations() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let workflow = workflow.replace("\r\n", "\n");
    let unnamed_upload = workflow.replacen(
        "      - name: Build MSI Installer\n",
        "      - uses: actions/upload-artifact@v7\n        with:\n          name: shadow-upload\n          path: payload.bin\n\n      - name: Build MSI Installer\n",
        1,
    );
    let appimage_start = workflow
        .find("      - name: Build AppImage\n")
        .expect("AppImage step");
    let appimage_end = workflow[appimage_start + 1..]
        .find("\n      - name:")
        .map(|offset| appimage_start + 1 + offset + 1)
        .expect("step after AppImage");
    let duplicated_appimage = format!(
        "{}{}{}",
        &workflow[..appimage_end],
        &workflow[appimage_start..appimage_end],
        &workflow[appimage_end..]
    );
    let changed_release_files = workflow.replace("files: release/*", "files: release/*.zip");
    let extra_release_files = workflow.replace(
        "files: release/*",
        "files: |\n            release/*\n            payload/*",
    );

    for mutation in [
        unnamed_upload,
        duplicated_appimage,
        changed_release_files,
        extra_release_files,
    ] {
        assert!(
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation).is_err(),
            "workflow mutation escaped the closed release contract"
        );
    }
}

fn move_named_workflow_step_after(workflow: &str, moving: &str, after: &str) -> String {
    let mut blocks = workflow
        .split("\n      - ")
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let moving_prefix = format!("name: {moving}\n");
    let after_prefix = format!("name: {after}\n");
    let moving_index = blocks
        .iter()
        .position(|block| block.starts_with(&moving_prefix))
        .unwrap_or_else(|| panic!("missing workflow step {moving}"));
    let moving_block = blocks.remove(moving_index);
    let after_index = blocks
        .iter()
        .position(|block| block.starts_with(&after_prefix))
        .unwrap_or_else(|| panic!("missing workflow step {after}"));
    blocks.insert(after_index + 1, moving_block);
    blocks.join("\n      - ")
}

fn insert_workflow_step_after(workflow: &str, after: &str, step: &str) -> String {
    let marker = format!("      - name: {after}\n");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("missing workflow step {after}"));
    let search_start = start + marker.len();
    let remainder = &workflow[search_start..];
    let end = ["\n      - ", "\n  build-", "\n  release:"]
        .into_iter()
        .filter_map(|boundary| remainder.find(boundary))
        .min()
        .map_or(workflow.len(), |offset| search_start + offset);
    format!("{}\n      - {step}{}", &workflow[..end], &workflow[end..])
}

fn round_five_compliant_workflow(workflow: &str) -> String {
    let workflow = move_named_workflow_step_after(
        &workflow.replace("\r\n", "\n"),
        "Upload EXE",
        "Verify Windows package outputs",
    );
    workflow.replace(
        "      - name: Setup Rust for package gate\n        uses: dtolnay/rust-toolchain@1.98.0\n\n      - name: Download all artifacts",
        "      - name: Setup Rust for package gate\n        uses: dtolnay/rust-toolchain@1.98.0\n\n      - name: Install package gate dependencies\n        run: |\n          sudo sed -i 's|http://azure.archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' /etc/apt/apt-mirrors.txt\n          sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update\n          sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y build-essential cmake curl pkg-config libssl-dev libfuse2 libboost-dev libclang-dev libgtk-3-dev libayatana-appindicator3-dev\n\n      - name: Download all artifacts",
    )
}

fn round_six_compliant_workflow(workflow: &str) -> String {
    move_named_workflow_step_after(
        &round_five_compliant_workflow(workflow),
        "Generate release description",
        "Prepare release files",
    )
}

fn round_eight_compliant_workflow(workflow: &str) -> String {
    let workflow = round_six_compliant_workflow(workflow);
    if workflow.contains("permissions:\n  contents: read") {
        workflow
    } else {
        workflow.replace(
            "env:\n  CARGO_TERM_COLOR: always",
            "permissions:\n  contents: read\n\nenv:\n  CARGO_TERM_COLOR: always",
        )
    }
}

#[test]
fn workflow_contract_rejects_order_and_failure_semantics_mutations() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let compliant = round_five_compliant_workflow(&workflow);
    enumerate_authoritative_sources(&wix, &cargo, &compliant)
        .expect("round-five compliant workflow fixture");

    let mutations = [
        (
            "verifier before package build",
            move_named_workflow_step_after(
                &compliant,
                "Build MSI Installer",
                "Verify Windows package outputs",
            ),
        ),
        (
            "verifier after upload",
            move_named_workflow_step_after(
                &compliant,
                "Verify Windows package outputs",
                "Upload MSI",
            ),
        ),
        (
            "continue-on-error",
            compliant.replace(
                "      - name: Verify Windows package outputs\n",
                "      - name: Verify Windows package outputs\n        continue-on-error: true\n",
            ),
        ),
        (
            "ignored missing upload",
            compliant.replace(
                "          path: target/wix/*.msi",
                "          path: target/wix/*.msi\n          if-no-files-found: ignore",
            ),
        ),
        (
            "duplicate path input",
            compliant.replace(
                "          path: target/wix/*.msi",
                "          path: target/wix/*.msi\n          path: target/wix/*.msi",
            ),
        ),
        (
            "unknown step field",
            compliant.replace(
                "      - name: Verify Windows package outputs\n",
                "      - name: Verify Windows package outputs\n        risk-mode: permissive\n",
            ),
        ),
        (
            "unknown action input",
            compliant.replace(
                "          path: target/wix/*.msi",
                "          path: target/wix/*.msi\n          retention-days: 1",
            ),
        ),
        (
            "unsupported YAML alias",
            compliant.replace(
                "      - name: Verify Windows package outputs\n",
                "      - name: Verify Windows package outputs\n        <<: *unsafe-step\n",
            ),
        ),
        (
            "unsupported YAML alias scalar",
            compliant.replace(
                "          body_path: ${{ github.workspace }}/RELEASE_BODY.md",
                "          body_path: *unsafe-body",
            ),
        ),
        (
            "unsupported YAML anchor scalar",
            compliant.replace(
                "          body_path: ${{ github.workspace }}/RELEASE_BODY.md",
                "          body_path: &unsafe-body RELEASE_BODY.md",
            ),
        ),
        (
            "release verifier before assembly",
            move_named_workflow_step_after(
                &compliant,
                "Prepare release files",
                "Verify final release outputs",
            ),
        ),
        (
            "release verifier after publication",
            move_named_workflow_step_after(
                &compliant,
                "Verify final release outputs",
                "Create GitHub Release",
            ),
        ),
    ];
    let escaped = mutations
        .into_iter()
        .filter_map(|(name, mutation)| {
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation)
                .is_ok()
                .then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        escaped.is_empty(),
        "unsafe workflow mutations passed: {escaped:?}"
    );
}

#[test]
fn release_gate_requires_exact_linux_native_prerequisites_before_verification() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let compliant = round_five_compliant_workflow(&workflow);
    enumerate_authoritative_sources(&wix, &cargo, &compliant)
        .expect("release gate has exact Linux prerequisites");
    let mutations = [
        move_named_workflow_step_after(
            &compliant,
            "Install package gate dependencies",
            "Verify final release outputs",
        ),
        compliant.replace("libgtk-3-dev", "libgtk-4-dev"),
    ];
    assert!(mutations.into_iter().all(|mutation| {
        enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation).is_err()
    }));
}

#[test]
fn workflow_contract_rejects_every_post_verifier_mutation_path() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let compliant = round_six_compliant_workflow(&workflow);
    enumerate_authoritative_sources(&wix, &cargo, &compliant)
        .expect("round-six compliant workflow fixture");

    let stages = [
        (
            "Verify Windows package outputs",
            "Copy-Item payload/renamed-codec.exe target/x86_64-pc-windows-msvc/release/server.exe",
        ),
        (
            "Verify Linux package outputs",
            "cp payload/renamed-codec.zip stream-server-linux-amd64.AppImage",
        ),
        (
            "Verify Arch package outputs",
            "cp payload/renamed-codec.exe pkg/stream-server-renamed.pkg.tar.zst",
        ),
        (
            "Verify final release outputs",
            "cp payload/renamed-codec.zip release/renamed-codec.bin",
        ),
    ];
    let block_headers = [
        "|",
        "|+",
        "|-",
        "|2",
        "| 2",
        "| +",
        "| -",
        "| 2 # trailing comment",
        "| # trailing comment",
        "|+ # trailing comment",
        ">",
        ">+",
        ">-",
        ">2",
    ];
    let mut mutations = Vec::<(String, String)>::new();
    for (verifier, command) in stages {
        for header in block_headers {
            mutations.push((
                format!("{verifier}: run {header}"),
                insert_workflow_step_after(
                    &compliant,
                    verifier,
                    &format!(
                        "name: Mutate verified payload\n        run: {header}\n          {command}"
                    ),
                ),
            ));
        }
        mutations.push((
            format!("{verifier}: intervening action"),
            insert_workflow_step_after(
                &compliant,
                verifier,
                "name: Intervening action\n        uses: actions/checkout@v7",
            ),
        ));
    }
    mutations.push((
        "release notes after final verifier".to_owned(),
        move_named_workflow_step_after(
            &compliant,
            "Generate release description",
            "Verify final release outputs",
        ),
    ));
    for (name, fields) in [
        (
            "mixed uses and run",
            "uses: actions/checkout@v7\n        run: echo mutate",
        ),
        ("post-gate shell", "run: echo mutate\n        shell: pwsh"),
        (
            "post-gate working directory",
            "run: echo mutate\n        working-directory: release",
        ),
        (
            "post-gate continue-on-error",
            "run: echo mutate\n        continue-on-error: true",
        ),
        (
            "post-gate environment",
            "run: echo mutate\n        env:\n          PAYLOAD: renamed-codec.exe",
        ),
    ] {
        mutations.push((
            name.to_owned(),
            insert_workflow_step_after(
                &compliant,
                "Verify Windows package outputs",
                &format!("name: Boundary field mutation\n        {fields}"),
            ),
        ));
    }

    let escaped = mutations
        .into_iter()
        .filter_map(|(name, mutation)| {
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation)
                .is_ok()
                .then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        escaped.is_empty(),
        "post-verifier mutations escaped the contract: {escaped:?}"
    );
}

#[test]
fn workflow_contract_allows_only_the_exact_post_upload_diagnostic_tail() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let compliant = round_six_compliant_workflow(&workflow);
    enumerate_authoritative_sources(&wix, &cargo, &compliant)
        .expect("round-six post-upload boundary fixture");

    let mutations = [
        (
            "step after Windows suffix",
            insert_workflow_step_after(
                &compliant,
                "Upload MSI",
                "name: Mutate after Windows uploads\n        run: Copy-Item payload/renamed-codec.exe target/x86_64-pc-windows-msvc/release/server.exe",
            ),
        ),
        (
            "step after Linux suffix",
            insert_workflow_step_after(
                &compliant,
                "Upload AppImage",
                "name: Mutate after Linux uploads\n        run: cp payload/renamed-codec.zip stream-server-linux-amd64.AppImage",
            ),
        ),
        (
            "step after Arch suffix",
            insert_workflow_step_after(
                &compliant,
                "Upload Arch Package",
                "name: Mutate after Arch upload\n        run: cp payload/renamed-codec.exe pkg/stream-server-renamed.pkg.tar.zst",
            ),
        ),
        (
            "changed diagnostic body",
            compliant.replace(
                "          Get-ChildItem -Path . -Force",
                "          Copy-Item payload/renamed-codec.exe target/x86_64-pc-windows-msvc/release/server.exe",
            ),
        ),
        (
            "changed diagnostic condition",
            compliant.replace("        if: always()", "        if: success()"),
        ),
        (
            "diagnostic environment",
            compliant.replace(
                "      - name: Debug VCPKG Location\n",
                "      - name: Debug VCPKG Location\n        env:\n          PAYLOAD: renamed-codec.exe\n",
            ),
        ),
    ];
    let escaped = mutations
        .into_iter()
        .filter_map(|(name, mutation)| {
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation)
                .is_ok()
                .then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        escaped.is_empty(),
        "post-upload tail mutations escaped the contract: {escaped:?}"
    );
}

#[test]
fn packaging_jobs_reject_extra_duplicate_or_mutated_pre_verifier_steps() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let compliant = round_six_compliant_workflow(&workflow);
    enumerate_authoritative_sources(&wix, &cargo, &compliant)
        .expect("round-seven ordered-step baseline");

    let mut mutations = vec![
        (
            "duplicate github-script",
            insert_workflow_step_after(
                &compliant,
                "Build Release",
                "name: Replace verified source\n        uses: actions/github-script@v9\n        with:\n          script: |\n            require('fs').writeFileSync('target/x86_64-pc-windows-msvc/release/server.exe', 'MZ')",
            ),
        ),
        (
            "changed github-script body",
            compliant.replace(
                "core.exportVariable('ACTIONS_CACHE_URL', process.env.ACTIONS_CACHE_URL);",
                "require('fs').writeFileSync('target/x86_64-pc-windows-msvc/release/server.exe', 'MZ');",
            ),
        ),
        (
            "changed cache path",
            compliant.replace("          path: target\n", "          path: payload\n"),
        ),
        (
            "changed cache key",
            compliant.replace(
                "          key: arch-cargo-${{ hashFiles('**/Cargo.lock') }}",
                "          key: attacker-controlled-cache",
            ),
        ),
        (
            "changed cache restore key",
            compliant.replace("            arch-cargo-", "            attacker-cache-"),
        ),
        (
            "changed toolchain target",
            compliant.replace("          targets: x86_64-pc-windows-msvc", "          targets: aarch64-pc-windows-msvc"),
        ),
        (
            "changed checkout fetch depth",
            compliant.replace("          fetch-depth: 0", "          fetch-depth: 1"),
        ),
        (
            "changed install-action tool list",
            compliant.replace("          tool: cargo-chef,cargo-wix", "          tool: cargo-chef"),
        ),
        (
            "changed vcpkg commit",
            compliant.replace(
                "          vcpkgGitCommitId: '9e593bb18ea69cc5095e012465dcd675a822ed0d'",
                "          vcpkgGitCommitId: '0000000000000000000000000000000000000000'",
            ),
        ),
        (
            "changed action environment",
            compliant.replace(
                "          VCPKG_DEFAULT_TRIPLET: x64-windows-v3-static-md-release",
                "          VCPKG_DEFAULT_TRIPLET: attacker",
            ),
        ),
        (
            "pre-verifier failure field",
            compliant.replace(
                "      - name: Build MSI Installer\n",
                "      - name: Build MSI Installer\n        continue-on-error: true\n",
            ),
        ),
    ];

    for (verifier, preceding) in [
        ("Verify Windows package outputs", "Build MSI Installer"),
        ("Verify Linux package outputs", "Build AppImage"),
        ("Verify Arch package outputs", "Build package"),
        (
            "Verify final release outputs",
            "Generate release description",
        ),
    ] {
        mutations.push((
            verifier,
            insert_workflow_step_after(
                &compliant,
                preceding,
                "name: Mutate before verifier\n        run: echo replace verified payload",
            ),
        ));
        mutations.push((
            verifier,
            insert_workflow_step_after(&compliant, preceding, "uses: actions/checkout@v7"),
        ));
    }

    for (label, preceding) in [
        ("duplicate Windows cache", "Build Release"),
        ("duplicate Linux cache", "Build DEB Package"),
        ("duplicate Arch cache", "Build binary"),
    ] {
        mutations.push((
            label,
            insert_workflow_step_after(
                &compliant,
                preceding,
                "name: Duplicate cache\n        uses: actions/cache@v6\n        with:\n          path: payload\n          key: duplicate\n          restore-keys: duplicate-",
            ),
        ));
    }

    for (label, preceding) in [
        ("duplicate Windows toolchain", "Build Release"),
        ("duplicate Linux toolchain", "Build DEB Package"),
        (
            "duplicate release toolchain",
            "Generate release description",
        ),
    ] {
        mutations.push((
            label,
            insert_workflow_step_after(
                &compliant,
                preceding,
                "name: Duplicate toolchain\n        uses: dtolnay/rust-toolchain@1.98.0",
            ),
        ));
    }

    let escaped = mutations
        .into_iter()
        .filter_map(|(name, mutation)| {
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation)
                .is_ok()
                .then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        escaped.is_empty(),
        "pre-verifier action/run mutations escaped: {escaped:?}"
    );
}

#[test]
fn packaging_jobs_reject_changed_or_duplicate_job_level_semantics() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let compliant = round_six_compliant_workflow(&workflow);
    enumerate_authoritative_sources(&wix, &cargo, &compliant)
        .expect("round-seven job contract baseline");

    let mutations = [
        (
            "changed runner",
            compliant.replace("    runs-on: windows-2022", "    runs-on: self-hosted"),
        ),
        (
            "changed job condition",
            compliant.replace(
                "    if: startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch'",
                "    if: always()",
            ),
        ),
        (
            "changed job environment",
            compliant.replace(
                "      VCPKG_BINARY_SOURCES: \"clear;x-gha,readwrite\"",
                "      VCPKG_BINARY_SOURCES: attacker",
            ),
        ),
        (
            "changed container",
            compliant.replace("    container: archlinux:latest", "    container: attacker/image:latest"),
        ),
        (
            "changed release needs",
            compliant.replace(
                "    needs: [build-windows, build-linux, build-arch]",
                "    needs: [build-windows]",
            ),
        ),
        (
            "changed release permission",
            compliant.replace("      contents: write", "      contents: read"),
        ),
        (
            "job defaults alter run meaning",
            compliant.replace(
                "    runs-on: windows-2022\n",
                "    runs-on: windows-2022\n    defaults:\n      run:\n        shell: cmd\n",
            ),
        ),
        (
            "job strategy changes execution",
            compliant.replace(
                "    runs-on: ubuntu-24.04\n",
                "    runs-on: ubuntu-24.04\n    strategy:\n      matrix:\n        payload: [safe, attacker]\n",
            ),
        ),
        (
            "job service adds mutable input",
            compliant.replace(
                "    container: archlinux:latest\n",
                "    container: archlinux:latest\n    services:\n      payload:\n        image: attacker/image:latest\n",
            ),
        ),
        (
            "duplicate participating job key",
            compliant.replace(
                "  release:\n",
                "  build-windows:\n    runs-on: windows-2022\n    steps:\n      - run: echo shadow\n\n  release:\n",
            ),
        ),
        (
            "additional contents-write job",
            compliant.replace(
                "  release:\n",
                "  shadow-release:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - run: echo shadow\n\n  release:\n",
            ),
        ),
        (
            "additional artifact-upload job",
            compliant.replace(
                "  release:\n",
                "  shadow-upload:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact@v7\n        with:\n          name: shadow\n          path: payload\n\n  release:\n",
            ),
        ),
        (
            "additional artifact-download job",
            compliant.replace(
                "  release:\n",
                "  shadow-download:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v8\n        with:\n          path: payload\n\n  release:\n",
            ),
        ),
        (
            "additional release-publication job",
            compliant.replace(
                "  release:\n",
                "  shadow-publication:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: softprops/action-gh-release@v3\n        with:\n          files: payload/*\n          body_path: body.md\n          generate_release_notes: false\n          prerelease: false\n\n  release:\n",
            ),
        ),
    ];

    let escaped = mutations
        .into_iter()
        .filter_map(|(name, mutation)| {
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation)
                .is_ok()
                .then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        escaped.is_empty(),
        "packaging job-level mutations escaped: {escaped:?}"
    );
}

#[test]
fn workflow_authority_contract_rejects_global_mapping_bypasses() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let compliant = round_eight_compliant_workflow(&workflow);
    enumerate_authoritative_sources(&wix, &cargo, &compliant)
        .expect("round-eight global authority baseline");

    let mutations = [
        (
            "workflow defaults shell",
            compliant.replace(
                "permissions:\n  contents: read",
                "defaults:\n  run:\n    shell: bash -e {0}\n\npermissions:\n  contents: read",
            ),
        ),
        (
            "global BASH_ENV",
            compliant.replace(
                "  CARGO_TERM_COLOR: always",
                "  BASH_ENV: payload/replace-verifier.sh\n  CARGO_TERM_COLOR: always",
            ),
        ),
        (
            "global contents write",
            compliant.replace("  contents: read", "  contents: write"),
        ),
        (
            "quoted global permissions key",
            compliant.replace(
                "permissions:\n  contents: read",
                "\"permissions\":\n  contents: write",
            ),
        ),
        (
            "duplicate global permissions",
            compliant.replace(
                "permissions:\n  contents: read",
                "permissions:\n  contents: read\n\npermissions:\n  contents: write",
            ),
        ),
        (
            "duplicate global env",
            compliant.replace(
                "jobs:\n",
                "env:\n  BASH_ENV: payload/replace-verifier.sh\n\njobs:\n",
            ),
        ),
        (
            "changed trigger authority",
            compliant.replace(
                "  workflow_dispatch:\n",
                "  workflow_dispatch:\n  repository_dispatch:\n",
            ),
        ),
        (
            "unsupported global concurrency",
            compliant.replace("jobs:\n", "concurrency: unsafe-release\n\njobs:\n"),
        ),
    ];
    let escaped = mutations
        .into_iter()
        .filter_map(|(name, mutation)| {
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation)
                .is_ok()
                .then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        escaped.is_empty(),
        "global workflow authority mutations escaped: {escaped:?}"
    );
}

#[test]
fn workflow_authority_contract_rejects_job_mapping_and_token_bypasses() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let compliant = round_eight_compliant_workflow(&workflow);
    enumerate_authoritative_sources(&wix, &cargo, &compliant)
        .expect("round-eight job authority baseline");

    let mutations = [
        (
            "check permissions after steps",
            compliant.replace(
                "\n  check-windows:\n",
                "\n    permissions:\n      contents: write\n\n  check-windows:\n",
            ),
        ),
        (
            "packaging defaults after steps",
            compliant.replace(
                "\n  build-linux:\n",
                "\n    defaults:\n      run:\n        shell: cmd\n\n  build-linux:\n",
            ),
        ),
        (
            "packaging BASH_ENV after steps",
            compliant.replace(
                "\n  build-arch:\n",
                "\n    env:\n      BASH_ENV: payload/replace-verifier.sh\n\n  build-arch:\n",
            ),
        ),
        (
            "duplicate runner after steps",
            compliant.replace(
                "\n  release:\n",
                "\n    runs-on: self-hosted\n\n  release:\n",
            ),
        ),
        (
            "quoted check permissions",
            compliant.replace(
                "  check:\n    name: Check\n",
                "  check:\n    name: Check\n    \"permissions\":\n      contents: write\n",
            ),
        ),
        (
            "check-windows contents write",
            compliant.replace(
                "  check-windows:\n    name: Check Windows native FFI and shutdown\n",
                "  check-windows:\n    name: Check Windows native FFI and shutdown\n    permissions:\n      contents: write\n",
            ),
        ),
        (
            "check gh api publication",
            insert_workflow_step_after(
                &compliant,
                "Run Tests",
                "name: Publish through GitHub CLI\n        run: gh api --method POST repos/${GITHUB_REPOSITORY}/releases",
            ),
        ),
        (
            "check-windows token script publication",
            insert_workflow_step_after(
                &compliant,
                "Test repeated Windows shutdown",
                "name: Publish with workflow token\n        env:\n          RELEASE_TOKEN: ${{ github.token }}\n        run: curl -H \"Authorization: Bearer $RELEASE_TOKEN\" https://api.github.com/repos/${GITHUB_REPOSITORY}/releases",
            ),
        ),
        (
            "additional quoted write and gh api job",
            compliant.replace(
                "  release:\n",
                "  shadow-release:\n    name: Shadow release\n    runs-on: ubuntu-latest\n    \"permissions\":\n      contents: write\n    steps:\n      - run: gh api --method POST repos/${GITHUB_REPOSITORY}/releases\n\n  release:\n",
            ),
        ),
        (
            "additional token-bearing REST job",
            compliant.replace(
                "  release:\n",
                "  shadow-rest:\n    name: Shadow REST release\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          RELEASE_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n        run: curl -H \"Authorization: Bearer $RELEASE_TOKEN\" https://api.github.com/repos/${GITHUB_REPOSITORY}/releases\n\n  release:\n",
            ),
        ),
        (
            "additional dependency on release",
            compliant.replace(
                "  release:\n",
                "  shadow-dependent:\n    name: Shadow dependent\n    needs: release\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo shadow\n\n  release:\n",
            ),
        ),
    ];
    let escaped = mutations
        .into_iter()
        .filter_map(|(name, mutation)| {
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation)
                .is_ok()
                .then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        escaped.is_empty(),
        "job workflow authority mutations escaped: {escaped:?}"
    );
}

#[test]
fn workflow_authority_contract_rejects_every_unconsumed_document_line() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let compliant = round_eight_compliant_workflow(&workflow);
    enumerate_authoritative_sources(&wix, &cargo, &compliant)
        .expect("round-eight complete-document baseline");

    let mutations = [
        ("top-level comment", format!("# hidden authority\n{compliant}")),
        (
            "comment hidden in action environment",
            compliant.replace(
                "          VCPKG_DEFAULT_TRIPLET: x64-windows-v3-static-md-release",
                "          # BASH_ENV: payload/replace-verifier.sh\n          VCPKG_DEFAULT_TRIPLET: x64-windows-v3-static-md-release",
            ),
        ),
        (
            "nested unconsumed action input",
            compliant.replace(
                "          path: target/wix/*.msi",
                "          path: target/wix/*.msi\n            hidden: payload/replace-verifier.sh",
            ),
        ),
        ("document start marker", format!("---\n{compliant}")),
        ("document end marker", format!("{compliant}\n...\n")),
        (
            "second YAML document",
            format!("{compliant}\n---\nname: shadow\n"),
        ),
        (
            "tab indentation",
            compliant.replace("  contents: read", "\tcontents: read"),
        ),
        (
            "malformed top indentation",
            compliant.replace("permissions:\n", " permissions:\n"),
        ),
        (
            "malformed job indentation",
            compliant.replace("    runs-on: windows-2022", "     runs-on: windows-2022"),
        ),
    ];
    let escaped = mutations
        .into_iter()
        .filter_map(|(name, mutation)| {
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation)
                .is_ok()
                .then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        escaped.is_empty(),
        "unconsumed workflow lines escaped: {escaped:?}"
    );
}

#[test]
fn workflow_digest_is_distinct_from_semantic_validation() {
    let (_, wix, cargo, workflow) = repository_inputs();
    let byte_only_change = format!("{workflow}\n");

    validate_workflow_semantics(&byte_only_change)
        .expect("a trailing blank line must remain semantically valid");
    assert_eq!(
        enumerate_authoritative_sources(&wix, &cargo, &byte_only_change).unwrap_err(),
        "release workflow declaration digest changed"
    );
}

#[test]
fn authoritative_ci_validates_the_immutable_workflow_object() {
    let (_, _, _, workspace) = repository_inputs();
    let malicious_commit = insert_workflow_step_after(
        &workspace.replace("persist-credentials: false", "persist-credentials: true"),
        "Verify Windows package outputs",
        "name: Mutate verified release\n        run: echo payload > release/renamed-runtime.exe",
    );
    let loaded = validate_authoritative_workflow_with_loader(
        &workspace,
        Some("true"),
        None,
        Some("ABCDEF0123456789ABCDEF0123456789ABCDEF01"),
        |sha| {
            assert_eq!(sha, "abcdef0123456789abcdef0123456789abcdef01");
            Ok(malicious_commit.into_bytes())
        },
    );

    assert_eq!(
        loaded.unwrap_err(),
        "release workflow declaration digest changed"
    );
}

#[test]
fn authoritative_identity_is_required_valid_and_workspace_bound() {
    let (_, _, _, workspace) = repository_inputs();
    let sha = "0123456789abcdef0123456789abcdef01234567";

    let safe = validate_authoritative_workflow_with_loader(
        &workspace,
        Some("true"),
        None,
        Some(sha),
        |actual| {
            assert_eq!(actual, sha);
            Ok(workspace.as_bytes().to_vec())
        },
    )
    .expect("matching immutable workflow");
    assert_eq!(safe.replace("\r\n", "\n"), workspace.replace("\r\n", "\n"));

    let changed_workspace = format!("{workspace}\n");
    assert_eq!(
        validate_authoritative_workflow_with_loader(
            &changed_workspace,
            Some("true"),
            None,
            Some(sha),
            |_| Ok(workspace.as_bytes().to_vec()),
        )
        .unwrap_err(),
        "workspace release workflow differs from commit object"
    );

    for invalid in [
        "",
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef012345678",
        "0123456789abcdef0123456789abcdef0123456g",
    ] {
        assert_eq!(
            validate_authoritative_workflow_with_loader(
                &workspace,
                Some("true"),
                None,
                Some(invalid),
                |_| Err("loader reached for invalid SHA"),
            )
            .unwrap_err(),
            "GITHUB_WORKFLOW_SHA must be 40 hexadecimal characters"
        );
    }
    assert_eq!(
        validate_authoritative_workflow_with_loader(&workspace, Some("true"), None, None, |_| Err(
            "loader reached without SHA"
        ),)
        .unwrap_err(),
        "GITHUB_WORKFLOW_SHA is required"
    );
    assert_eq!(
        validate_authoritative_workflow_with_loader(
            &workspace,
            None,
            Some("windows"),
            None,
            |_| Err("loader reached without SHA"),
        )
        .unwrap_err(),
        "GITHUB_WORKFLOW_SHA is required"
    );
    validate_authoritative_workflow_with_loader(&workspace, None, None, None, |_| {
        Err("local fixture attempted immutable loading")
    })
    .expect("local fixture bytes do not require CI identity");
}

#[test]
fn authoritative_commit_object_is_size_bounded() {
    let (_, _, _, workspace) = repository_inputs();
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let result = validate_authoritative_workflow_with_loader(
        &workspace,
        Some("true"),
        None,
        Some(sha),
        |_| Ok(vec![b'x'; 1024 * 1024 + 1]),
    );
    assert_eq!(
        result.unwrap_err(),
        "release workflow commit object exceeds size limit"
    );
    assert_eq!(
        validate_authoritative_workflow_with_loader(
            &workspace,
            Some("true"),
            None,
            Some(sha),
            |_| Ok(vec![0xff, 0xfe]),
        )
        .unwrap_err(),
        "release workflow commit object is not UTF-8"
    );
    for error in [
        "workflow Git tool unavailable",
        "workflow Git object command failed",
        "workflow Git object read failed",
        "workflow Git object command timed out",
    ] {
        assert_eq!(
            validate_authoritative_workflow_with_loader(
                &workspace,
                Some("true"),
                None,
                Some(sha),
                |_| Err(error),
            )
            .unwrap_err(),
            error
        );
    }
}

#[test]
fn workflow_object_command_is_bounded_timed_and_reaped() {
    let unavailable = &mut Command::new("stream-server-definitely-missing-git-tool");
    assert_eq!(
        run_bounded_workflow_command(unavailable, Duration::from_millis(100)).unwrap_err(),
        "workflow Git tool unavailable"
    );

    let (repository, _, _, _) = repository_inputs();
    let missing_object = &mut Command::new("git");
    missing_object.current_dir(&repository).args([
        "cat-file",
        "blob",
        "0000000000000000000000000000000000000000:.github/workflows/release.yml",
    ]);
    assert_eq!(
        run_bounded_workflow_command(missing_object, Duration::from_secs(2)).unwrap_err(),
        "workflow Git object command failed"
    );

    let blocked = &mut Command::new("git");
    blocked
        .current_dir(&repository)
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped());
    let started = Instant::now();
    assert_eq!(
        run_bounded_workflow_command(blocked, Duration::from_millis(100)).unwrap_err(),
        "workflow Git object command timed out"
    );
    assert!(started.elapsed() < Duration::from_secs(2));

    let temporary = tempfile::tempdir().expect("temporary Git object store");
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .arg(temporary.path())
            .status()
            .expect("initialize temporary Git object store")
            .success()
    );
    let oversized_path = temporary.path().join("oversized-workflow");
    fs::write(&oversized_path, vec![b'x'; 1024 * 1024 + 1]).expect("oversized object fixture");
    let hash = Command::new("git")
        .current_dir(temporary.path())
        .args(["hash-object", "-w", "oversized-workflow"])
        .output()
        .expect("hash oversized object");
    assert!(hash.status.success());
    let hash = std::str::from_utf8(&hash.stdout)
        .expect("object hash UTF-8")
        .trim();
    let oversized = &mut Command::new("git");
    oversized
        .current_dir(temporary.path())
        .args(["cat-file", "blob", hash]);
    assert_eq!(
        run_bounded_workflow_command(oversized, Duration::from_secs(2)).unwrap_err(),
        "release workflow commit object exceeds size limit"
    );
}

fn workflow_reader_cleanup_helper_command(ready: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("workflow test executable"));
    command
        .args([
            "--ignored",
            "--exact",
            "workflow_reader_cleanup_child_helper",
        ])
        .env("STREAM_SERVER_WORKFLOW_READER_READY", ready)
        .stdin(Stdio::null());
    command
}

fn wait_for_workflow_reader_helper(ready: &Path) -> std::net::SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(address) = fs::read_to_string(ready)
            && let Ok(address) = address.parse()
        {
            return address;
        }
        assert!(
            Instant::now() < deadline,
            "workflow reader cleanup helper did not become ready"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn workflow_reader_wait_ignores_partial_address_publication() {
    let temporary = tempfile::tempdir().expect("partial readiness fixture");
    let ready = temporary.path().join("ready");
    fs::write(&ready, "127.0.0.").expect("publish partial helper address");

    let completed_ready = ready.clone();
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        fs::write(completed_ready, "127.0.0.1:31415").expect("publish complete helper address");
    });

    assert_eq!(
        wait_for_workflow_reader_helper(&ready),
        "127.0.0.1:31415"
            .parse()
            .expect("expected helper listener address")
    );
    writer.join().expect("readiness writer must finish");
}

#[test]
fn reader_spawn_failure_kills_and_waits_for_the_owned_git_child() {
    let temporary = tempfile::tempdir().expect("reader spawn failure fixture");
    let ready = temporary.path().join("ready");
    let mut command = workflow_reader_cleanup_helper_command(&ready);
    let observed_ready = ready.clone();

    assert_eq!(
        run_bounded_workflow_command_with_reader(
            &mut command,
            Duration::from_secs(5),
            move |stdout, _sender| {
                wait_for_workflow_reader_helper(&observed_ready);
                drop(stdout);
                Err(std::io::Error::other("injected reader spawn failure"))
            },
        )
        .unwrap_err(),
        "workflow Git reader unavailable"
    );

    let address = wait_for_workflow_reader_helper(&ready);
    std::net::TcpListener::bind(address).expect("reader spawn failure must not leave child alive");
}

#[test]
fn reader_panic_is_a_read_failure_and_reaps_the_owned_git_child() {
    let temporary = tempfile::tempdir().expect("reader panic fixture");
    let ready = temporary.path().join("ready");
    let mut command = workflow_reader_cleanup_helper_command(&ready);
    let observed_ready = ready.clone();

    assert_eq!(
        run_bounded_workflow_command_with_reader(
            &mut command,
            Duration::from_secs(5),
            move |stdout, sender| {
                wait_for_workflow_reader_helper(&observed_ready);
                thread::Builder::new()
                    .name("injected-workflow-reader-panic".to_owned())
                    .spawn(move || {
                        drop(stdout);
                        drop(sender);
                        panic!("injected workflow reader panic");
                    })
            },
        )
        .unwrap_err(),
        "workflow Git object read failed"
    );

    let address = wait_for_workflow_reader_helper(&ready);
    std::net::TcpListener::bind(address).expect("reader panic must not leave child alive");
}

#[test]
#[ignore = "spawned only by workflow reader ownership fixtures"]
fn workflow_reader_cleanup_child_helper() {
    let Some(ready) = std::env::var_os("STREAM_SERVER_WORKFLOW_READER_READY") else {
        return;
    };
    let ready = PathBuf::from(ready);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind helper listener");
    fs::write(
        ready,
        listener
            .local_addr()
            .expect("helper listener address")
            .to_string(),
    )
    .expect("publish helper listener address");
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn git_workflow_loader_reads_the_fixed_commit_path() {
    let (_, _, _, workflow) = repository_inputs();
    let temporary = tempfile::tempdir().expect("temporary committed workflow repository");
    let workflow_path = temporary.path().join(".github/workflows/release.yml");
    fs::create_dir_all(workflow_path.parent().expect("workflow fixture parent"))
        .expect("create workflow fixture parent");
    fs::write(&workflow_path, workflow.as_bytes()).expect("write committed workflow fixture");
    for args in [
        vec!["init", "--quiet"],
        vec!["add", ".github/workflows/release.yml"],
        vec![
            "-c",
            "user.name=Workflow Fixture",
            "-c",
            "user.email=workflow@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
    ] {
        assert!(
            Command::new("git")
                .current_dir(temporary.path())
                .args(args)
                .status()
                .expect("prepare committed workflow fixture")
                .success()
        );
    }
    let head = Command::new("git")
        .current_dir(temporary.path())
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("resolve workflow fixture HEAD");
    assert!(head.status.success());
    let head = std::str::from_utf8(&head.stdout)
        .expect("fixture HEAD UTF-8")
        .trim();

    let committed = load_git_workflow_object(temporary.path(), head)
        .expect("load fixed committed workflow path");
    assert_eq!(
        String::from_utf8(committed)
            .expect("committed workflow UTF-8")
            .replace("\r\n", "\n"),
        workflow.replace("\r\n", "\n")
    );
}

#[test]
fn authoritative_jobs_fetch_the_workflow_identity_object() {
    let (_, _, _, workflow) = repository_inputs();
    let parsed = workflow_steps(&workflow).expect("parse authoritative workflow checkout policy");
    for job in [
        "check",
        "build-windows",
        "build-linux",
        "build-arch",
        "release",
    ] {
        let checkout = parsed
            .steps
            .iter()
            .find(|step| step.job == job && step.ordinal == 0)
            .expect("authoritative job checkout");
        assert_eq!(
            checkout.inputs.get("fetch-depth"),
            Some(&vec!["0".to_owned()]),
            "{job} must fetch the GITHUB_WORKFLOW_SHA object"
        );
    }
    let embed_only_checkout = parsed
        .steps
        .iter()
        .find(|step| step.job == "check-windows" && step.ordinal == 0)
        .expect("embed-only Windows checkout");
    assert!(!embed_only_checkout.inputs.contains_key("fetch-depth"));
}

#[test]
fn check_jobs_require_exact_ordered_steps_and_values() {
    let (_, _, _, workflow) = repository_inputs();
    let replace_nth = |source: &str, pattern: &str, replacement: &str, occurrence: usize| {
        let start = source
            .match_indices(pattern)
            .nth(occurrence)
            .map(|(index, _)| index)
            .expect("workflow mutation target");
        let mut mutated = source.to_owned();
        mutated.replace_range(start..start + pattern.len(), replacement);
        mutated
    };
    let mutations = [
        (
            "check bracket PAT release",
            insert_workflow_step_after(
                &workflow,
                "Run Tests",
                "name: Publish with bracket PAT\n        run: gh release create unsafe --repo ${{ secrets['RELEASE_PAT'] }}",
            ),
            "packaging workflow step count changed",
        ),
        (
            "check split API host",
            insert_workflow_step_after(
                &workflow,
                "Run Tests",
                "name: Publish through split host\n        run: host=api.github; host=$host.com; curl https://$host/repos/$GITHUB_REPOSITORY/releases",
            ),
            "packaging workflow step count changed",
        ),
        (
            "check cache release paths",
            workflow.replacen(
                "          path: target",
                "          path: |\n            target\n            .git\n            release",
                1,
            ),
            "packaging workflow action contract changed",
        ),
        (
            "check changed toolchain input",
            workflow.replacen("          components: clippy", "          components: rustfmt", 1),
            "packaging workflow action contract changed",
        ),
        (
            "check extra run",
            insert_workflow_step_after(
                &workflow,
                "Run Tests",
                "name: Extra check command\n        run: echo extra",
            ),
            "packaging workflow step count changed",
        ),
        (
            "check duplicate checkout",
            workflow.replacen(
                "      - uses: actions/checkout@v7",
                "      - uses: actions/checkout@v7\n\n      - name: Duplicate checkout\n        uses: actions/checkout@v7",
                1,
            ),
            "packaging workflow step count changed",
        ),
        (
            "check-windows bracket PAT release",
            insert_workflow_step_after(
                &workflow,
                "Test repeated Windows shutdown",
                "name: Publish with bracket PAT\n        run: gh release create unsafe --repo ${{ secrets['RELEASE_PAT'] }}",
            ),
            "packaging workflow step count changed",
        ),
        (
            "check-windows split API host",
            insert_workflow_step_after(
                &workflow,
                "Test repeated Windows shutdown",
                "name: Publish through split host\n        run: $host = 'api.github' + '.com'; curl https://$host/repos/$env:GITHUB_REPOSITORY/releases",
            ),
            "packaging workflow step count changed",
        ),
        (
            "check-windows dangerous cache",
            insert_workflow_step_after(
                &workflow,
                "Setup Rust",
                "name: Cache release authority\n        uses: actions/cache@v6\n        with:\n          path: |\n            .git\n            release\n          key: unsafe-release",
            ),
            "packaging workflow step count changed",
        ),
        (
            "check-windows changed toolchain input",
            replace_nth(
                &workflow,
                "          components: clippy",
                "          components: rustfmt",
                1,
            ),
            "packaging workflow action contract changed",
        ),
        (
            "check-windows extra run",
            insert_workflow_step_after(
                &workflow,
                "Test repeated Windows shutdown",
                "name: Extra Windows check command\n        run: echo extra",
            ),
            "packaging workflow step count changed",
        ),
        (
            "check-windows duplicate checkout",
            replace_nth(
                &workflow,
                "      - uses: actions/checkout@v7",
                "      - uses: actions/checkout@v7\n\n      - name: Duplicate checkout\n        uses: actions/checkout@v7",
                1,
            ),
            "packaging workflow step count changed",
        ),
    ];

    let escaped = mutations
        .into_iter()
        .filter_map(|(name, mutation, expected)| {
            let result = validate_workflow_semantics(&mutation).map(|_| ());
            match result {
                Err(actual) if actual == expected => None,
                Err(actual) => Some(format!("{name}: expected {expected:?}, got {actual:?}")),
                Ok(()) => Some(format!("{name}: escaped semantic validation")),
            }
        })
        .collect::<Vec<_>>();
    assert!(
        escaped.is_empty(),
        "check-job semantic mutations escaped: {escaped:?}"
    );
}

#[test]
fn structural_contract_rejects_absent_renamed_payload_declarations() {
    let (_, wix, cargo, workflow) = repository_inputs();
    for absent in ["payload/renamed-codec.exe", "payload/renamed-codec.zip"] {
        let member = Path::new(absent)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("absent payload member");
        let mutation = workflow
            .replacen(
                "target/x86_64-pc-windows-msvc/release/server.exe",
                absent,
                1,
            )
            .replacen(
                "artifacts/server-windows-amd64/server.exe",
                &format!("artifacts/server-windows-amd64/{member}"),
                1,
            );
        assert!(
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutation).is_err(),
            "absent renamed payload was treated as structurally safe"
        );
    }
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
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutated).is_err(),
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
            candidate_tree_is_safe(repository.path(), &path).is_err(),
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
        assert!(
            enumerate_authoritative_sources_semantically(&wix, &cargo, &mutated).is_err(),
            "structural contract admitted renamed payload {name}"
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
    assert!(
        enumerate_authoritative_sources_semantically(&wix, &cargo, &directory_workflow).is_err(),
        "declared directory was accepted by the exact structural contract"
    );
    assert!(!forbidden_runtime_payload(
        Path::new("repository"),
        Path::new("repository/target/x86_64-pc-windows-msvc/release/server.exe"),
        b"MZapplication"
    ));
    assert!(!forbidden_runtime_payload(
        Path::new("repository"),
        Path::new("repository/vendor/native/ffmpeg_api_source.cpp"),
        b"source only"
    ));
}

#[test]
fn generated_tree_scans_reject_nested_application_path_suffix_spoofs() {
    for tree in ["AppDir", "pkg", "artifacts", "release"] {
        let repository = tempfile::tempdir().expect("nested PE suffix fixture");
        let spoof = repository
            .path()
            .join(tree)
            .join("nested/target/x86_64-pc-windows-msvc/release/server.exe");
        fs::create_dir_all(spoof.parent().expect("spoof parent"))
            .expect("create nested PE suffix path");
        fs::write(&spoof, b"MZnested suffix spoof").expect("write nested PE suffix spoof");
        assert!(
            candidate_tree_is_safe(repository.path(), &repository.path().join(tree)).is_err(),
            "{tree} accepted a PE whose suffix mimics an allowed application path"
        );
    }
}
