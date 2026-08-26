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
    fields: BTreeSet<String>,
    inputs: BTreeMap<String, Vec<String>>,
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
            .is_some_and(|value| matches!(value, '&' | '*' | '!' | '{' | '[' | '>'))
        || matches!(value, "|" | "|-")
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
        "actions/checkout@v7" => Some(&["fetch-depth"]),
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

fn workflow_steps(workflow: &str) -> Result<Vec<WorkflowStep>, &'static str> {
    if workflow.lines().any(|line| line.trim() == "---") {
        return Err("multiple workflow documents are not accepted");
    }
    let lines = workflow.lines().collect::<Vec<_>>();
    let jobs = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (line.trim() == "jobs:").then_some((index, *line)))
        .collect::<Vec<_>>();
    if jobs.len() != 1 || yaml_indent(jobs[0].1)? != 0 {
        return Err("workflow must contain one top-level jobs mapping");
    }
    let jobs_start = jobs[0].0;
    let job_indent = lines[jobs_start + 1..]
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| yaml_indent(line))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|indent| *indent > 0)
        .min()
        .ok_or("workflow jobs mapping is empty")?;
    let mut steps = Vec::new();
    let mut job_start = jobs_start + 1;
    while job_start < lines.len() {
        if lines[job_start].trim().is_empty() || yaml_indent(lines[job_start])? != job_indent {
            job_start += 1;
            continue;
        }
        let job = lines[job_start]
            .trim()
            .strip_suffix(':')
            .filter(|job| !job.is_empty())
            .ok_or("malformed workflow job mapping")?
            .to_owned();
        let mut job_end = job_start + 1;
        while job_end < lines.len() {
            let indent = yaml_indent(lines[job_end])?;
            if !lines[job_end].trim().is_empty() && indent <= job_indent {
                break;
            }
            job_end += 1;
        }
        let step_mappings = (job_start + 1..job_end)
            .filter(|index| lines[*index].trim() == "steps:")
            .collect::<Vec<_>>();
        if step_mappings.len() != 1 {
            return Err("workflow job must contain one steps sequence");
        }
        let steps_mapping = step_mappings[0];
        let steps_indent = yaml_indent(lines[steps_mapping])?;
        let mut sequence_end = steps_mapping + 1;
        while sequence_end < job_end {
            let indent = yaml_indent(lines[sequence_end])?;
            if !lines[sequence_end].trim().is_empty() && indent <= steps_indent {
                break;
            }
            sequence_end += 1;
        }
        let list_indent = lines[steps_mapping + 1..sequence_end]
            .iter()
            .filter(|line| !line.trim().is_empty())
            .map(|line| yaml_indent(line))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .min()
            .ok_or("workflow steps sequence is empty")?;
        let mut cursor = steps_mapping + 1;
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
                        let value = if matches!(value, "|" | "|-") {
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
                            if yaml_indent(lines[child])? == child_indent {
                                let (input, value) = yaml_field(lines[child].trim())
                                    .ok_or("unsupported workflow action input shape")?;
                                let values = if matches!(value, "|" | "|-") {
                                    block_value(
                                        &lines,
                                        child,
                                        yaml_indent(lines[child])?,
                                        with_end,
                                    )?
                                    .0
                                    .lines()
                                    .map(str::trim)
                                    .filter(|line| !line.is_empty())
                                    .map(yaml_scalar)
                                    .collect::<Result<Vec<_>, _>>()?
                                } else {
                                    vec![yaml_scalar(value)?]
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
                            }
                            child += 1;
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
                            if trimmed.is_empty() || trimmed.starts_with('#') {
                                continue;
                            }
                            let (variable, value) = yaml_field(trimmed)
                                .ok_or("unsupported workflow environment shape")?;
                            if !variables.insert(variable) {
                                return Err("duplicate workflow environment key");
                            }
                            yaml_scalar(value)?;
                        }
                    }
                    "id" | "if" => {
                        yaml_scalar(value)?;
                    }
                    _ => unreachable!("workflow step field allowlist checked"),
                }
            }
            validate_workflow_step_shape(&step)?;
            steps.push(step);
        }
        job_start = job_end;
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
        if completion >= gate {
            return Err("package verifier does not follow package creation");
        }
        for upload in steps.iter().filter(|step| {
            step.job == job && step.uses.as_deref() == Some("actions/upload-artifact@v7")
        }) {
            require_step_fields(upload, &["name", "uses", "with"])?;
            require_action_inputs(upload, &["name", "path"])?;
            if upload.ordinal <= *gate {
                return Err("package upload does not follow its verifier");
            }
        }
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
    if !(download.ordinal < classified.assembly_ordinal
        && classified.assembly_ordinal < release_gate
        && release_gate < publication.ordinal)
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
    let wix = wix_sources(wix)?;
    let deb = cargo_deb_sources(cargo)?;
    let steps = workflow_steps(workflow)?;
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
    let workflow = read_authoritative_release_workflow(&repository.join(".github/workflows"))
        .expect("read closed authoritative release workflow set");
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
        assert!(enumerate_authoritative_sources(&wix, &cargo, &mutated).is_err());
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
            enumerate_authoritative_sources(&wix, &cargo, &mutation).is_err(),
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
            enumerate_authoritative_sources(&wix, &cargo, &mutation)
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
    assert!(
        mutations
            .into_iter()
            .all(|mutation| { enumerate_authoritative_sources(&wix, &cargo, &mutation).is_err() })
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
            enumerate_authoritative_sources(&wix, &cargo, &mutation).is_err(),
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
            enumerate_authoritative_sources(&wix, &cargo, &mutated).is_err(),
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
        enumerate_authoritative_sources(&wix, &cargo, &directory_workflow).is_err(),
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
