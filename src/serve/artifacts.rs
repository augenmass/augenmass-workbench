//! Local opt-in artifact export for `augenmass serve`.
//!
//! The public trace API stays redacted. This module writes sensitive replay
//! material only when the operator explicitly enables `--unsafe-debug-artifacts`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DebugArtifact {
    pub label: String,
    pub filename: String,
    pub path: String,
    pub len: usize,
    pub sha256: String,
}

impl DebugArtifact {
    pub(crate) fn trace_detail(&self) -> Value {
        json!({
            "artifact": {
                "label": &self.label,
                "filename": &self.filename,
                "len": self.len,
                "sha256": &self.sha256,
            },
            "unsafeDebugArtifacts": true,
            "pathRedacted": true,
            "redacted": true,
            "redaction": "trace exposes only the artifact filename, label, length, and hash; full local paths and file contents remain local"
        })
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn prepare_root(root: &Path) -> Result<()> {
    fs::create_dir_all(root)
        .with_context(|| format!("create unsafe debug artifact root {}", root.display()))?;
    tighten_dir_permissions(root)
}

pub(crate) fn write_json(
    root: &Path,
    session: Uuid,
    filename: &str,
    label: &str,
    value: &Value,
) -> Result<DebugArtifact> {
    let data = serde_json::to_string_pretty(value)? + "\n";
    write_text(root, session, filename, label, &data)
}

pub(crate) fn write_text(
    root: &Path,
    session: Uuid,
    filename: &str,
    label: &str,
    text: &str,
) -> Result<DebugArtifact> {
    write_bytes(root, session, filename, label, text.as_bytes())
}

fn write_bytes(
    root: &Path,
    session: Uuid,
    filename: &str,
    label: &str,
    data: &[u8],
) -> Result<DebugArtifact> {
    if filename.contains('/') || filename.contains('\\') {
        bail!("unsafe debug artifact filename must be a plain filename");
    }
    let dir = root.join(session.to_string());
    fs::create_dir_all(&dir)
        .with_context(|| format!("create unsafe debug session dir {}", dir.display()))?;
    tighten_dir_permissions(&dir)?;

    let actual_filename = unique_artifact_filename(&dir, filename);
    let path = dir.join(&actual_filename);
    fs::write(&path, data)
        .with_context(|| format!("write unsafe debug artifact {}", path.display()))?;
    tighten_file_permissions(&path)?;

    let artifact = DebugArtifact {
        label: label.to_string(),
        filename: actual_filename,
        path: display_path(&path),
        len: data.len(),
        sha256: sha256_hex(data),
    };
    update_manifest(&dir, session, &artifact)?;
    Ok(artifact)
}

fn unique_artifact_filename(dir: &Path, filename: &str) -> String {
    let first = dir.join(filename);
    if !first.exists() {
        return filename.to_string();
    }

    let path = Path::new(filename);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(filename);
    let ext = path.extension().and_then(|value| value.to_str());
    for idx in 2.. {
        let candidate = match ext {
            Some(ext) => format!("{stem}-{idx}.{ext}"),
            None => format!("{stem}-{idx}"),
        };
        if !dir.join(&candidate).exists() {
            return candidate;
        }
    }
    unreachable!("unbounded duplicate artifact filename search should always return")
}

fn update_manifest(dir: &Path, session: Uuid, artifact: &DebugArtifact) -> Result<()> {
    let manifest_path = dir.join("debug-manifest.json");
    let existing = if manifest_path.exists() {
        let text = fs::read_to_string(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?;
        serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };
    let mut entries = existing
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    entries.retain(
        |entry| match entry.get("filename").and_then(Value::as_str) {
            Some(name) => name != artifact.filename,
            None => true,
        },
    );
    entries.push(json!(artifact));
    let manifest = json!({
        "schemaVersion": 1,
        "tool": {
            "name": "augenmass",
            "version": env!("CARGO_PKG_VERSION"),
            "command": "serve --unsafe-debug-artifacts",
        },
        "kind": "serve-unsafe-debug-artifacts",
        "session": session.to_string(),
        "sessionDir": display_path(dir),
        "sensitive": true,
        "entries": entries,
        "caveats": [
            "contains verifier session private encryption key material",
            "contains raw wallet direct_post and decrypted authorization-response material when available",
            debug_artifact_permission_caveat(),
            "this file is written only when --unsafe-debug-artifacts is explicitly enabled"
        ]
    });
    let data = serde_json::to_string_pretty(&manifest)? + "\n";
    fs::write(&manifest_path, data)
        .with_context(|| format!("write {}", manifest_path.display()))?;
    tighten_file_permissions(&manifest_path)?;
    Ok(())
}

fn display_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| PathBuf::from(path))
        .display()
        .to_string()
}

#[cfg(unix)]
fn debug_artifact_permission_caveat() -> &'static str {
    "local filesystem permissions are tightened to owner-only mode on Unix (directories 0700, files 0600)"
}

#[cfg(not(unix))]
fn debug_artifact_permission_caveat() -> &'static str {
    "owner-only filesystem permissions are not enforced by this build; store artifacts in a private or encrypted workspace"
}

#[cfg(unix)]
fn tighten_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn tighten_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn tighten_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn tighten_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_trace_detail_redacts_paths_and_contents() {
        let root = std::env::temp_dir().join(format!("augenmass-artifacts-{}", Uuid::new_v4()));
        prepare_root(&root).expect("prepare root");
        let session = Uuid::new_v4();
        let artifact = write_text(&root, session, "body.txt", "raw body", "secret-value")
            .expect("write artifact");
        let detail = artifact.trace_detail();
        assert_eq!(detail["artifact"]["filename"], "body.txt");
        assert_eq!(detail["artifact"]["len"], 12);
        assert!(detail.to_string().contains(&sha256_hex(b"secret-value")));
        assert!(!detail.to_string().contains("secret-value"));
        assert!(!detail.to_string().contains(&root.display().to_string()));

        let dir = root.join(session.to_string());
        let manifest: Value = serde_json::from_str(
            &fs::read_to_string(dir.join("debug-manifest.json")).expect("read manifest"),
        )
        .expect("manifest json");
        assert_eq!(manifest["sensitive"], true);
        assert!(manifest["caveats"]
            .as_array()
            .expect("manifest caveats")
            .iter()
            .any(|caveat| caveat.as_str() == Some(debug_artifact_permission_caveat())));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            let file_mode = fs::metadata(dir.join("body.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn duplicate_artifact_writes_preserve_first_capture() {
        let root = std::env::temp_dir().join(format!("augenmass-artifacts-{}", Uuid::new_v4()));
        prepare_root(&root).expect("prepare root");
        let session = Uuid::new_v4();

        let first = write_text(&root, session, "direct-post.body", "raw body", "first-body")
            .expect("write first artifact");
        let second = write_text(
            &root,
            session,
            "direct-post.body",
            "raw body",
            "second-body",
        )
        .expect("write duplicate artifact");

        assert_eq!(first.filename, "direct-post.body");
        assert_eq!(second.filename, "direct-post-2.body");
        let dir = root.join(session.to_string());
        assert_eq!(
            fs::read_to_string(dir.join("direct-post.body")).expect("first body"),
            "first-body"
        );
        assert_eq!(
            fs::read_to_string(dir.join("direct-post-2.body")).expect("second body"),
            "second-body"
        );

        let manifest: Value = serde_json::from_str(
            &fs::read_to_string(dir.join("debug-manifest.json")).expect("read manifest"),
        )
        .expect("manifest json");
        let filenames = manifest["entries"]
            .as_array()
            .expect("manifest entries")
            .iter()
            .filter_map(|entry| entry["filename"].as_str())
            .collect::<Vec<_>>();
        assert!(filenames.contains(&"direct-post.body"));
        assert!(filenames.contains(&"direct-post-2.body"));

        let _ = fs::remove_dir_all(root);
    }
}
