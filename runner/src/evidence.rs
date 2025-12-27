use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const EVIDENCE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Deserialize)]
pub struct EvidenceManifest {
    pub schema_version: u32,
    pub app_bundle_id: Option<String>,
    pub app_binary_rel_path: Option<String>,
    pub app_entitlements: Option<Value>,
    pub entries: Vec<EvidenceEntry>,
    pub notes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EvidenceEntry {
    pub id: String,
    pub kind: String,
    pub bundle_id: Option<String>,
    pub rel_path: String,
    pub sha256: Option<String>,
    pub lc_uuid: Option<String>,
    pub entitlements: Option<Value>,
    pub entitlements_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub checked: usize,
    pub mismatches: Vec<VerifyMismatch>,
    pub manifest_path: String,
    pub schema_version: u32,
    pub notes: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct VerifyMismatch {
    pub id: String,
    pub rel_path: String,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
    pub error: Option<String>,
}

pub fn load_manifest(path: &Path) -> Result<EvidenceManifest, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read manifest {}: {e}", path.display()))?;
    let manifest: EvidenceManifest = serde_json::from_str(&data)
        .map_err(|e| format!("failed to parse manifest {}: {e}", path.display()))?;
    if manifest.schema_version != EVIDENCE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported evidence manifest schema_version {} (expected {}) in {}",
            manifest.schema_version,
            EVIDENCE_SCHEMA_VERSION,
            path.display()
        ));
    }
    Ok(manifest)
}

pub fn sha256_hex(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    Ok(out)
}

pub fn verify_manifest(manifest: &EvidenceManifest, app_root: &Path, manifest_path: &Path) -> VerifyReport {
    let mut mismatches = Vec::new();
    let mut checked = 0usize;

    for entry in &manifest.entries {
        let expected = entry.sha256.clone();
        if expected.is_none() {
            continue;
        }
        checked += 1;
        let abs = app_root.join(&entry.rel_path);
        if !abs.exists() {
            mismatches.push(VerifyMismatch {
                id: entry.id.clone(),
                rel_path: entry.rel_path.clone(),
                expected_sha256: expected,
                actual_sha256: None,
                error: Some("missing file".to_string()),
            });
            continue;
        }
        let actual = match sha256_hex(&abs) {
            Ok(v) => v,
            Err(e) => {
                mismatches.push(VerifyMismatch {
                    id: entry.id.clone(),
                    rel_path: entry.rel_path.clone(),
                    expected_sha256: expected,
                    actual_sha256: None,
                    error: Some(e),
                });
                continue;
            }
        };
        if expected.as_deref() != Some(actual.as_str()) {
            mismatches.push(VerifyMismatch {
                id: entry.id.clone(),
                rel_path: entry.rel_path.clone(),
                expected_sha256: expected,
                actual_sha256: Some(actual),
                error: None,
            });
        }
    }

    VerifyReport {
        ok: mismatches.is_empty(),
        checked,
        mismatches,
        manifest_path: manifest_path.display().to_string(),
        schema_version: manifest.schema_version,
        notes: manifest.notes.clone(),
    }
}

pub fn find_entry_by_id<'a>(manifest: &'a EvidenceManifest, selector: &str) -> Option<&'a EvidenceEntry> {
    manifest.entries.iter().find(|entry| {
        entry.id == selector || entry.bundle_id.as_deref() == Some(selector)
    })
}

pub fn find_entry_by_rel_path<'a>(
    manifest: &'a EvidenceManifest,
    rel_path: &str,
) -> Option<&'a EvidenceEntry> {
    manifest.entries.iter().find(|entry| entry.rel_path == rel_path)
}

pub fn rel_path_from_absolute(app_root: &Path, abs: &Path) -> Option<String> {
    abs.strip_prefix(app_root)
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

pub fn app_root_from_exe(exe: &Path) -> Result<PathBuf, String> {
    let contents_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| format!("unexpected executable location: {}", exe.display()))?;
    let app_root = contents_dir
        .parent()
        .ok_or_else(|| format!("unexpected app bundle location: {}", exe.display()))?;
    Ok(app_root.to_path_buf())
}

pub fn manifest_path_from_app_root(app_root: &Path) -> PathBuf {
    app_root.join("Contents").join("Resources").join("Evidence").join("manifest.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let base = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        base.join(format!("ej-evidence-test-{}", stamp))
    }

    #[test]
    fn parses_manifest() {
        let manifest = r#"{
  "schema_version": 2,
  "app_bundle_id": "com.example.app",
  "app_binary_rel_path": "Contents/MacOS/entitlement-jail",
  "app_entitlements": {"com.apple.security.app-sandbox": true},
  "entries": [
    {
      "id": "com.example.service",
      "kind": "xpc-service",
      "bundle_id": "com.example.service",
      "rel_path": "Contents/XPCServices/Service.xpc/Contents/MacOS/Service",
      "sha256": "deadbeef",
      "lc_uuid": "uuid",
      "entitlements": {"com.apple.security.app-sandbox": true}
    }
  ],
  "notes": ["ok"]
}"#;
        let parsed: EvidenceManifest = serde_json::from_str(manifest).unwrap();
        assert_eq!(parsed.schema_version, 2);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].id, "com.example.service");
    }

    #[test]
    fn verifies_hashes() {
        let root = temp_dir();
        let target = root.join("Contents").join("MacOS");
        fs::create_dir_all(&target).unwrap();
        let file_path = target.join("tool");
        fs::write(&file_path, b"hello").unwrap();
        let hash = sha256_hex(&file_path).unwrap();

        let manifest = EvidenceManifest {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            app_bundle_id: None,
            app_binary_rel_path: None,
            app_entitlements: None,
            entries: vec![EvidenceEntry {
                id: "tool".to_string(),
                kind: "helper".to_string(),
                bundle_id: None,
                rel_path: "Contents/MacOS/tool".to_string(),
                sha256: Some(hash),
                lc_uuid: None,
                entitlements: None,
                entitlements_error: None,
            }],
            notes: None,
        };

        let report = verify_manifest(&manifest, &root, &PathBuf::from("manifest.json"));
        assert!(report.ok);
        assert_eq!(report.checked, 1);
        assert!(report.mismatches.is_empty());
    }

    #[test]
    fn reports_mismatch() {
        let root = temp_dir();
        let target = root.join("Contents").join("MacOS");
        fs::create_dir_all(&target).unwrap();
        let file_path = target.join("tool");
        fs::write(&file_path, b"hello").unwrap();

        let manifest = EvidenceManifest {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            app_bundle_id: None,
            app_binary_rel_path: None,
            app_entitlements: None,
            entries: vec![EvidenceEntry {
                id: "tool".to_string(),
                kind: "helper".to_string(),
                bundle_id: None,
                rel_path: "Contents/MacOS/tool".to_string(),
                sha256: Some("deadbeef".to_string()),
                lc_uuid: None,
                entitlements: None,
                entitlements_error: None,
            }],
            notes: None,
        };

        let report = verify_manifest(&manifest, &root, &PathBuf::from("manifest.json"));
        assert!(!report.ok);
        assert_eq!(report.checked, 1);
        assert_eq!(report.mismatches.len(), 1);
    }

    #[test]
    fn finds_entry_by_id() {
        let manifest = EvidenceManifest {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            app_bundle_id: None,
            app_binary_rel_path: None,
            app_entitlements: None,
            entries: vec![EvidenceEntry {
                id: "com.example.service".to_string(),
                kind: "xpc-service".to_string(),
                bundle_id: Some("com.example.service".to_string()),
                rel_path: "Contents/XPCServices/Service.xpc/Contents/MacOS/Service".to_string(),
                sha256: Some("deadbeef".to_string()),
                lc_uuid: None,
                entitlements: None,
                entitlements_error: None,
            }],
            notes: None,
        };

        assert!(find_entry_by_id(&manifest, "com.example.service").is_some());
    }

    #[derive(Debug, Deserialize)]
    struct SymbolsManifest {
        entries: Vec<SymbolsEntry>,
    }

    #[derive(Debug, Deserialize)]
    struct SymbolsEntry {
        id: String,
        symbols: Vec<String>,
    }

    #[test]
    fn parses_symbols_manifest() {
        let symbols = r#"{
  "generated_at": "2025-01-01T00:00:00Z",
  "entries": [
    {
      "id": "com.example.service",
      "symbols": ["ej_probe_fs_op"]
    }
  ]
}"#;
        let parsed: SymbolsManifest = serde_json::from_str(symbols).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].id, "com.example.service");
        assert!(parsed.entries[0].symbols.contains(&"ej_probe_fs_op".to_string()));
    }
}
