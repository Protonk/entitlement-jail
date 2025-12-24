use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct ProfilesManifest {
    pub generated_at: Option<String>,
    pub profiles: Vec<ProfileEntry>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProfileEntry {
    pub profile_id: String,
    pub bundle_id: String,
    pub service_name: String,
    pub kind: String,
    pub label: Option<String>,
    pub tags: Option<Vec<String>>,
    pub risk_tier: Option<u8>,
    pub risk_reasons: Option<Vec<String>>,
    pub entitlements: Option<Value>,
    pub entitlements_error: Option<String>,
}

pub fn load_profiles(path: &Path) -> Result<ProfilesManifest, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read profiles {}: {e}", path.display()))?;
    serde_json::from_str(&data)
        .map_err(|e| format!("failed to parse profiles {}: {e}", path.display()))
}

pub fn profiles_path_from_app_root(app_root: &Path) -> PathBuf {
    app_root
        .join("Contents")
        .join("Resources")
        .join("Evidence")
        .join("profiles.json")
}

pub fn find_profile<'a>(
    manifest: &'a ProfilesManifest,
    selector: &str,
) -> Option<&'a ProfileEntry> {
    manifest.profiles.iter().find(|profile| {
        profile.profile_id == selector
            || profile.bundle_id == selector
            || profile.service_name == selector
    })
}

pub fn filter_profiles<'a>(
    manifest: &'a ProfilesManifest,
    kind: Option<&str>,
) -> Vec<&'a ProfileEntry> {
    manifest
        .profiles
        .iter()
        .filter(|profile| match kind {
            Some(kind) => profile.kind == kind,
            None => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profiles_manifest() {
        let data = r#"{
  "generated_at": "2025-01-01T00:00:00Z",
  "profiles": [
    {
      "profile_id": "minimal",
      "bundle_id": "com.example.ProbeService_minimal",
      "service_name": "ProbeService_minimal",
      "kind": "probe",
      "label": "minimal",
      "tags": ["probe", "baseline"],
      "entitlements": {"com.apple.security.app-sandbox": true}
    }
  ]
}"#;
        let parsed: ProfilesManifest = serde_json::from_str(data).unwrap();
        assert_eq!(parsed.profiles.len(), 1);
        assert_eq!(parsed.profiles[0].profile_id, "minimal");
        assert_eq!(parsed.profiles[0].kind, "probe");
    }

    #[test]
    fn finds_profile_by_selector() {
        let manifest = ProfilesManifest {
            generated_at: None,
            profiles: vec![ProfileEntry {
                profile_id: "minimal".to_string(),
                bundle_id: "com.example.ProbeService_minimal".to_string(),
                service_name: "ProbeService_minimal".to_string(),
                kind: "probe".to_string(),
                label: None,
                tags: None,
                risk_tier: None,
                risk_reasons: None,
                entitlements: None,
                entitlements_error: None,
            }],
        };

        assert!(find_profile(&manifest, "minimal").is_some());
        assert!(find_profile(&manifest, "com.example.ProbeService_minimal").is_some());
        assert!(find_profile(&manifest, "ProbeService_minimal").is_some());
    }

    #[test]
    fn parses_risk_fields() {
        let data = r#"{
  "profiles": [
    {
      "profile_id": "fully_injectable",
      "bundle_id": "com.example.ProbeService_fully_injectable",
      "service_name": "ProbeService_fully_injectable",
      "kind": "probe",
      "risk_tier": 2,
      "risk_reasons": ["allow_jit", "allow_unsigned_exec_mem"],
      "entitlements": {}
    }
  ]
}"#;
        let parsed: ProfilesManifest = serde_json::from_str(data).unwrap();
        let entry = &parsed.profiles[0];
        assert_eq!(entry.risk_tier, Some(2));
        assert!(entry
            .risk_reasons
            .as_ref()
            .unwrap()
            .contains(&"allow_jit".to_string()));
    }
}
