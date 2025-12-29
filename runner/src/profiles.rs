use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct ProfilesManifest {
    pub generated_at: Option<String>,
    pub profiles: Vec<ProfileEntry>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProfileVariant {
    pub variant: String,
    pub bundle_id: String,
    pub service_name: String,
    pub tags: Option<Vec<String>>,
    pub risk_tier: Option<u8>,
    pub risk_reasons: Option<Vec<String>>,
    pub entitlements: Option<Value>,
    pub entitlements_error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProfileEntry {
    pub profile_id: String,
    pub kind: String,
    pub label: Option<String>,
    pub variants: Vec<ProfileVariant>,
}

#[derive(Debug, Clone)]
pub struct ResolvedProfileVariant<'a> {
    pub profile: &'a ProfileEntry,
    pub variant: &'a ProfileVariant,
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

pub fn find_profile_by_id<'a>(manifest: &'a ProfilesManifest, selector: &str) -> Option<&'a ProfileEntry> {
    manifest
        .profiles
        .iter()
        .find(|profile| profile.profile_id == selector)
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

pub fn find_variant<'a>(profile: &'a ProfileEntry, variant: &str) -> Option<&'a ProfileVariant> {
    profile.variants.iter().find(|entry| entry.variant == variant)
}

pub fn find_variant_by_bundle_id<'a>(
    manifest: &'a ProfilesManifest,
    bundle_id: &str,
) -> Option<ResolvedProfileVariant<'a>> {
    for profile in &manifest.profiles {
        for variant in &profile.variants {
            if variant.bundle_id == bundle_id {
                return Some(ResolvedProfileVariant { profile, variant });
            }
        }
    }
    None
}

pub fn find_variant_by_service_name<'a>(
    manifest: &'a ProfilesManifest,
    service_name: &str,
) -> Option<ResolvedProfileVariant<'a>> {
    for profile in &manifest.profiles {
        for variant in &profile.variants {
            if variant.service_name == service_name {
                return Some(ResolvedProfileVariant { profile, variant });
            }
        }
    }
    None
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
      "kind": "probe",
      "label": "minimal",
      "variants": [
        {
          "variant": "base",
          "bundle_id": "com.example.ProbeService_minimal",
          "service_name": "ProbeService_minimal",
          "tags": ["probe", "baseline"],
          "entitlements": {"com.apple.security.app-sandbox": true}
        }
      ]
    }
  ]
}"#;
        let parsed: ProfilesManifest = serde_json::from_str(data).unwrap();
        assert_eq!(parsed.profiles.len(), 1);
        assert_eq!(parsed.profiles[0].profile_id, "minimal");
        assert_eq!(parsed.profiles[0].kind, "probe");
        assert_eq!(parsed.profiles[0].variants.len(), 1);
    }

    #[test]
    fn finds_profile_by_selectors() {
        let manifest = ProfilesManifest {
            generated_at: None,
            profiles: vec![ProfileEntry {
                profile_id: "minimal".to_string(),
                kind: "probe".to_string(),
                label: None,
                variants: vec![ProfileVariant {
                    variant: "base".to_string(),
                    bundle_id: "com.example.ProbeService_minimal".to_string(),
                    service_name: "ProbeService_minimal".to_string(),
                    tags: None,
                    risk_tier: None,
                    risk_reasons: None,
                    entitlements: None,
                    entitlements_error: None,
                }],
            }],
        };

        assert!(find_profile_by_id(&manifest, "minimal").is_some());

        let by_bundle =
            find_variant_by_bundle_id(&manifest, "com.example.ProbeService_minimal")
                .expect("variant by bundle");
        assert_eq!(by_bundle.profile.profile_id, "minimal");
        assert_eq!(by_bundle.variant.service_name, "ProbeService_minimal");

        let by_service =
            find_variant_by_service_name(&manifest, "ProbeService_minimal")
                .expect("variant by service name");
        assert_eq!(by_service.profile.profile_id, "minimal");
        assert_eq!(by_service.variant.bundle_id, "com.example.ProbeService_minimal");
    }

    #[test]
    fn finds_variant_by_bundle_id() {
        let manifest = ProfilesManifest {
            generated_at: None,
            profiles: vec![ProfileEntry {
                profile_id: "minimal".to_string(),
                kind: "probe".to_string(),
                label: None,
                variants: vec![ProfileVariant {
                    variant: "injectable".to_string(),
                    bundle_id: "com.example.ProbeService_minimal.injectable".to_string(),
                    service_name: "ProbeService_minimal__injectable".to_string(),
                    tags: None,
                    risk_tier: Some(2),
                    risk_reasons: Some(vec!["allow_unsigned_exec_mem".to_string()]),
                    entitlements: None,
                    entitlements_error: None,
                }],
            }],
        };

        let resolved = find_variant_by_bundle_id(
            &manifest,
            "com.example.ProbeService_minimal.injectable",
        )
        .expect("variant");
        assert_eq!(resolved.profile.profile_id, "minimal");
        assert_eq!(resolved.variant.variant, "injectable");
    }
}
