use serde::Serialize;
use serde_json::{Map, Value};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize, Clone)]
pub struct JsonResult {
    pub ok: bool,
    pub rc: Option<i64>,
    pub exit_code: Option<i32>,
    pub normalized_outcome: Option<String>,
    pub errno: Option<i64>,
    pub error: Option<String>,
    pub stderr: Option<String>,
    pub stdout: Option<String>,
}

impl JsonResult {
    pub fn from_ok(ok: bool) -> Self {
        JsonResult {
            ok,
            rc: None,
            exit_code: Some(if ok { 0 } else { 3 }),
            normalized_outcome: None,
            errno: None,
            error: None,
            stderr: None,
            stdout: None,
        }
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn sort_value(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                sort_value(item);
            }
        }
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> =
                map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = Map::new();
            for (key, mut val) in entries {
                sort_value(&mut val);
                sorted.insert(key, val);
            }
            *map = sorted;
        }
        _ => {}
    }
}

fn envelope_value<T: Serialize>(kind: &str, result: JsonResult, data: &T) -> Result<Value, String> {
    let mut value = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "generated_at_unix_ms": now_unix_ms(),
        "result": result,
        "data": data,
    });
    sort_value(&mut value);
    Ok(value)
}

pub fn render_envelope<T: Serialize>(
    kind: &str,
    result: JsonResult,
    data: &T,
) -> Result<String, String> {
    let value = envelope_value(kind, result, data)?;
    serde_json::to_string_pretty(&value)
        .map_err(|e| format!("failed to encode JSON: {e}"))
}

#[allow(dead_code)]
pub fn render_envelope_compact<T: Serialize>(
    kind: &str,
    result: JsonResult,
    data: &T,
) -> Result<String, String> {
    let value = envelope_value(kind, result, data)?;
    serde_json::to_string(&value).map_err(|e| format!("failed to encode JSON: {e}"))
}

pub fn print_envelope<T: Serialize>(
    kind: &str,
    result: JsonResult,
    data: &T,
) -> Result<(), String> {
    let text = render_envelope(kind, result, data)?;
    println!("{text}");
    Ok(())
}

pub fn write_envelope<T: Serialize>(
    path: &Path,
    kind: &str,
    result: JsonResult,
    data: &T,
) -> Result<(), String> {
    let text = render_envelope(kind, result, data)?;
    std::fs::write(path, text)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Dummy {
        label: String,
    }

    #[test]
    fn compact_envelope_is_single_line() {
        let payload = Dummy {
            label: "ok".to_string(),
        };
        let text = render_envelope_compact("dummy", JsonResult::from_ok(true), &payload)
            .expect("render");
        assert!(!text.contains('\n'));
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("parse");
        assert_eq!(parsed["kind"], "dummy");
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }
}
