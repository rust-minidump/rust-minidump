use serde_json::map::Map;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use tracing::error;

/// Things extracted from the Evil JSON File
#[derive(Debug, Default)]
pub(crate) struct Evil {
    /// module name => cert
    pub certs: HashMap<String, String>,
    /// The microcode version of the cpu
    pub cpu_microcode_version: Option<String>,
}

pub(crate) fn handle_evil(evil_path: &Path) -> Option<Evil> {
    // Get the evil json
    let evil_json = File::open(evil_path)
        .map_err(|e| {
            error!("Could not load Extra JSON at {:?}", evil_path);
            e
        })
        .ok()?;

    let buf = BufReader::new(evil_json);
    let mut json: Map<String, Value> = serde_json::from_reader(buf)
        .map_err(|e| {
            error!("Could not parse Extra JSON (was not valid JSON)");
            e
        })
        .ok()?;

    // Of course evil json contains a string-that-can-be-parsed-as-a-json-object
    // instead of having a normal json object!
    fn evil_obj<K, V>(json: &mut Map<String, Value>, field_name: &str) -> Option<HashMap<K, V>>
    where
        K: for<'de> serde::de::Deserialize<'de> + Eq + std::hash::Hash,
        V: for<'de> serde::de::Deserialize<'de>,
    {
        json.remove(field_name).and_then(|val| {
            match val {
                Value::Object(_) => serde_json::from_value(val).ok(),
                Value::String(string) => serde_json::from_str(&string).ok(),
                _ => None,
            }
            .or_else(|| {
                error!("Could not parse Evil JSON's {} (not an object)", field_name);
                None
            })
        })
    }

    // Convert certs from
    // "cert_name1": ["module1", "module2", ...], "cert_name2": ...
    // to
    // "module1": "cert_name1", "module2": "cert_name1", ...
    let certs = evil_obj(&mut json, "ModuleSignatureInfo")
        .map(|certs: HashMap<String, Vec<String>>| {
            let mut cert_map = HashMap::new();
            for (cert, modules) in certs {
                for module in modules {
                    cert_map.insert(module, cert.clone());
                }
            }
            cert_map
        })
        .unwrap_or_default();

    // The CPUMicrocodeVersion field is a hex string starting with "0x"; the string formatting will
    // be verified later.
    let cpu_microcode_version = json
        .remove("CPUMicrocodeVersion")
        .and_then(|v| Some(v.as_str()?.to_owned()));

    Some(Evil {
        certs,
        cpu_microcode_version,
    })
}
