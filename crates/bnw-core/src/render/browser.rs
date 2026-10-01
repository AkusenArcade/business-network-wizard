//! Policy di sistema di Firefox e Zen: `policies.Proxy` punta a tinyproxy. Il resto
//! del file (altre policy messe da altri) resta com'è.

use serde_json::{Map, Value, json};

use super::local_proxy_url;

pub fn proxy_policy(port: u16) -> Value {
    let hostport = local_proxy_url(port).trim_start_matches("http://").to_string();
    json!({
        "Mode": "manual",
        "HTTPProxy": hostport,
        "SSLProxy": hostport,
        "UseHTTPProxyForAllProtocols": true,
        "Passthrough": "localhost, 127.0.0.1, ::1",
        "AutoLogin": false,
        "UseProxyForDNS": false,
        "Locked": false
    })
}

/// Esito dell'unione: il nuovo testo e un avviso se il file esistente era da buttare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged {
    pub content: String,
    pub warning: Option<String>,
}

/// `existing` è il contenuto attuale del file, se esiste. Un JSON illeggibile o che
/// non è un oggetto viene sostituito, e lo si dice.
pub fn merge(existing: Option<&str>, port: u16) -> Merged {
    let mut warning = None;
    let mut root = match existing.map(serde_json::from_str::<Value>) {
        None => Map::new(),
        Some(Ok(Value::Object(m))) => m,
        Some(Ok(_)) => {
            warning = Some("il file esistente non è un oggetto JSON: lo sostituisco".into());
            Map::new()
        }
        Some(Err(e)) => {
            warning = Some(format!("JSON esistente illeggibile ({e}): lo sostituisco"));
            Map::new()
        }
    };
    let policies = root
        .entry("policies")
        .or_insert_with(|| Value::Object(Map::new()));
    if !policies.is_object() {
        *policies = Value::Object(Map::new());
    }
    policies
        .as_object_mut()
        .unwrap()
        .insert("Proxy".into(), proxy_policy(port));
    let mut content = serde_json::to_string_pretty(&Value::Object(root)).unwrap();
    content.push('\n');
    Merged { content, warning }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conserva_le_altre_policy() {
        let old = r#"{"policies": {"DisableTelemetry": true, "Proxy": {"Mode": "none"}}, "x": 1}"#;
        let m = merge(Some(old), 8118);
        assert!(m.warning.is_none());
        let v: Value = serde_json::from_str(&m.content).unwrap();
        assert_eq!(v["policies"]["DisableTelemetry"], true);
        assert_eq!(v["policies"]["Proxy"]["HTTPProxy"], "127.0.0.1:8118");
        assert_eq!(v["x"], 1);
    }

    #[test]
    fn json_rotto_viene_sostituito_con_avviso() {
        let m = merge(Some("{rotto"), 8118);
        assert!(m.warning.is_some());
        assert_eq!(m.content, merge(None, 8118).content);
    }
}
