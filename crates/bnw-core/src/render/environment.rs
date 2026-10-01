//! `/etc/environment`: le variabili del proxy per tutta la sessione. Il file è di
//! tutti, quindi si aggiorna riga per riga senza toccare il resto.

use super::local_proxy_url;

const NO_PROXY: &str = "localhost,127.0.0.1,::1";
const KEYS: [&str; 6] = [
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "no_proxy",
    "NO_PROXY",
];

fn wanted(port: u16) -> Vec<(&'static str, String)> {
    let url = local_proxy_url(port);
    KEYS.iter()
        .map(|&k| {
            let v = if k.eq_ignore_ascii_case("no_proxy") {
                NO_PROXY.to_string()
            } else {
                url.clone()
            };
            (k, v)
        })
        .collect()
}

fn key_of(line: &str) -> Option<&str> {
    let (k, _) = line.split_once('=')?;
    let k = k.trim();
    KEYS.contains(&k).then_some(k)
}

/// Porta le sei variabili al valore giusto: corregge quelle presenti con un valore
/// diverso, aggiunge in fondo quelle che mancano, lascia stare tutto il resto.
pub fn merge(existing: &str, port: u16) -> String {
    let want = wanted(port);
    let mut seen = Vec::new();
    let mut out = String::new();
    for line in existing.lines() {
        match key_of(line) {
            Some(k) if seen.contains(&k) => continue, // doppione: resta la prima
            Some(k) => {
                let (_, v) = want.iter().find(|(wk, _)| *wk == k).unwrap();
                out += &format!("{k}={v}\n");
                seen.push(k);
            }
            None => {
                out += line;
                out += "\n";
            }
        }
    }
    for (k, v) in &want {
        if !seen.contains(k) {
            out += &format!("{k}={v}\n");
        }
    }
    out
}

/// Toglie le variabili del proxy (disinstallazione).
pub fn remove(existing: &str) -> String {
    existing
        .lines()
        .filter(|l| key_of(l).is_none())
        .map(|l| format!("{l}\n"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corregge_la_porta_senza_duplicare() {
        let old = "A=1\nhttp_proxy=http://127.0.0.1:9999\nhttp_proxy=x\n";
        let new = merge(old, 8118);
        assert!(
            new.starts_with("A=1\nhttp_proxy=http://127.0.0.1:8118\nhttps_proxy="),
            "{new}"
        );
        assert_eq!(new.matches("http_proxy=").count(), 1);
        assert_eq!(merge(&new, 8118), new);
        assert_eq!(remove(&new), "A=1\n");
    }
}
