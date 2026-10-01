//! "Prova un URL": la stessa richiesta diretta e attraverso il proxy locale. Serve a
//! capire se un sito va messo tra le eccezioni (il classico 504 dei siti interni).

use std::process::Command;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Probe {
    /// Codice HTTP; `None` se la connessione non è riuscita.
    pub code: Option<u16>,
    pub seconds: f64,
    /// Messaggio di curl quando non c'è risposta.
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UrlTest {
    pub direct: Probe,
    pub proxy: Probe,
}

/// Solo URL http(s) su una riga: finisce come argomento di curl.
pub fn valid_url(url: &str) -> bool {
    bnw_core::validate::is_http_url(url)
}

fn probe(url: &str, proxy: Option<&str>) -> Probe {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-s",
        "-o",
        "/dev/null",
        "--max-time",
        "10",
        "-w",
        "%{http_code} %{time_total}",
    ]);
    match proxy {
        Some(p) => cmd.args(["--proxy", p]),
        None => cmd.args(["--noproxy", "*"]),
    };
    cmd.arg("--url").arg(url);
    // le variabili *_proxy dell'ambiente non devono decidere al posto nostro
    for v in [
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ] {
        cmd.env_remove(v);
    }
    match cmd.output() {
        Ok(out) => parse_curl(&String::from_utf8_lossy(&out.stdout), out.status.code()),
        Err(e) => Probe {
            code: None,
            seconds: 0.0,
            error: Some(format!("curl: {e}")),
        },
    }
}

/// `-w "%{http_code} %{time_total}"` → codice (000 = nessuna risposta) e tempo.
fn parse_curl(out: &str, exit: Option<i32>) -> Probe {
    let mut parts = out.split_whitespace();
    let code = parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .filter(|&c| c != 0);
    let seconds = parts.next().and_then(|t| t.parse().ok()).unwrap_or(0.0);
    let error = match (code, exit) {
        (Some(_), _) => None,
        (None, Some(6)) => Some("nome non risolto".into()),
        (None, Some(7)) => Some("connessione rifiutata".into()),
        (None, Some(28)) => Some("tempo scaduto".into()),
        (None, Some(35 | 60)) => Some("errore TLS".into()),
        (None, Some(c)) => Some(format!("curl uscito con {c}")),
        (None, None) => Some("curl interrotto".into()),
    };
    Probe { code, seconds, error }
}

pub fn test_url(url: &str, local_port: u16) -> UrlTest {
    let proxy = format!("http://127.0.0.1:{local_port}");
    UrlTest {
        direct: probe(url, None),
        proxy: probe(url, Some(&proxy)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_e_uscita_di_curl() {
        assert!(valid_url("https://www.esempio.it/x?y=1"));
        assert!(!valid_url("file:///etc/passwd"));
        assert!(!valid_url("https://a b"));
        assert!(!valid_url("-K/etc/x"));
        assert_eq!(parse_curl("200 0.123", Some(0)).code, Some(200));
        let p = parse_curl("000 10.0", Some(28));
        assert_eq!((p.code, p.error.as_deref()), (None, Some("tempo scaduto")));
        assert_eq!(parse_curl("504 0.5", Some(0)).code, Some(504));
    }
}
