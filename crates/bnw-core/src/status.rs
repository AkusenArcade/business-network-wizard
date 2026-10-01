//! Lo stato della macchina come lo mostrano la GUI e `bnw status --json`. Qui ci sono
//! solo i tipi e l'interpretazione dei testi; la lettura vera sta in `bnw-client`.

use serde::{Deserialize, Serialize};

use crate::action::ProxyMode;

/// Dove va il traffico di tinyproxy, secondo il symlink `active.conf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    /// Connessione diretta.
    Direct,
    /// Attraverso cntlm e il proxy aziendale.
    Upstream,
}

impl Route {
    /// Dal nome del file a cui punta `active.conf`.
    pub fn from_target(target: &str) -> Option<Route> {
        match target.rsplit('/').next()?.strip_suffix(".conf")? {
            "direct" => Some(Route::Direct),
            "upstream" => Some(Route::Upstream),
            _ => None,
        }
    }
}

/// Una connessione di NetworkManager del profilo (VPN o WiFi aziendale).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub name: String,
    pub active: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// Nome dell'azienda del profilo applicato; `None` se l'app non ha ancora
    /// configurato questa macchina.
    pub company: Option<String>,
    pub route: Option<Route>,
    /// Forzatura manuale in corso (`on`/`off`); `None` se automatico.
    pub forced: Option<ProxyMode>,
    /// `ActiveState` di systemd (`active`, `inactive`, `failed`…).
    pub tinyproxy: Option<String>,
    pub cntlm: Option<String>,
    pub vpn: Option<Connection>,
    pub wifi: Option<Connection>,
    /// L'ultima decisione di `proxy-detect`, dal journal.
    pub last_decision: Option<String>,
    /// Ci sono ancora gli script di un'installazione manuale da adottare.
    pub legacy: bool,
    #[serde(default)]
    pub shares: Vec<ShareState>,
    #[serde(default)]
    pub printers: Vec<PrinterState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareState {
    pub mount: String,
    pub unc: String,
    pub mounted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrinterState {
    pub name: String,
    /// `idle`, `printing`, `disabled`; `None` se la coda non esiste.
    pub state: Option<String>,
}

/// I punti di montaggio CIFS da `/proc/mounts` (gli spazi sono `\040`).
pub fn cifs_mounts(proc_mounts: &str) -> Vec<String> {
    proc_mounts
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 2 && (f[2] == "cifs" || f[2] == "smb3")).then(|| f[1].replace("\\040", " "))
        })
        .collect()
}

/// Lo stato di una coda da `lpstat -p NOME` (in inglese: `LANG=C`).
pub fn parse_lpstat(out: &str) -> Option<String> {
    let line = out.lines().find(|l| l.starts_with("printer "))?;
    Some(
        if line.contains(" is idle") {
            "idle"
        } else if line.contains("now printing") {
            "printing"
        } else if line.contains("disabled") {
            "disabled"
        } else {
            "unknown"
        }
        .to_string(),
    )
}

/// `ActiveState` di systemd in italiano.
pub fn service_label(state: Option<&str>) -> &str {
    match state {
        Some("active") => "attivo",
        Some("inactive") => "spento",
        Some("failed") => "in errore",
        Some("activating") => "in avvio",
        Some("deactivating") => "in arresto",
        Some(other) => other,
        None => "sconosciuto",
    }
}

/// `/run/proxy-mode.manual` contiene `on` o `off`.
pub fn parse_forced(content: &str) -> Option<ProxyMode> {
    match content.trim() {
        "on" => Some(ProxyMode::On),
        "off" => Some(ProxyMode::Off),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_dal_symlink() {
        assert_eq!(
            Route::from_target("/etc/tinyproxy/upstream.conf"),
            Some(Route::Upstream)
        );
        assert_eq!(Route::from_target("direct.conf"), Some(Route::Direct));
        assert_eq!(Route::from_target("/etc/tinyproxy/altro.conf"), None);
        assert_eq!(parse_forced("on\n"), Some(ProxyMode::On));
        assert_eq!(parse_forced(""), None);
        assert_eq!(
            cifs_mounts("/dev/a / btrfs rw 0 0\n//s/X /mnt/a\\040b cifs rw 0 0\n"),
            ["/mnt/a b"]
        );
        assert_eq!(
            parse_lpstat("printer STAMPA_P1 is idle.  enabled since x\n").as_deref(),
            Some("idle")
        );
        assert_eq!(parse_lpstat("lpstat: Invalid destination name\n"), None);
    }
}
