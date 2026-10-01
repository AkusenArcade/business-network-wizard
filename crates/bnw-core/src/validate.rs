//! Validazione del profilo e dei dati della macchina. I valori finiscono dentro file di
//! configurazione a righe (cntlm, tinyproxy, unit systemd, credenziali CIFS) scritti
//! da root: un a capo o una virgoletta di troppo cambierebbe il significato del file.
//! L'helper rivalida tutto, anche se la GUI l'ha già fatto.

use std::fmt;

use crate::profile::Profile;
use crate::target::{Secret, Target};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    /// Dove, es. `share[2].mount`.
    pub field: String,
    pub message: String,
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

#[derive(Default)]
struct Report(Vec<Invalid>);

impl Report {
    fn check(&mut self, ok: bool, field: impl Into<String>, message: impl Into<String>) {
        if !ok {
            self.0.push(Invalid {
                field: field.into(),
                message: message.into(),
            });
        }
    }

    fn finish(self) -> Result<(), Vec<Invalid>> {
        if self.0.is_empty() { Ok(()) } else { Err(self.0) }
    }
}

/// Nome host DNS (o indirizzo IPv4): etichette di lettere, cifre e trattini.
pub fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// `host:porta`, porta obbligatoria.
pub fn is_host_port(s: &str) -> bool {
    match s.rsplit_once(':') {
        Some((h, p)) => is_hostname(h) && p.parse::<u16>().is_ok_and(|p| p > 0),
        None => false,
    }
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
}

/// Eccezione del proxy: host, `.suffisso` o rete IPv4 CIDR.
pub fn is_direct_rule(s: &str) -> bool {
    if let Some((ip, bits)) = s.split_once('/') {
        return is_ipv4(ip) && bits.parse::<u8>().is_ok_and(|b| b <= 32);
    }
    is_hostname(s.strip_prefix('.').unwrap_or(s))
}

/// Testo libero su una riga sola: niente caratteri di controllo.
pub fn is_single_line(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

/// URL http(s) senza spazi né caratteri di controllo (finisce come argomento di curl).
pub fn is_http_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://"))
        && s.len() > 8
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Parola "sicura": lettere, cifre e `._-` (più quelli ammessi in `extra`).
fn is_word(s: &str, extra: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c) || extra.contains(c))
}

/// Punto di montaggio: sotto `/mnt`, componenti semplici, niente `..`.
pub fn is_mount_path(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("/mnt/") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('/')
            .all(|c| is_word(c, "") && c != "." && c != ".." && !c.starts_with('.'))
}

fn is_sha1_fingerprint(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 20
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

pub fn profile(p: &Profile) -> Result<(), Vec<Invalid>> {
    let mut r = Report::default();

    r.check(
        is_single_line(&p.company.name) && !p.company.slug().is_empty(),
        "company.name",
        "serve un nome con almeno una lettera o cifra, su una riga",
    );
    r.check(
        is_word(&p.company.domain, "") && p.company.domain.len() <= 15,
        "company.domain",
        "dominio NetBIOS: lettere, cifre, . _ -, al massimo 15 caratteri",
    );

    let px = &p.proxy;
    r.check(
        !px.upstream.is_empty(),
        "proxy.upstream",
        "serve almeno un proxy aziendale",
    );
    for (i, u) in px.upstream.iter().enumerate() {
        r.check(
            is_host_port(u),
            format!("proxy.upstream[{i}]"),
            format!("\"{u}\" non è host:porta"),
        );
    }
    r.check(px.local_port > 0, "proxy.local_port", "porta non valida");
    r.check(px.cntlm_port > 0, "proxy.cntlm_port", "porta non valida");
    r.check(
        px.local_port != px.cntlm_port,
        "proxy.cntlm_port",
        "deve essere diversa da local_port",
    );
    for (i, d) in px.direct.iter().enumerate() {
        r.check(
            is_direct_rule(d.host()),
            format!("proxy.direct[{i}]"),
            format!("\"{}\" non è un host, un .dominio o una rete CIDR", d.host()),
        );
        if let Some(note) = d.note() {
            r.check(
                !note.chars().any(|c| c.is_control() && c != '\n'),
                format!("proxy.direct[{i}].note"),
                "caratteri di controllo nella nota",
            );
        }
    }
    if let Some(url) = &px.check_url {
        r.check(
            is_http_url(url),
            "proxy.check_url",
            "serve un URL http:// o https:// su una riga",
        );
    }
    if let Some(pac) = &px.pac {
        r.check(is_single_line(pac), "proxy.pac", "deve stare su una riga");
    }

    if let Some(v) = &p.vpn {
        // diventa anche il nome del file .ovpn da importare: niente «/» né punto iniziale
        r.check(
            is_word(&v.name, " ") && !v.name.starts_with('.') && v.name.len() <= 64,
            "vpn.name",
            "nome della VPN: lettere, cifre, spazi, . _ - (fino a 64)",
        );
        r.check(
            is_archive_path(&v.file),
            "vpn.file",
            "percorso relativo dentro il profilo",
        );
    }

    if let Some(w) = &p.wifi {
        r.check(
            !w.name.is_empty() && is_single_line(&w.name),
            "wifi.name",
            "nome vuoto o su più righe",
        );
        r.check(
            !w.ssid.is_empty() && w.ssid.len() <= 32 && is_single_line(&w.ssid),
            "wifi.ssid",
            "SSID da 1 a 32 byte",
        );
        r.check(
            is_archive_path(&w.ca),
            "wifi.ca",
            "percorso relativo dentro il profilo",
        );
        if let Some(fp) = &w.ca_sha1 {
            r.check(
                is_sha1_fingerprint(fp),
                "wifi.ca_sha1",
                "formato atteso AA:BB:… (20 byte)",
            );
        }
        r.check(
            is_hostname(&w.domain_suffix_match),
            "wifi.domain_suffix_match",
            "nome host non valido",
        );
    }

    let mut mounts = Vec::new();
    for (i, s) in p.shares.iter().enumerate() {
        r.check(
            is_hostname(&s.server),
            format!("share[{i}].server"),
            "nome host non valido",
        );
        r.check(
            is_word(&s.name, "$"),
            format!("share[{i}].name"),
            "nome della share: lettere, cifre, . _ - $ (niente spazi)",
        );
        r.check(
            is_mount_path(&s.mount),
            format!("share[{i}].mount"),
            "cartella sotto /mnt, con lettere, cifre, . _ -",
        );
        r.check(
            !mounts.contains(&&s.mount),
            format!("share[{i}].mount"),
            "cartella già usata da un'altra share",
        );
        mounts.push(&s.mount);
        if let Some(l) = &s.label {
            r.check(
                is_single_line(l),
                format!("share[{i}].label"),
                "deve stare su una riga",
            );
        }
    }

    let mut names = Vec::new();
    for (i, pr) in p.printers.iter().enumerate() {
        r.check(
            is_word(&pr.name, "") && pr.name.len() <= 127,
            format!("printer[{i}].name"),
            "nome della coda: lettere, cifre, . _ -",
        );
        r.check(
            !names.contains(&&pr.name),
            format!("printer[{i}].name"),
            "coda già presente",
        );
        names.push(&pr.name);
        let host = pr
            .uri
            .strip_prefix("ipp://")
            .or_else(|| pr.uri.strip_prefix("ipps://"));
        r.check(
            host.is_some_and(|h| {
                let authority = h.split('/').next().unwrap_or("");
                (is_hostname(authority) || is_host_port(authority))
                    && is_single_line(h)
                    && !h.contains(char::is_whitespace)
            }),
            format!("printer[{i}].uri"),
            "URI atteso ipp://host/… o ipps://host/…",
        );
        for (f, v) in [("description", &pr.description), ("location", &pr.location)] {
            if let Some(v) = v {
                r.check(
                    is_single_line(v),
                    format!("printer[{i}].{f}"),
                    "deve stare su una riga",
                );
            }
        }
    }

    r.finish()
}

/// Percorso dentro l'archivio `.bnw`: relativo, senza `..`.
pub fn is_archive_path(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('/') && s.split('/').all(|c| is_word(c, " ") && c != "..")
}

pub fn target(t: &Target) -> Result<(), Vec<Invalid>> {
    let mut r = Report::default();
    r.check(
        is_word(&t.domain_user, "") && t.domain_user.len() <= 104,
        "domain_user",
        "utenza di dominio: lettere, cifre, . _ - (senza DOMINIO\\)",
    );
    r.finish()
}

/// La password va su una riga del file credenziali CIFS e su stdin di `cntlm -H`.
pub fn password(p: &Secret) -> Result<(), Vec<Invalid>> {
    let mut r = Report::default();
    r.check(!p.expose().is_empty(), "password", "password vuota");
    r.check(
        !p.expose().contains(['\n', '\r', '\0']),
        "password",
        "la password non può contenere a capo",
    );
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_e_regole() {
        assert!(is_hostname("fs1.corp.esempio"));
        assert!(is_hostname("10.20.30.40"));
        assert!(!is_hostname("a b"));
        assert!(!is_hostname("a..b"));
        assert!(!is_hostname("x\"y"));
        assert!(is_host_port("10.20.30.40:3128"));
        assert!(!is_host_port("10.20.30.40"));
        assert!(!is_host_port("h:0"));
        assert!(is_direct_rule(".corp.esempio"));
        assert!(is_direct_rule("172.16.0.0/12"));
        assert!(!is_direct_rule("172.16.0.0/33"));
        assert!(!is_direct_rule("\"x\""));
    }

    #[test]
    fn punti_di_montaggio() {
        assert!(is_mount_path("/mnt/area-clienti"));
        assert!(is_mount_path("/mnt/a/b"));
        assert!(!is_mount_path("/mnt/"));
        assert!(!is_mount_path("/etc/x"));
        assert!(!is_mount_path("/mnt/../etc"));
        assert!(!is_mount_path("/mnt/a b"));
    }

    #[test]
    fn password_su_una_riga() {
        assert!(password(&Secret::new("a;b c\"d")).is_ok());
        assert!(password(&Secret::new("a\nusername=x")).is_err());
        assert!(password(&Secret::new("")).is_err());
    }
}
