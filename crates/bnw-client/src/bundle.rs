//! Esportazione e importazione del profilo `.bnw` dal lato utente: trovare i file da
//! mettere dentro, costruire l'archivio, riassumerne il contenuto.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use bnw_core::Profile;
use bnw_core::bundle::{Bundle, BundleError, pem_sha1};

/// La CA che la connessione WiFi usa davvero (`802-1x.ca-cert`, non è un segreto).
pub fn detect_ca(profile: &Profile) -> Option<PathBuf> {
    let wifi = profile.wifi.as_ref()?;
    let out = Command::new("nmcli")
        .args(["-g", "802-1x.ca-cert", "connection", "show", "id", &wifi.name])
        .output()
        .ok()?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let path = PathBuf::from(value.strip_prefix("file://").unwrap_or(&value));
    (path.is_absolute() && path.is_file()).then_some(path)
}

/// L'`.ovpn` con quel nome nelle cartelle dove di solito sta (Documenti, Scaricati),
/// fino a tre livelli di profondità.
pub fn detect_ovpn(profile: &Profile, home: &Path) -> Option<PathBuf> {
    let name = Path::new(&profile.vpn.as_ref()?.file).file_name()?.to_os_string();
    fn find(dir: &Path, name: &std::ffi::OsStr, depth: u8) -> Option<PathBuf> {
        let entries = std::fs::read_dir(dir).ok()?;
        let mut subdirs = Vec::new();
        for e in entries.flatten() {
            let p = e.path();
            if e.file_name() == name && p.is_file() {
                return Some(p);
            }
            if depth > 0 && p.is_dir() && !e.file_name().to_string_lossy().starts_with('.') {
                subdirs.push(p);
            }
        }
        subdirs.sort();
        subdirs.into_iter().find_map(|d| find(&d, name, depth - 1))
    }
    ["Documenti", "Documents", "Scaricati", "Downloads"]
        .iter()
        .find_map(|d| find(&home.join(d), &name, 3))
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("{0}: {1}")]
    Read(String, std::io::Error),
    #[error("serve il file {0}")]
    Needed(&'static str),
    #[error(transparent)]
    Bundle(#[from] BundleError),
}

/// Costruisce il profilo da esportare. Il fingerprint della CA, se il profilo non ce
/// l'ha, lo si calcola qui: chi importa potrà controllarlo.
pub fn build(
    profile: &Profile,
    ovpn: Option<&Path>,
    ca: Option<&Path>,
) -> Result<(Bundle, Vec<String>), ExportError> {
    let mut profile = profile.clone();
    let mut files = BTreeMap::new();
    let read = |p: &Path| std::fs::read(p).map_err(|e| ExportError::Read(p.display().to_string(), e));
    if let Some(v) = &profile.vpn {
        let path = ovpn.ok_or(ExportError::Needed("della VPN (.ovpn)"))?;
        files.insert(v.file.clone(), read(path)?);
    }
    if let Some(w) = profile.wifi.as_mut() {
        let path = ca.ok_or(ExportError::Needed("della CA del WiFi"))?;
        let data = read(path)?;
        if w.ca_sha1.is_none() {
            w.ca_sha1 = pem_sha1(&data);
        }
        files.insert(w.ca.clone(), data);
    }
    let bundle = Bundle { profile, files };
    let warnings = bundle.check()?;
    Ok((bundle, warnings))
}

/// Il contenuto in poche righe, per chi importa.
pub fn summary(b: &Bundle) -> String {
    let p = &b.profile;
    let mut out = format!("Azienda: {} (dominio {})\n", p.company.name, p.company.domain);
    out += &format!(
        "Proxy: {} — {} eccezioni{}\n",
        p.proxy.upstream.join(", "),
        p.proxy.direct.len(),
        if p.proxy.browsers.is_empty() {
            String::new()
        } else {
            format!(
                ", browser: {}",
                p.proxy
                    .browsers
                    .iter()
                    .map(|b| format!("{b:?}").to_lowercase())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );
    if let Some(v) = &p.vpn {
        out += &format!("VPN: {} ({})\n", v.name, v.file);
    }
    if let Some(w) = &p.wifi {
        out += &format!(
            "WiFi: {} (SSID {}, CA {})\n",
            w.name,
            w.ssid,
            w.ca_sha1.as_deref().unwrap_or("senza fingerprint")
        );
    }
    if !p.shares.is_empty() {
        out += &format!(
            "Dischi di rete: {}\n",
            p.shares
                .iter()
                .map(|s| s.mount.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !p.printers.is_empty() {
        out += &format!(
            "Stampanti: {}\n",
            p.printers
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    out
}

/// L'azione che applica un profilo importato: una sola, così il profilo precedente si
/// legge una volta e quello che non c'è più si toglie. I segnalibri dei dischi li
/// aggiorna chi chiama.
pub fn apply_action(b: &Bundle, domain_user: Option<String>) -> bnw_core::action::Action {
    use bnw_core::Blob;
    let p = &b.profile;
    bnw_core::action::Action::ApplyProfile {
        profile: p.clone(),
        ovpn: p
            .vpn
            .as_ref()
            .and_then(|v| b.files.get(&v.file))
            .map(|d| Blob(d.clone())),
        ca: p
            .wifi
            .as_ref()
            .and_then(|w| b.files.get(&w.ca))
            .map(|d| Blob(d.clone())),
        domain_user,
        owner_uid: crate::user::current_uid(),
    }
}

/// Cosa resta da fare dopo l'importazione.
pub const AFTER_IMPORT: &str = "Le password non sono nel profilo: aggiornale dalla pagina Password (o con \
«bnw password»). Le stampanti che non rispondono si aggiungono rilanciando dalla rete aziendale.";
