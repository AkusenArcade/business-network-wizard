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

/// Un profilo vuoto da compilare a mano.
pub fn empty() -> Bundle {
    use bnw_core::profile::{Company, Proxy};
    Bundle {
        profile: Profile {
            company: Company {
                name: String::new(),
                domain: String::new(),
                user_hint: None,
            },
            proxy: Proxy {
                upstream: Vec::new(),
                local_port: 8118,
                cntlm_port: 3128,
                direct: [
                    "localhost",
                    "127.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                ]
                .iter()
                .map(|h| bnw_core::profile::DirectRule::Host(h.to_string()))
                .collect(),
                browsers: vec![bnw_core::profile::Browser::Firefox],
                pac: None,
                check_url: None,
            },
            vpn: None,
            wifi: None,
            shares: Vec::new(),
            printers: Vec::new(),
        },
        files: BTreeMap::new(),
    }
}

/// Il profilo applicato su questa macchina, con l'`.ovpn` e la CA trovati come fa
/// l'esportazione (quelli che non si trovano restano da scegliere).
pub fn from_installed(env: &crate::Env, home: &Path) -> Option<Bundle> {
    let profile = crate::status::installed_profile(env)?;
    let mut files = BTreeMap::new();
    if let (Some(v), Some(path)) = (&profile.vpn, detect_ovpn(&profile, home))
        && let Ok(d) = std::fs::read(path)
    {
        files.insert(v.file.clone(), d);
    }
    if let (Some(w), Some(path)) = (&profile.wifi, detect_ca(&profile))
        && let Ok(d) = std::fs::read(path)
    {
        files.insert(w.ca.clone(), d);
    }
    Some(Bundle { profile, files })
}

/// Allinea l'archivio al profilo: l'`.ovpn` in `vpn/<nome>.ovpn`, la CA in
/// `wifi/ca.pem`, il fingerprint della CA ricalcolato dal file, e via i file che il
/// profilo non cita più (per esempio dopo aver tolto la VPN).
pub fn normalize(mut b: Bundle) -> Bundle {
    let take = |files: &mut BTreeMap<String, Vec<u8>>, current: Option<&str>, suffix: &str| {
        current.and_then(|c| files.remove(c)).or_else(|| {
            let key = files.keys().find(|k| k.ends_with(suffix)).cloned()?;
            files.remove(&key)
        })
    };
    let mut out = BTreeMap::new();
    if let Some(v) = b.profile.vpn.as_mut() {
        let data = take(&mut b.files, Some(&v.file), ".ovpn");
        v.file = format!("vpn/{}.ovpn", v.name.replace('/', "-"));
        if let Some(d) = data {
            out.insert(v.file.clone(), d);
        }
    }
    if let Some(w) = b.profile.wifi.as_mut() {
        let data = take(&mut b.files, Some(&w.ca), ".pem");
        w.ca = "wifi/ca.pem".into();
        if let Some(d) = data {
            if let Some(fp) = pem_sha1(&d) {
                w.ca_sha1 = Some(fp);
            }
            out.insert(w.ca.clone(), d);
        }
    }
    b.files = out;
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use bnw_core::profile::{Vpn, Wifi};

    const CA: &str = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";

    #[test]
    fn normalizza_file_e_fingerprint() {
        let mut b = empty();
        b.profile.vpn = Some(Vpn {
            name: "Nuova".into(),
            file: "vecchio/x.ovpn".into(),
            full_tunnel: true,
        });
        b.profile.wifi = Some(Wifi {
            name: "W".into(),
            ssid: "W".into(),
            eap: Default::default(),
            phase2: Default::default(),
            ca: "altro.pem".into(),
            ca_sha1: Some("00".into()),
            domain_suffix_match: "dc.x".into(),
            autoconnect: false,
        });
        b.files.insert("vecchio/x.ovpn".into(), b"client".to_vec());
        b.files.insert("altro.pem".into(), CA.as_bytes().to_vec());
        b.files.insert("orfano.txt".into(), b"x".to_vec());
        let n = normalize(b);
        assert_eq!(n.profile.vpn.as_ref().unwrap().file, "vpn/Nuova.ovpn");
        assert_eq!(
            n.files.keys().collect::<Vec<_>>(),
            ["vpn/Nuova.ovpn", "wifi/ca.pem"]
        );
        assert_eq!(n.profile.wifi.as_ref().unwrap().ca_sha1, pem_sha1(CA.as_bytes()));
        // tolta la VPN, via anche il suo file
        let mut n2 = n.clone();
        n2.profile.vpn = None;
        assert_eq!(normalize(n2).files.keys().collect::<Vec<_>>(), ["wifi/ca.pem"]);
    }

    #[test]
    fn profilo_vuoto_non_valido_finche_non_si_compila() {
        let mut b = empty();
        assert!(bnw_core::validate::profile(&b.profile).is_err());
        b.profile.company.name = "Esempio".into();
        b.profile.company.domain = "ESEMPIO".into();
        b.profile.proxy.upstream.push("10.20.30.40:8080".into());
        assert!(bnw_core::validate::profile(&b.profile).is_ok());
    }
}
