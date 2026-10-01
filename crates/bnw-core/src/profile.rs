//! Il profilo aziendale: tutto ciò che descrive la rete di un'azienda e che non è
//! segreto. È il `profile.toml` dentro il `.bnw` e la copia in `/etc/bnw/profile.toml`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub company: Company,
    pub proxy: Proxy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn: Option<Vpn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wifi: Option<Wifi>,
    #[serde(default, rename = "share", skip_serializing_if = "Vec::is_empty")]
    pub shares: Vec<Share>,
    #[serde(default, rename = "printer", skip_serializing_if = "Vec::is_empty")]
    pub printers: Vec<Printer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Company {
    /// Nome leggibile, anche nei commenti dei file generati.
    pub name: String,
    /// Dominio NTLM (NetBIOS) per cntlm e per le credenziali CIFS.
    pub domain: String,
    /// Esempio di utenza da mostrare nel wizard, non l'utenza vera.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_hint: Option<String>,
}

impl Company {
    /// Nome in forma di file: `/etc/samba/credentials/<slug>`.
    pub fn slug(&self) -> String {
        let mut out = String::new();
        for c in self.name.chars() {
            if c.is_ascii_alphanumeric() {
                out.push(c.to_ascii_lowercase());
            } else if !out.is_empty() && !out.ends_with('-') {
                out.push('-');
            }
        }
        out.trim_end_matches('-').to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    /// Proxy aziendali (`host:porta`), padri di cntlm, in ordine di preferenza.
    pub upstream: Vec<String>,
    #[serde(default = "default_local_port")]
    pub local_port: u16,
    #[serde(default = "default_cntlm_port")]
    pub cntlm_port: u16,
    /// Destinazioni che non passano dal proxy aziendale.
    #[serde(default)]
    pub direct: Vec<DirectRule>,
    #[serde(default)]
    pub browsers: Vec<Browser>,
    /// Il PAC da cui sono state tradotte le regole, se c'è: solo documentazione.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pac: Option<String>,
    /// Indirizzo esterno con cui provare l'autenticazione NTLM dopo un cambio
    /// password; se manca, [`DEFAULT_CHECK_URL`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_url: Option<String>,
}

pub const DEFAULT_CHECK_URL: &str = "https://www.google.com";

impl Proxy {
    pub fn check_url(&self) -> &str {
        self.check_url.as_deref().unwrap_or(DEFAULT_CHECK_URL)
    }
}

fn default_local_port() -> u16 {
    8118
}

fn default_cntlm_port() -> u16 {
    3128
}

/// Un'eccezione del proxy: un host, un suffisso (`.dominio`) o una rete CIDR, con
/// una nota facoltativa che finisce come commento in `upstream.conf`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DirectRule {
    Host(String),
    Annotated { host: String, note: String },
}

impl DirectRule {
    pub fn host(&self) -> &str {
        match self {
            DirectRule::Host(h) | DirectRule::Annotated { host: h, .. } => h,
        }
    }

    pub fn note(&self) -> Option<&str> {
        match self {
            DirectRule::Host(_) => None,
            DirectRule::Annotated { note, .. } => Some(note),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Browser {
    Firefox,
    Zen,
}

impl Browser {
    /// File di policy di sistema. Per Zen `/etc/zen` è il percorso stabile: quello
    /// sotto `/opt` lo sovrascrivono gli aggiornamenti (lo gestisce l'helper, se c'è).
    pub fn policy_path(self) -> &'static str {
        match self {
            Browser::Firefox => "/etc/firefox/policies/policies.json",
            Browser::Zen => "/etc/zen/policies/policies.json",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vpn {
    /// Nome della connessione in NetworkManager.
    pub name: String,
    /// Percorso dell'`.ovpn` dentro l'archivio `.bnw`.
    pub file: String,
    #[serde(default = "yes")]
    pub full_tunnel: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wifi {
    /// Nome della connessione in NetworkManager.
    pub name: String,
    pub ssid: String,
    #[serde(default)]
    pub eap: Eap,
    #[serde(default)]
    pub phase2: Phase2,
    /// Percorso della CA del RADIUS dentro l'archivio `.bnw`.
    pub ca: String,
    /// Fingerprint SHA-1 atteso della CA (`AA:BB:…`), controllato all'import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_sha1: Option<String>,
    pub domain_suffix_match: String,
    #[serde(default)]
    pub autoconnect: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Eap {
    #[default]
    Peap,
    Ttls,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase2 {
    #[default]
    Mschapv2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub server: String,
    pub name: String,
    pub mount: String,
    /// Etichetta del segnalibro; se manca, `NOME (server)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Share {
    pub fn unc(&self) -> String {
        format!("//{}/{}", self.server, self.name)
    }

    pub fn label(&self) -> String {
        match &self.label {
            Some(l) => l.clone(),
            None => {
                let host = self.server.split('.').next().unwrap_or(&self.server);
                format!("{} ({})", self.name, host)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Printer {
    /// Nome della coda CUPS.
    pub name: String,
    /// URI IPP driverless, es. `ipp://host/ipp`.
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Lato di stampa predefinito: `false` = solo fronte.
    #[serde(default)]
    pub duplex: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("profilo non leggibile: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("profilo non scrivibile: {0}")]
    Serialize(#[from] toml::ser::Error),
}

impl Profile {
    pub fn from_toml(text: &str) -> Result<Self, ProfileError> {
        Ok(toml::from_str(text)?)
    }

    pub fn to_toml(&self) -> Result<String, ProfileError> {
        Ok(toml::to_string_pretty(self)?)
    }
}
