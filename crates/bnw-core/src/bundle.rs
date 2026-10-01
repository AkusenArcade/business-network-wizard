//! Il profilo aziendale `.bnw`: un tar con `profile.toml` e i file che cita (`.ovpn`,
//! CA del WiFi), cifrato con [age](https://age-encryption.org) a passphrase. Formato
//! standard: in emergenza si apre anche a mano con `age -d esempio.bnw | tar x`.
//!
//! Dentro non ci sono password di dominio; c'è però la chiave privata della VPN,
//! ed è per questo che il file è sempre cifrato.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use age::secrecy::SecretString;
use base64::Engine;
use sha1::{Digest, Sha1};

use crate::profile::{Profile, ProfileError};
use crate::validate;

const PROFILE_NAME: &str = "profile.toml";
/// Più che sufficiente per un profilo, un `.ovpn` e una CA.
const MAX_TOTAL: u64 = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 16;
pub const MIN_PASSPHRASE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub profile: Profile,
    /// I file citati dal profilo, per percorso relativo (`vpn/Esempio.ovpn`).
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("passphrase sbagliata, oppure non è un profilo .bnw")]
    Decrypt,
    #[error("cifratura non riuscita: {0}")]
    Encrypt(String),
    #[error("la passphrase deve avere almeno {MIN_PASSPHRASE} caratteri")]
    WeakPassphrase,
    #[error("archivio non valido: {0}")]
    Archive(String),
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error("profilo non valido: {0}")]
    Invalid(String),
    #[error("manca il file {0} citato dal profilo")]
    Missing(String),
}

impl Bundle {
    /// I file che il profilo cita: devono esserci tutti, e non altri.
    pub fn referenced(profile: &Profile) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(v) = &profile.vpn {
            out.push(v.file.clone());
        }
        if let Some(w) = &profile.wifi {
            out.push(w.ca.clone());
        }
        out
    }

    /// Controlla profilo e file. Restituisce gli avvisi (non bloccanti).
    pub fn check(&self) -> Result<Vec<String>, BundleError> {
        validate::profile(&self.profile).map_err(|e| {
            BundleError::Invalid(e.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "))
        })?;
        for f in Self::referenced(&self.profile) {
            if !self.files.contains_key(&f) {
                return Err(BundleError::Missing(f));
            }
        }
        let mut warnings = Vec::new();
        if let Some(w) = &self.profile.wifi {
            let ca = &self.files[&w.ca];
            match pem_sha1(ca) {
                None => warnings.push(format!("{}: non è un certificato PEM leggibile", w.ca)),
                Some(fp) => {
                    if let Some(expected) = &w.ca_sha1
                        && !expected.eq_ignore_ascii_case(&fp)
                    {
                        return Err(BundleError::Invalid(format!(
                            "la CA del WiFi ha fingerprint {fp}, il profilo si aspetta {expected}"
                        )));
                    }
                    // la trappola del runbook: la CA della VPN al posto di quella del RADIUS
                    if let Some(v) = &self.profile.vpn
                        && ovpn_inline(&self.files[&v.file], "ca").and_then(|c| pem_sha1(c.as_bytes()))
                            == Some(fp)
                    {
                        warnings.push(
                            "la CA del WiFi è la stessa della VPN: di solito il RADIUS ne usa un'altra"
                                .into(),
                        );
                    }
                }
            }
        }
        if let Some(v) = &self.profile.vpn
            && ovpn_inline(&self.files[&v.file], "key").is_none()
        {
            warnings.push(format!(
                "{}: nessuna chiave privata inline (<key>): la VPN potrebbe non salire",
                v.file
            ));
        }
        Ok(warnings)
    }

    pub fn to_tar(&self) -> Result<Vec<u8>, BundleError> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut add = |name: &str, data: &[u8]| -> Result<(), BundleError> {
            let mut h = tar::Header::new_ustar();
            h.set_size(data.len() as u64);
            h.set_mode(0o600);
            h.set_mtime(0);
            h.set_entry_type(tar::EntryType::Regular);
            builder
                .append_data(&mut h, name, data)
                .map_err(|e| BundleError::Archive(e.to_string()))
        };
        add(PROFILE_NAME, self.profile.to_toml()?.as_bytes())?;
        for (name, data) in &self.files {
            add(name, data)?;
        }
        builder
            .into_inner()
            .map_err(|e| BundleError::Archive(e.to_string()))
    }

    /// Legge un tar fidandosi il meno possibile: solo file regolari, percorsi relativi
    /// semplici, dimensioni limitate, e solo i file che il profilo cita.
    pub fn from_tar(data: &[u8]) -> Result<Bundle, BundleError> {
        let bad = |m: &str| BundleError::Archive(m.to_string());
        let mut archive = tar::Archive::new(data);
        let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut total = 0u64;
        for entry in archive.entries().map_err(|e| bad(&e.to_string()))? {
            let mut entry = entry.map_err(|e| bad(&e.to_string()))?;
            match entry.header().entry_type() {
                tar::EntryType::Regular => {}
                tar::EntryType::Directory => continue,
                _ => return Err(bad("contiene link o file speciali")),
            }
            let name = entry
                .path()
                .map_err(|e| bad(&e.to_string()))?
                .to_string_lossy()
                .into_owned();
            let name = name.trim_start_matches("./").to_string();
            if !validate::is_archive_path(&name) {
                return Err(bad(&format!("percorso non ammesso: {name}")));
            }
            total += entry.size();
            if total > MAX_TOTAL || entries.len() >= MAX_ENTRIES {
                return Err(bad("troppo grande"));
            }
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| bad(&e.to_string()))?;
            if entries.insert(name.clone(), buf).is_some() {
                return Err(bad(&format!("{name} compare due volte")));
            }
        }
        let profile_bytes = entries
            .remove(PROFILE_NAME)
            .ok_or_else(|| bad("manca profile.toml"))?;
        let text = String::from_utf8(profile_bytes).map_err(|_| bad("profile.toml non è testo UTF-8"))?;
        let profile = Profile::from_toml(&text)?;
        let wanted = Self::referenced(&profile);
        if let Some(extra) = entries.keys().find(|k| !wanted.contains(k)) {
            return Err(bad(&format!("file non citato dal profilo: {extra}")));
        }
        Ok(Bundle {
            profile,
            files: entries,
        })
    }

    pub fn encrypt(&self, passphrase: &str) -> Result<Vec<u8>, BundleError> {
        if passphrase.chars().count() < MIN_PASSPHRASE {
            return Err(BundleError::WeakPassphrase);
        }
        let plain = self.to_tar()?;
        let enc = age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_owned()));
        let mut out = Vec::new();
        let err = |e: std::io::Error| BundleError::Encrypt(e.to_string());
        let mut w = enc.wrap_output(&mut out).map_err(err)?;
        w.write_all(&plain).map_err(err)?;
        w.finish().map_err(err)?;
        Ok(out)
    }

    pub fn decrypt(data: &[u8], passphrase: &str) -> Result<Bundle, BundleError> {
        let dec = age::Decryptor::new(data).map_err(|_| BundleError::Decrypt)?;
        if !dec.is_scrypt() {
            return Err(BundleError::Decrypt);
        }
        let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
        let mut reader = dec
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|_| BundleError::Decrypt)?;
        let mut plain = Vec::new();
        reader
            .by_ref()
            .take(MAX_TOTAL * 2)
            .read_to_end(&mut plain)
            .map_err(|_| BundleError::Decrypt)?;
        Bundle::from_tar(&plain)
    }
}

/// Fingerprint SHA-1 (`AA:BB:…`) del primo certificato di un PEM.
pub fn pem_sha1(pem: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(pem).ok()?;
    let start = text.find("-----BEGIN CERTIFICATE-----")? + "-----BEGIN CERTIFICATE-----".len();
    let end = start + text[start..].find("-----END CERTIFICATE-----")?;
    let b64: String = text[start..end].chars().filter(|c| !c.is_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let digest = Sha1::digest(&der);
    Some(
        digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Il contenuto di un blocco inline `<tag>…</tag>` di un `.ovpn`.
pub fn ovpn_inline(ovpn: &[u8], tag: &str) -> Option<String> {
    let text = std::str::from_utf8(ovpn).ok()?;
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = start + text[start..].find(&close)?;
    Some(text[start..end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un PEM di prova: basta che sia base64 valido, il fingerprint è solo un hash.
    const CA: &str = "-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUDEMDQ9i9cGPAL9RFyc5utN1C8aowCgYIKoZIzj0EAwIw
LzEtMCsGA1UEAwwkQnVzaW5lc3MgTmV0d29yayBXaXphcmQgdGVzdCBSQURJVVMw
HhcNMjYxMDAxMDAwMDAwWhcNMzYwOTI4MDAwMDAwWjAvMS0wKwYDVQQDDCRCdXNp
bmVzcyBOZXR3b3JrIFdpemFyZCB0ZXN0IFJBRElVUzBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABHUlL3JKq1ZJdW/Pk8l/cBJr1lRL2lSnQJ0F+r1HGuOU2sIc+L7p
mT1kp6WMXhqG3/9gEe0eZo/PBwJ5Nn6wWrijUzBRMB0GA1UdDgQWBBRm8L9b1Sv0
hR93YNgy7HzwmcrjqTAfBgNVHSMEGDAWgBRm8L9b1Sv0hR93YNgy7HzwmcrjqTAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCJBqzxhZ0E7pDGt9yV
2D3l6sd5rUx9hQ8yaP7MUvT3bAIgM9k5H9cN0ZQx7Qz4C2VWJ0L1ySwN6mZf8yqV
aWbQhUo=
-----END CERTIFICATE-----
";

    fn bundle() -> Bundle {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/esempio/profile.toml"
        ))
        .unwrap();
        let mut profile = Profile::from_toml(&text).unwrap();
        profile.wifi.as_mut().unwrap().ca_sha1 = pem_sha1(CA.as_bytes());
        let mut files = BTreeMap::new();
        files.insert(
            "vpn/Esempio.ovpn".into(),
            b"client\nremote vpn.example 1194\n<key>\nSEGNAPOSTO\n</key>\n".to_vec(),
        );
        files.insert("wifi/root-ca.pem".into(), CA.as_bytes().to_vec());
        Bundle { profile, files }
    }

    #[test]
    fn andata_e_ritorno() {
        let b = bundle();
        assert!(b.check().unwrap().is_empty());
        let enc = b.encrypt("passphrase lunga").unwrap();
        assert!(enc.starts_with(b"age-encryption.org/v1"));
        assert!(!enc.windows(10).any(|w| w == b"SEGNAPOSTO"));
        assert_eq!(Bundle::decrypt(&enc, "passphrase lunga").unwrap(), b);
        assert!(matches!(
            Bundle::decrypt(&enc, "passphrase sbagliata"),
            Err(BundleError::Decrypt)
        ));
        assert!(matches!(b.encrypt("corta"), Err(BundleError::WeakPassphrase)));
    }

    #[test]
    fn fingerprint_e_trappola_della_ca() {
        let mut b = bundle();
        b.profile.wifi.as_mut().unwrap().ca_sha1 = Some("00:".repeat(19) + "00");
        assert!(matches!(b.check(), Err(BundleError::Invalid(_))));
        let mut b = bundle();
        b.files.insert(
            "vpn/Esempio.ovpn".into(),
            format!("client\n<ca>\n{CA}</ca>\n<key>\nx\n</key>\n").into_bytes(),
        );
        assert!(b.check().unwrap().iter().any(|w| w.contains("stessa della VPN")));
        let mut b = bundle();
        b.files.insert("vpn/Esempio.ovpn".into(), b"client\n".to_vec());
        assert!(b.check().unwrap().iter().any(|w| w.contains("chiave privata")));
        b.files.remove("wifi/root-ca.pem");
        assert!(matches!(b.check(), Err(BundleError::Missing(_))));
    }

    #[test]
    fn tar_malevoli_rifiutati() {
        let tar_with = |name: &str| {
            let mut builder = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            let data = b"x";
            h.set_size(1);
            h.set_mode(0o600);
            h.set_entry_type(tar::EntryType::Regular);
            // set_path rifiuta «..»: si scrive il nome a mano, come farebbe un archivio ostile
            h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_cksum();
            builder.append(&h, &data[..]).unwrap();
            builder.into_inner().unwrap()
        };
        for name in ["../../etc/passwd", "/etc/passwd", "vpn/../../x"] {
            assert!(
                matches!(Bundle::from_tar(&tar_with(name)), Err(BundleError::Archive(_))),
                "{name}"
            );
        }
        // un file in più, non citato dal profilo
        let mut b = bundle();
        b.files.insert("altro.sh".into(), b"rm -rf".to_vec());
        assert!(Bundle::from_tar(&b.to_tar().unwrap()).is_err());
    }
}
