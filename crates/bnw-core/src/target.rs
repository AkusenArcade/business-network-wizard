//! Ciò che dipende dalla macchina di destinazione e non sta nel profilo: l'utenza di
//! dominio e l'utente locale che possiede le share montate.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Utenza di dominio (`nome.cognome`), senza il dominio.
    pub domain_user: String,
    /// Utente locale a cui appartengono i file delle share CIFS.
    pub uid: u32,
    pub gid: u32,
}

/// Una stringa segreta: non compare mai in `Debug`, quindi nemmeno nei log. Si
/// serializza in chiaro solo per viaggiare sullo stdin dell'helper.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Contenuto di un file passato all'helper (un `.ovpn` con la chiave privata, una CA).
/// In `Debug` mostra solo la dimensione; in JSON viaggia come base64.
#[derive(Clone, PartialEq, Eq)]
pub struct Blob(pub Vec<u8>);

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob({} byte)", self.0.len())
    }
}

impl serde::Serialize for Blob {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Blob {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use base64::Engine;
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map(Blob)
            .map_err(serde::de::Error::custom)
    }
}
