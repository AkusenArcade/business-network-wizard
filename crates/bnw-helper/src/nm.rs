//! NetworkManager via D-Bus (`org.freedesktop.NetworkManager.Settings`). Le
//! impostazioni di una connessione sono un dizionario `a{sa{sv}}`: sezione → chiave →
//! valore. I segreti viaggiano solo qui dentro, mai su una riga di comando.

use std::collections::HashMap;
use std::io;

use zbus::blocking::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

pub type Settings = HashMap<String, HashMap<String, OwnedValue>>;

/// Una connessione salvata.
pub struct Conn {
    pub path: String,
    pub settings: Settings,
    /// Il keyfile su disco, se NetworkManager lo dice.
    pub filename: Option<String>,
}

pub trait Nm {
    /// La connessione con quel nome (`connection.id`).
    fn find(&mut self, id: &str) -> io::Result<Option<Conn>>;
    /// I segreti di una sezione (`vpn`, `802-1x`).
    fn secrets(&mut self, path: &str, setting: &str) -> io::Result<Settings>;
    /// Sostituisce tutte le impostazioni (segreti compresi: quelli che mancano si perdono).
    fn update(&mut self, path: &str, settings: &Settings) -> io::Result<()>;
    fn add(&mut self, settings: &Settings) -> io::Result<String>;
    fn delete(&mut self, path: &str) -> io::Result<()>;
}

/// Con `--root`: NetworkManager non si tocca.
pub struct NoNm;

impl Nm for NoNm {
    fn find(&mut self, _: &str) -> io::Result<Option<Conn>> {
        Err(unavailable())
    }
    fn secrets(&mut self, _: &str, _: &str) -> io::Result<Settings> {
        Err(unavailable())
    }
    fn update(&mut self, _: &str, _: &Settings) -> io::Result<()> {
        Err(unavailable())
    }
    fn add(&mut self, _: &Settings) -> io::Result<String> {
        Err(unavailable())
    }
    fn delete(&mut self, _: &str) -> io::Result<()> {
        Err(unavailable())
    }
}

fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "NetworkManager non usato (--root)")
}

const NM: &str = "org.freedesktop.NetworkManager";
const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const SETTINGS: &str = "org.freedesktop.NetworkManager.Settings";
const CONNECTION: &str = "org.freedesktop.NetworkManager.Settings.Connection";

pub struct RealNm {
    bus: Connection,
}

fn dbus(e: zbus::Error) -> io::Error {
    io::Error::other(format!("NetworkManager: {e}"))
}

impl RealNm {
    pub fn connect() -> io::Result<RealNm> {
        Ok(RealNm {
            bus: Connection::system().map_err(dbus)?,
        })
    }

    fn call<B, R>(&self, path: &str, iface: &str, method: &str, body: &B) -> io::Result<R>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
        R: for<'d> zbus::zvariant::DynamicDeserialize<'d>,
    {
        let reply = self
            .bus
            .call_method(Some(NM), path, Some(iface), method, body)
            .map_err(dbus)?;
        reply.body().deserialize::<R>().map_err(dbus)
    }
}

impl Nm for RealNm {
    fn find(&mut self, id: &str) -> io::Result<Option<Conn>> {
        let list: Vec<OwnedObjectPath> = self.call(SETTINGS_PATH, SETTINGS, "ListConnections", &())?;
        for p in list {
            let settings: Settings = self.call(p.as_str(), CONNECTION, "GetSettings", &())?;
            if get_str(&settings, "connection", "id").as_deref() == Some(id) {
                let props = zbus::blocking::fdo::PropertiesProxy::builder(&self.bus)
                    .destination(NM)
                    .map_err(dbus)?
                    .path(p.as_str())
                    .map_err(dbus)?
                    .build()
                    .map_err(dbus)?;
                let filename = props
                    .get(
                        zbus::names::InterfaceName::from_static_str(CONNECTION)
                            .map_err(|e| io::Error::other(e.to_string()))?,
                        "Filename",
                    )
                    .ok()
                    .and_then(|v| String::try_from(v).ok())
                    .filter(|f| !f.is_empty());
                return Ok(Some(Conn {
                    path: p.to_string(),
                    settings,
                    filename,
                }));
            }
        }
        Ok(None)
    }

    fn secrets(&mut self, path: &str, setting: &str) -> io::Result<Settings> {
        self.call(path, CONNECTION, "GetSecrets", &(setting,))
    }

    fn update(&mut self, path: &str, settings: &Settings) -> io::Result<()> {
        self.call::<_, ()>(path, CONNECTION, "Update", &(settings,))
    }

    fn add(&mut self, settings: &Settings) -> io::Result<String> {
        let p: OwnedObjectPath = self.call(SETTINGS_PATH, SETTINGS, "AddConnection", &(settings,))?;
        Ok(p.to_string())
    }

    fn delete(&mut self, path: &str) -> io::Result<()> {
        self.call::<_, ()>(path, CONNECTION, "Delete", &())
    }
}

// --- lettura e scrittura dei valori --------------------------------------------------

pub fn value<'a>(v: impl Into<Value<'a>>) -> OwnedValue {
    OwnedValue::try_from(v.into()).expect("nessun descrittore di file nei valori")
}

pub fn get<'a>(s: &'a Settings, section: &str, key: &str) -> Option<&'a OwnedValue> {
    s.get(section)?.get(key)
}

pub fn get_str(s: &Settings, section: &str, key: &str) -> Option<String> {
    get(s, section, key).and_then(|v| v.downcast_ref::<String>().ok())
}

pub fn get_bool(s: &Settings, section: &str, key: &str) -> Option<bool> {
    get(s, section, key).and_then(|v| v.downcast_ref::<bool>().ok())
}

pub fn get_u32(s: &Settings, section: &str, key: &str) -> Option<u32> {
    get(s, section, key).and_then(|v| v.downcast_ref::<u32>().ok())
}

pub fn get_bytes(s: &Settings, section: &str, key: &str) -> Option<Vec<u8>> {
    let v = get(s, section, key)?.try_clone().ok()?;
    Vec::<u8>::try_from(v).ok()
}

pub fn get_strs(s: &Settings, section: &str, key: &str) -> Option<Vec<String>> {
    let v = get(s, section, key)?.try_clone().ok()?;
    Vec::<String>::try_from(v).ok()
}

/// Un dizionario `a{ss}` (come `vpn.data` e `vpn.secrets`).
pub fn get_dict(s: &Settings, section: &str, key: &str) -> HashMap<String, String> {
    get(s, section, key)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| HashMap::<String, String>::try_from(v).ok())
        .unwrap_or_default()
}

pub fn set(s: &mut Settings, section: &str, key: &str, v: OwnedValue) {
    s.entry(section.to_string())
        .or_default()
        .insert(key.to_string(), v);
}

/// Il percorso di un certificato nel formato di NetworkManager (`file://…\0`).
pub fn cert_path_value(path: &str) -> OwnedValue {
    let mut bytes = format!("file://{path}").into_bytes();
    bytes.push(0);
    value(bytes)
}

/// Il percorso da un valore `file://…\0`.
pub fn cert_path(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?.trim_end_matches('\0');
    s.strip_prefix("file://").map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valori() {
        let mut s = Settings::new();
        set(&mut s, "connection", "id", value("Esempio"));
        set(&mut s, "connection", "autoconnect", value(false));
        let mut data = HashMap::new();
        data.insert("remote".to_string(), "x:443".to_string());
        set(&mut s, "vpn", "data", value(data.clone()));
        set(
            &mut s,
            "802-1x",
            "ca-cert",
            cert_path_value("/etc/bnw/wifi/ca.pem"),
        );
        set(&mut s, "802-1x", "eap", value(vec!["peap".to_string()]));
        assert_eq!(get_str(&s, "connection", "id").as_deref(), Some("Esempio"));
        assert_eq!(get_bool(&s, "connection", "autoconnect"), Some(false));
        assert_eq!(get_dict(&s, "vpn", "data"), data);
        assert_eq!(
            cert_path(&get_bytes(&s, "802-1x", "ca-cert").unwrap()).as_deref(),
            Some("/etc/bnw/wifi/ca.pem")
        );
        assert_eq!(get_strs(&s, "802-1x", "eap").unwrap(), ["peap"]);
    }
}
