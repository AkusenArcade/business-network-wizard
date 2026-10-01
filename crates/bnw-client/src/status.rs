//! Lettura dello stato: file (`active.conf`, forzatura, profilo), systemd e
//! NetworkManager via D-Bus, ultima decisione di `proxy-detect` dal journal.

use std::fs;
use std::process::Command;

use bnw_core::Profile;
use bnw_core::paths;
use bnw_core::status::{
    Connection, PrinterState, Route, ShareState, Status, cifs_mounts, parse_forced, parse_lpstat,
};
use zbus::blocking::Connection as Bus;
use zbus::blocking::fdo::PropertiesProxy;
use zbus::names::InterfaceName;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::Env;

/// Il profilo applicato, se c'è.
pub fn installed_profile(env: &Env) -> Option<Profile> {
    let text = fs::read_to_string(env.path(paths::PROFILE)).ok()?;
    Profile::from_toml(&text).ok()
}

pub fn read(env: &Env) -> Status {
    let profile = installed_profile(env);
    let mut st = Status {
        company: profile.as_ref().map(|p| p.company.name.clone()),
        route: fs::read_link(env.path(paths::ACTIVE_CONF))
            .ok()
            .and_then(|t| Route::from_target(&t.to_string_lossy())),
        forced: fs::read_to_string(env.path(paths::MANUAL))
            .ok()
            .and_then(|s| parse_forced(&s)),
        legacy: paths::LEGACY_FILES.iter().any(|f| env.path(f).exists()),
        last_decision: last_decision(),
        ..Default::default()
    };

    // D-Bus: se il bus di sistema non risponde lo stato resta parziale, non fallisce.
    if let Ok(bus) = Bus::system() {
        st.tinyproxy = unit_state(&bus, "tinyproxy.service");
        st.cntlm = unit_state(&bus, "cntlm.service");
        let active = active_connections(&bus);
        let conn = |name: &str| Connection {
            name: name.to_string(),
            active: active.iter().any(|a| a == name),
        };
        if let Some(p) = &profile {
            st.vpn = p.vpn.as_ref().map(|v| conn(&v.name));
            st.wifi = p.wifi.as_ref().map(|w| conn(&w.name));
        }
    }
    if let Some(p) = &profile {
        let mounts = cifs_mounts(&fs::read_to_string(env.path("/proc/mounts")).unwrap_or_default());
        st.shares = p
            .shares
            .iter()
            .map(|s| ShareState {
                mount: s.mount.clone(),
                unc: s.unc(),
                mounted: mounts.contains(&s.mount),
            })
            .collect();
        st.printers = p
            .printers
            .iter()
            .map(|pr| PrinterState {
                name: pr.name.clone(),
                state: printer_state(&pr.name),
            })
            .collect();
    }
    st
}

/// Lo stato di una coda CUPS (`lpstat -p`, in inglese per poterlo leggere).
fn printer_state(name: &str) -> Option<String> {
    let out = Command::new("lpstat")
        .args(["-p", name])
        .env("LANG", "C")
        .output()
        .ok()?;
    parse_lpstat(&String::from_utf8_lossy(&out.stdout))
}

fn prop(
    bus: &Bus,
    dest: &str,
    path: &OwnedObjectPath,
    iface: &'static str,
    name: &str,
) -> Option<OwnedValue> {
    let props = PropertiesProxy::builder(bus)
        .destination(dest)
        .ok()?
        .path(path.as_ref())
        .ok()?
        .build()
        .ok()?;
    props.get(InterfaceName::from_static_str(iface).ok()?, name).ok()
}

/// `ActiveState` della unit, o `non installato`.
fn unit_state(bus: &Bus, unit: &str) -> Option<String> {
    let reply = bus
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "LoadUnit",
            &(unit,),
        )
        .ok()?;
    let path: OwnedObjectPath = reply.body().deserialize().ok()?;
    let iface = "org.freedesktop.systemd1.Unit";
    let load: String = prop(bus, "org.freedesktop.systemd1", &path, iface, "LoadState")?
        .try_into()
        .ok()?;
    if load == "not-found" {
        return Some("non installato".into());
    }
    prop(bus, "org.freedesktop.systemd1", &path, iface, "ActiveState")?
        .try_into()
        .ok()
}

/// Nomi delle connessioni NetworkManager attive (stato "attivata").
fn active_connections(bus: &Bus) -> Vec<String> {
    const NM: &str = "org.freedesktop.NetworkManager";
    const ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
    let root = OwnedObjectPath::try_from("/org/freedesktop/NetworkManager").unwrap();
    let Some(list) = prop(bus, NM, &root, NM, "ActiveConnections") else {
        return Vec::new();
    };
    let Ok(paths): Result<Vec<OwnedObjectPath>, _> = list.try_into() else {
        return Vec::new();
    };
    paths
        .iter()
        .filter(|p| {
            prop(bus, NM, p, ACTIVE, "State").and_then(|v| u32::try_from(v).ok()) == Some(2) // ACTIVATED
        })
        .filter_map(|p| prop(bus, NM, p, ACTIVE, "Id")?.try_into().ok())
        .collect()
}

/// L'ultima riga di `proxy-detect` nel journal, senza la data.
fn last_decision() -> Option<String> {
    let out = Command::new("journalctl")
        .args(["-t", "proxy-detect", "-n", "1", "-o", "cat", "--no-pager", "-q"])
        .output()
        .ok()?;
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!line.is_empty()).then_some(line)
}

/// Rileva la rete adesso, senza cambiare niente (`proxy-detect --dry-run`: può
/// durare qualche secondo se il proxy aziendale non risponde).
pub fn detect_now(env: &Env) -> Result<String, String> {
    let script = [paths::PROXY_DETECT, "/usr/local/bin/proxy-detect"]
        .into_iter()
        .find(|p| env.path(p).exists())
        .ok_or("proxy-detect non installato")?;
    let mut cmd = Command::new(env.path(script));
    cmd.arg("--dry-run");
    if env.dev_root {
        cmd.env("BNW_TEST_ROOT", &env.root);
    }
    let out = cmd.output().map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() {
        Ok(text)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}
