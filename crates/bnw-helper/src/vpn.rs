//! La VPN OpenVPN del profilo, con le correzioni di `install.sh`:
//! - l'importatore di NetworkManager mette `ns-cert-type` (deprecato) al posto di
//!   `remote-cert-tls` e aggiunge `challenge-response-flags` (un prompt interattivo);
//! - lascia `password-flags = 1`, "chiedi a un secret agent": su niri non ce n'è, e la
//!   VPN non salirebbe mai;
//! - il full-tunnel è voluto (`ipv4.never-default = no`).
//!
//! I blocchi inline dell'`.ovpn` diventano file in `/etc/bnw/vpn/<nome>/` (700 root)
//! prima dell'import, così non finiscono nella home di chi lancia l'importatore.

use std::collections::HashMap;

use bnw_core::action::Outcome;
use bnw_core::profile::Profile;
use bnw_core::{Secret, ovpn, validate};

use crate::nm::{self, Conn};
use crate::proxy::invalid;
use crate::{Ctx, NM_BACKUP_DIR};

const NMCLI: &str = "/usr/bin/nmcli";

/// Nome di cartella per una connessione: minuscole, cifre e trattini.
pub fn slug(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    s.trim_matches('-').to_string()
}

/// Scrive il profilo applicato in `/etc/bnw/profile.toml`.
pub(crate) fn save_profile(ctx: &mut Ctx, profile: &Profile) -> bool {
    match profile.to_toml() {
        Ok(t) => {
            let r = ctx.fs.write(crate::PROFILE_PATH, &t, 0o644);
            ctx.file(crate::PROFILE_PATH, r) != Outcome::Failed
        }
        Err(e) => {
            ctx.fail("profilo", e.to_string());
            false
        }
    }
}

/// Trova la connessione; con `--root` NetworkManager non si usa e lo si dice.
pub(crate) fn find(ctx: &mut Ctx, name: &str) -> Result<Option<Conn>, ()> {
    match ctx.nm.find(name) {
        Ok(c) => Ok(c),
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            ctx.report.push(
                format!("connessione «{name}»"),
                Outcome::Skipped,
                Some(e.to_string()),
            );
            Err(())
        }
        Err(e) => {
            ctx.fail(&format!("connessione «{name}»"), e.to_string());
            Err(())
        }
    }
}

pub fn apply(
    ctx: &mut Ctx,
    profile: &Profile,
    ovpn_data: Option<&[u8]>,
    reimport: bool,
    domain_user: Option<&str>,
    password: Option<&Secret>,
) {
    if let Err(e) = validate::profile(profile) {
        return invalid(ctx, "profilo", e);
    }
    if let Some(p) = password
        && let Err(e) = validate::password(p)
    {
        return invalid(ctx, "password", e);
    }
    if let Some(u) = domain_user
        && let Err(e) = validate::target(&bnw_core::Target {
            domain_user: u.into(),
            uid: 0,
            gid: 0,
        })
    {
        return invalid(ctx, "utenza", e);
    }
    let Some(vpn) = &profile.vpn else {
        return ctx.fail("VPN", "il profilo non ha una VPN");
    };
    if !save_profile(ctx, profile) {
        return;
    }
    let what = format!("VPN «{}»", vpn.name);

    // I file vanno scritti prima dell'import, che li cita per percorso.
    let dir = format!("/etc/bnw/vpn/{}", slug(&vpn.name));
    let ovpn_path = format!("{dir}/{}.ovpn", vpn.name);
    if let Some(data) = ovpn_data {
        let (text, files) = match ovpn::externalize(data, &dir) {
            Ok(x) => x,
            Err(e) => return ctx.fail(&what, format!(".ovpn non valido: {e}")),
        };
        if let Err(e) = ctx.fs.ensure_dir(&dir, 0o700) {
            return ctx.fail(&dir, e.to_string());
        }
        for f in &files {
            let p = format!("{dir}/{}", f.name);
            let r = ctx.fs.write(&p, &f.content, 0o600);
            if ctx.file(&p, r) == Outcome::Failed {
                return;
            }
        }
        let r = ctx.fs.write(&ovpn_path, &text, 0o600);
        if ctx.file(&ovpn_path, r) == Outcome::Failed {
            return;
        }
    }

    let Ok(existing) = find(ctx, &vpn.name) else {
        return;
    };
    let mut kept_secrets: HashMap<String, String> = HashMap::new();
    let mut imported = false;
    let conn = match existing {
        Some(c) if !reimport => c,
        other => {
            if ovpn_data.is_none() {
                return ctx.fail(&what, "connessione assente: serve il file .ovpn per importarla");
            }
            if let Some(old) = other {
                // la password salvata sopravvive alla reimportazione
                if let Ok(s) = ctx.nm.secrets(&old.path, "vpn") {
                    kept_secrets = nm::get_dict(&s, "vpn", "secrets");
                }
                if let Some(f) = &old.filename {
                    let _ = ctx.fs.backup_copy(f, NM_BACKUP_DIR);
                }
                if let Err(e) = ctx.nm.delete(&old.path) {
                    return ctx.fail(
                        &what,
                        format!("non riesco a togliere la vecchia connessione: {e}"),
                    );
                }
                ctx.report.push(
                    format!("{what}: connessione precedente"),
                    Outcome::Changed,
                    Some("tolta (backup in /etc/bnw/backup)".into()),
                );
            }
            let real = ctx.fs.path(&ovpn_path).to_string_lossy().into_owned();
            let import = ["connection", "import", "type", "openvpn", "file", &real];
            if ctx
                .cmd(&format!("{what}: import"), NMCLI, &import, None)
                .is_none()
            {
                return;
            }
            imported = true;
            match find(ctx, &vpn.name) {
                Ok(Some(c)) => c,
                Ok(None) => return ctx.fail(&what, "dopo l'import la connessione non c'è"),
                Err(()) => return,
            }
        }
    };

    let user = domain_user
        .map(str::to_string)
        .or_else(|| {
            nm::get_dict(&conn.settings, "vpn", "data")
                .get("username")
                .cloned()
        })
        .or_else(|| crate::password::user_from_files(ctx, profile));
    let mut settings = conn.settings;
    let changes = fix(&mut settings, user.as_deref(), vpn.full_tunnel);

    let mut secrets = if kept_secrets.is_empty() {
        ctx.nm
            .secrets(&conn.path, "vpn")
            .map(|s| nm::get_dict(&s, "vpn", "secrets"))
            .unwrap_or_default()
    } else {
        kept_secrets
    };
    let mut changes = changes;
    if let Some(p) = password {
        if secrets.get("password").map(String::as_str) != Some(p.expose()) {
            changes.push("password salvata".into());
        }
        secrets.insert("password".into(), p.expose().to_string());
    }
    if changes.is_empty() && !imported {
        ctx.report
            .push(what, Outcome::Unchanged, Some("già a posto".into()));
        return;
    }
    if !secrets.is_empty() {
        nm::set(&mut settings, "vpn", "secrets", nm::value(secrets));
    }
    if let Some(f) = &conn.filename {
        let _ = ctx.fs.backup_copy(f, NM_BACKUP_DIR);
    }
    match ctx.nm.update(&conn.path, &settings) {
        Ok(()) => {
            let detail = if changes.is_empty() {
                "importata".to_string()
            } else {
                changes.join(", ")
            };
            ctx.report.push(what, Outcome::Changed, Some(detail));
        }
        Err(e) => ctx.fail(&what, e.to_string()),
    }
}

/// Le correzioni sulle impostazioni; restituisce cosa è cambiato (mai valori segreti).
pub fn fix(settings: &mut nm::Settings, user: Option<&str>, full_tunnel: bool) -> Vec<String> {
    let mut data = nm::get_dict(settings, "vpn", "data");
    let mut changes = Vec::new();
    for (key, why) in [
        ("ns-cert-type", "tolto ns-cert-type (deprecato)"),
        ("challenge-response-flags", "tolto challenge-response-flags"),
    ] {
        if data.remove(key).is_some() {
            changes.push(why.to_string());
        }
    }
    for (key, want, why) in [
        ("remote-cert-tls", "server", "remote-cert-tls=server"),
        ("password-flags", "0", "password-flags=0 (niente secret agent)"),
    ] {
        if data.get(key).map(String::as_str) != Some(want) {
            data.insert(key.into(), want.into());
            changes.push(why.to_string());
        }
    }
    if let Some(u) = user
        && data.get("username").map(String::as_str) != Some(u)
    {
        data.insert("username".into(), u.into());
        changes.push(format!("utenza {u}"));
    }
    nm::set(settings, "vpn", "data", nm::value(data));
    let never_default = !full_tunnel;
    if nm::get_bool(settings, "ipv4", "never-default").unwrap_or(false) != never_default {
        nm::set(settings, "ipv4", "never-default", nm::value(never_default));
        changes.push(
            if full_tunnel {
                "full-tunnel"
            } else {
                "solo le reti aziendali in VPN"
            }
            .into(),
        );
    }
    changes
}
