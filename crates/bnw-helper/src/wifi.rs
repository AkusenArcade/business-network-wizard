//! Il WiFi aziendale 802.1X (PEAP o TTLS, fase 2 MSCHAPv2), costruito direttamente via
//! D-Bus. La CA del RADIUS è controllata sul fingerprint del profilo: è la trappola del
//! runbook, dove la CA della VPN sembrava giusta e non lo era.

use bnw_core::Secret;
use bnw_core::action::Outcome;
use bnw_core::bundle::pem_sha1;
use bnw_core::profile::{Eap, Phase2, Profile};
use bnw_core::validate;

use crate::nm::{self, Settings};
use crate::proxy::invalid;
use crate::vpn::{find, save_profile, slug};
use crate::{Ctx, NM_BACKUP_DIR};

fn new_uuid() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn apply(
    ctx: &mut Ctx,
    profile: &Profile,
    ca: Option<&[u8]>,
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
    let Some(w) = &profile.wifi else {
        return ctx.fail("WiFi", "il profilo non ha un WiFi aziendale");
    };
    let what = format!("WiFi «{}»", w.name);

    let new_fp = match ca {
        Some(data) => {
            match pem_sha1(data) {
                Some(fp) => {
                    if let Some(expected) = &w.ca_sha1
                        && !expected.eq_ignore_ascii_case(&fp)
                    {
                        return ctx.fail(
                        &what,
                        format!("la CA scelta ha fingerprint {fp}, il profilo si aspetta {expected}: non la uso"),
                    );
                    }
                    Some(fp)
                }
                None => return ctx.fail(&what, "la CA non è un certificato PEM leggibile"),
            }
        }
        None => None,
    };
    if !save_profile(ctx, profile) {
        return;
    }

    let existing = match find(ctx, &w.name) {
        Ok(c) => c,
        Err(()) => {
            // con --root si scrive comunque la CA, per vedere dove andrebbe
            if let Some(data) = ca {
                write_ca(ctx, &w.name, data);
            }
            return;
        }
    };

    // La CA: si tiene quella attuale se ha già il fingerprint giusto.
    let current_ca = existing
        .as_ref()
        .and_then(|c| nm::get_bytes(&c.settings, "802-1x", "ca-cert"))
        .and_then(|b| nm::cert_path(&b));
    let current_fp = current_ca
        .as_deref()
        .and_then(|p| std::fs::read(ctx.fs.path(p)).ok())
        .and_then(|d| pem_sha1(&d));
    let ca_path = match (ca, &new_fp) {
        (Some(data), Some(fp)) => {
            if current_fp.as_ref() == Some(fp) {
                current_ca
                    .clone()
                    .expect("c'è un fingerprint, quindi un percorso")
            } else {
                match write_ca(ctx, &w.name, data) {
                    Some(p) => p,
                    None => return,
                }
            }
        }
        _ => {
            let Some(path) = current_ca.clone() else {
                return ctx.fail(&what, "serve la CA del RADIUS per creare la connessione");
            };
            if let (Some(expected), Some(fp)) = (&w.ca_sha1, &current_fp)
                && !expected.eq_ignore_ascii_case(fp)
            {
                return ctx.fail(
                    &what,
                    format!("la CA attuale ({path}) ha fingerprint {fp}, il profilo si aspetta {expected}: sostituiscila"),
                );
            }
            path
        }
    };

    let user = domain_user
        .map(str::to_string)
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|c| nm::get_str(&c.settings, "802-1x", "identity"))
        })
        .or_else(|| crate::password::user_from_files(ctx, profile));
    let Some(user) = user else {
        return ctx.fail(&what, "utenza di dominio sconosciuta");
    };

    let mut settings = existing.as_ref().map(|c| c.settings.clone()).unwrap_or_default();
    let mut changes = desired(&mut settings, profile, &ca_path, &user);
    if existing.is_none() {
        nm::set(&mut settings, "connection", "uuid", nm::value(new_uuid()));
        nm::set(
            &mut settings,
            "802-11-wireless",
            "mode",
            nm::value("infrastructure"),
        );
        nm::set(&mut settings, "ipv4", "method", nm::value("auto"));
        nm::set(&mut settings, "ipv6", "method", nm::value("auto"));
    }

    // la password: quella nuova, oppure si conserva quella salvata
    let mut pw = match &existing {
        Some(c) => ctx
            .nm
            .secrets(&c.path, "802-1x")
            .ok()
            .and_then(|s| nm::get_str(&s, "802-1x", "password")),
        None => None,
    };
    if let Some(p) = password {
        if pw.as_deref() != Some(p.expose()) {
            changes.push("password salvata".into());
        }
        pw = Some(p.expose().to_string());
    }
    if let Some(p) = pw {
        nm::set(&mut settings, "802-1x", "password", nm::value(p));
    }

    match existing {
        None => match ctx.nm.add(&settings) {
            Ok(_) => ctx.report.push(what, Outcome::Changed, Some("creata".into())),
            Err(e) => ctx.fail(&what, e.to_string()),
        },
        Some(_) if changes.is_empty() => {
            ctx.report
                .push(what, Outcome::Unchanged, Some("già a posto".into()))
        }
        Some(c) => {
            if let Some(f) = &c.filename {
                let _ = ctx.fs.backup_copy(f, NM_BACKUP_DIR);
            }
            match ctx.nm.update(&c.path, &settings) {
                Ok(()) => ctx.report.push(what, Outcome::Changed, Some(changes.join(", "))),
                Err(e) => ctx.fail(&what, e.to_string()),
            }
        }
    }
}

/// La CA in `/etc/bnw/wifi/<nome>/ca.pem` (644: è un certificato pubblico).
fn write_ca(ctx: &mut Ctx, name: &str, data: &[u8]) -> Option<String> {
    let Ok(text) = std::str::from_utf8(data) else {
        ctx.fail("CA del WiFi", "non è testo PEM");
        return None;
    };
    let dir = format!("/etc/bnw/wifi/{}", slug(name));
    let path = format!("{dir}/ca.pem");
    if let Err(e) = ctx.fs.ensure_dir(&dir, 0o755) {
        ctx.fail(&dir, e.to_string());
        return None;
    }
    let r = ctx.fs.write(&path, text, 0o644);
    (ctx.file(&path, r) != Outcome::Failed).then_some(path)
}

/// Porta le chiavi del profilo nelle impostazioni; restituisce cosa è cambiato.
pub fn desired(s: &mut Settings, profile: &Profile, ca_path: &str, user: &str) -> Vec<String> {
    let w = profile.wifi.as_ref().expect("profilo con WiFi");
    let mut changes = Vec::new();
    let mut put_str = |s: &mut Settings, sec: &str, key: &str, v: &str, label: &str| {
        if nm::get_str(s, sec, key).as_deref() != Some(v) {
            nm::set(s, sec, key, nm::value(v.to_string()));
            changes.push(label.to_string());
        }
    };
    put_str(s, "connection", "id", &w.name, "nome");
    put_str(s, "connection", "type", "802-11-wireless", "tipo");
    put_str(
        s,
        "802-11-wireless-security",
        "key-mgmt",
        "wpa-eap",
        "WPA-Enterprise",
    );
    let phase2 = match w.phase2 {
        Phase2::Mschapv2 => "mschapv2",
    };
    put_str(s, "802-1x", "phase2-auth", phase2, "fase 2");
    put_str(s, "802-1x", "identity", user, "utenza");
    put_str(
        s,
        "802-1x",
        "domain-suffix-match",
        &w.domain_suffix_match,
        "domain-suffix-match",
    );

    if nm::get_bytes(s, "802-11-wireless", "ssid").as_deref() != Some(w.ssid.as_bytes()) {
        nm::set(
            s,
            "802-11-wireless",
            "ssid",
            nm::value(w.ssid.as_bytes().to_vec()),
        );
        changes.push("SSID".into());
    }
    let eap = match w.eap {
        Eap::Peap => "peap",
        Eap::Ttls => "ttls",
    };
    if nm::get_strs(s, "802-1x", "eap").as_deref() != Some(&[eap.to_string()][..]) {
        nm::set(s, "802-1x", "eap", nm::value(vec![eap.to_string()]));
        changes.push("EAP".into());
    }
    if nm::get_bytes(s, "802-1x", "ca-cert")
        .and_then(|b| nm::cert_path(&b))
        .as_deref()
        != Some(ca_path)
    {
        nm::set(s, "802-1x", "ca-cert", nm::cert_path_value(ca_path));
        changes.push(format!("CA {ca_path}"));
    }
    if nm::get_bool(s, "802-1x", "system-ca-certs").unwrap_or(false) {
        nm::set(s, "802-1x", "system-ca-certs", nm::value(false));
        changes.push("niente CA di sistema".into());
    }
    if nm::get_u32(s, "802-1x", "password-flags").unwrap_or(0) != 0 {
        nm::set(s, "802-1x", "password-flags", nm::value(0u32));
        changes.push("password-flags=0".into());
    }
    if nm::get_bool(s, "connection", "autoconnect").unwrap_or(true) != w.autoconnect {
        nm::set(s, "connection", "autoconnect", nm::value(w.autoconnect));
        changes.push(
            if w.autoconnect {
                "connessione automatica"
            } else {
                "niente connessione automatica"
            }
            .into(),
        );
    }
    changes
}
