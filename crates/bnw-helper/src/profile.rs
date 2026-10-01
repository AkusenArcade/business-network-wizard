//! Un profilo intero, in una sola azione: per l'import, la prima configurazione e il
//! passaggio da un profilo a un altro (per esempio un'azienda che cambia dominio).
//!
//! Il profilo applicato prima si legge una volta sola, all'inizio: le azioni delle
//! singole parti salvano il profilo nuovo, e dopo la prima non si saprebbe più cosa
//! c'era.

use bnw_core::action::Outcome;
use bnw_core::profile::Profile;
use bnw_core::render::cifs;
use bnw_core::validate;

use crate::proxy::{self, invalid};
use crate::shares::previous_profile;
use crate::vpn::slug;
use crate::{Ctx, NM_BACKUP_DIR, printers, shares, vpn, wifi};

pub fn apply(
    ctx: &mut Ctx,
    profile: &Profile,
    ovpn: Option<&[u8]>,
    ca: Option<&[u8]>,
    domain_user: Option<&str>,
    owner_uid: Option<u32>,
) {
    if let Err(e) = validate::profile(profile) {
        return invalid(ctx, "profilo", e);
    }
    let previous = previous_profile(ctx);
    if let Some(old) = &previous {
        remove_old(ctx, old, profile);
    }

    proxy::apply(ctx, profile, proxy::CntlmConf::Update);
    if profile.vpn.is_some() {
        vpn::apply(ctx, profile, ovpn, false, domain_user, None);
    }
    if profile.wifi.is_some() {
        wifi::apply(ctx, profile, ca, domain_user, None);
    }
    let old_shares = previous.as_ref().map(|p| p.shares.clone()).unwrap_or_default();
    shares::apply_with(ctx, profile, owner_uid, &old_shares);
    let old_printers = previous.as_ref().map(|p| p.printers.clone()).unwrap_or_default();
    printers::apply_with(ctx, profile, &old_printers);
}

/// Toglie dal profilo vecchio quello che nel nuovo non c'è più: la VPN e il WiFi con un
/// altro nome (connessione, file estratti) e le credenziali dei dischi di un'altra
/// azienda. Dischi e stampanti li toglie `apply_with`.
fn remove_old(ctx: &mut Ctx, old: &Profile, new: &Profile) {
    if let Some(v) = &old.vpn
        && new.vpn.as_ref().map(|n| &n.name) != Some(&v.name)
    {
        remove_connection(ctx, &v.name, "VPN");
        remove_dir(ctx, &format!("/etc/bnw/vpn/{}", slug(&v.name)));
    }
    if let Some(w) = &old.wifi
        && new.wifi.as_ref().map(|n| &n.name) != Some(&w.name)
    {
        remove_connection(ctx, &w.name, "WiFi");
        remove_dir(ctx, &format!("/etc/bnw/wifi/{}", slug(&w.name)));
    }
    let old_cred = cifs::credentials_path(old);
    if old_cred != cifs::credentials_path(new) && ctx.fs.exists(&old_cred) {
        let done = ctx
            .fs
            .backup_copy(&old_cred, "/etc/bnw/backup/samba")
            .and_then(|()| ctx.fs.remove(&old_cred));
        match done {
            Ok(()) => ctx.report.push(
                old_cred,
                Outcome::Changed,
                Some("credenziali del profilo precedente tolte".into()),
            ),
            Err(e) => ctx.fail(&old_cred, e.to_string()),
        }
    }
}

fn remove_connection(ctx: &mut Ctx, name: &str, kind: &str) {
    let what = format!("{kind} «{name}» del profilo precedente");
    match ctx.nm.find(name) {
        Ok(Some(c)) => {
            if let Some(f) = &c.filename {
                let _ = ctx.fs.backup_copy(f, NM_BACKUP_DIR);
            }
            match ctx.nm.delete(&c.path) {
                Ok(()) => ctx.report.push(
                    what,
                    Outcome::Changed,
                    Some("tolta (backup in /etc/bnw/backup)".into()),
                ),
                Err(e) => ctx.fail(&what, e.to_string()),
            }
        }
        Ok(None) => {}
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            ctx.report.push(what, Outcome::Skipped, Some(e.to_string()));
        }
        Err(e) => ctx.fail(&what, e.to_string()),
    }
}

fn remove_dir(ctx: &mut Ctx, dir: &str) {
    match ctx.fs.remove_tree(dir) {
        Ok(true) => ctx.report.push(dir, Outcome::Changed, Some("tolta".into())),
        Ok(false) => {}
        Err(e) => ctx.fail(dir, e.to_string()),
    }
}
