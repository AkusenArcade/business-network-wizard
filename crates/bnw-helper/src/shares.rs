//! Dischi di rete: per ogni share una coppia `.mount` + `.automount` in
//! `/etc/systemd/system`, la cartella sotto `/mnt` e l'automount attivo. Montano al
//! primo accesso e si smontano dopo 10 minuti di inattività.
//!
//! L'helper toglie solo le share che conosce: quelle del profilo applicato prima di
//! questo. Unit e cartelle messe da altri non si toccano.

use bnw_core::action::Outcome;
use bnw_core::profile::{Profile, Share};
use bnw_core::render::cifs;
use bnw_core::status::cifs_mounts;
use bnw_core::{Target, systemd, validate};

use crate::proxy::invalid;
use crate::vpn::save_profile;
use crate::{Ctx, SYSTEMCTL};

const UNIT_DIR: &str = "/etc/systemd/system";
const UNIT_BACKUP_DIR: &str = "/etc/bnw/backup/systemd";

/// Il profilo applicato prima di questa azione, se c'è (senza segnalare errori).
pub(crate) fn previous_profile(ctx: &Ctx) -> Option<Profile> {
    let text = ctx.fs.read(crate::PROFILE_PATH).ok()??;
    Profile::from_toml(&text).ok()
}

/// L'utente che possiede i file montati: chi ha chiesto l'azione. Sotto pkexec è
/// `PKEXEC_UID`, che non si può falsificare dall'azione JSON.
fn owner(ctx: &Ctx, owner_uid: Option<u32>) -> Result<(u32, u32), String> {
    let uid = std::env::var("PKEXEC_UID")
        .ok()
        .and_then(|u| u.parse().ok())
        .or(owner_uid)
        .ok_or("utente proprietario dei dischi sconosciuto")?;
    let passwd = ctx.fs.read("/etc/passwd").ok().flatten().unwrap_or_default();
    let gid = passwd
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 3 && f[2].parse() == Ok(uid))
                .then(|| f[3].parse().ok())
                .flatten()
        })
        .ok_or_else(|| format!("utente {uid} non trovato in /etc/passwd"))?;
    Ok((uid, gid))
}

fn unit_path(name: &str) -> String {
    format!("{UNIT_DIR}/{name}")
}

/// Le unit hanno il backup fuori da `/etc/systemd/system`.
fn write_unit(ctx: &mut Ctx, name: &str, content: &str) -> Outcome {
    let path = unit_path(name);
    let r = ctx
        .fs
        .write_backup_in(&path, content, 0o644, Some(UNIT_BACKUP_DIR));
    ctx.file(&path, r)
}

fn active(ctx: &mut Ctx, unit: &str) -> bool {
    ctx.run
        .run(SYSTEMCTL, &["is-active", "--quiet", unit], None)
        .is_ok_and(|o| o.success)
}

pub fn apply(ctx: &mut Ctx, profile: &Profile, owner_uid: Option<u32>) {
    let previous = previous_profile(ctx).map(|p| p.shares).unwrap_or_default();
    apply_with(ctx, profile, owner_uid, &previous);
}

/// Come [`apply`], con le share "di prima" passate da chi chiama (l'applicazione di
/// un profilo intero legge il profilo precedente una volta sola, all'inizio).
pub fn apply_with(ctx: &mut Ctx, profile: &Profile, owner_uid: Option<u32>, previous: &[Share]) {
    if let Err(e) = validate::profile(profile) {
        return invalid(ctx, "profilo", e);
    }
    let (uid, gid) = match owner(ctx, owner_uid) {
        Ok(x) => x,
        Err(e) => return ctx.fail("dischi di rete", e),
    };
    if !save_profile(ctx, profile) {
        return;
    }
    let target = Target {
        domain_user: String::new(),
        uid,
        gid,
    };

    let mut reload = false;
    let mut to_enable = Vec::new();
    let mut to_unmount = Vec::new();
    for share in &profile.shares {
        let mount = cifs::mount_unit(profile, &target, share);
        let automount = cifs::automount_unit(share);
        let m = write_unit(ctx, &mount.name, &mount.content);
        let a = write_unit(ctx, &automount.name, &automount.content);
        if let Err(e) = ctx.fs.ensure_dir(&share.mount, 0o755) {
            ctx.fail(&share.mount, e.to_string());
        }
        if m == Outcome::Changed || a == Outcome::Changed {
            reload = true;
            to_enable.push(automount.name.clone());
            if m == Outcome::Changed {
                // con opzioni nuove si rimonta al prossimo accesso
                to_unmount.push(mount.name.clone());
            }
        } else if !active(ctx, &automount.name) {
            to_enable.push(automount.name.clone());
        }
    }

    let kept: Vec<&str> = profile.shares.iter().map(|s| s.mount.as_str()).collect();
    let removed: Vec<&Share> = previous
        .iter()
        .filter(|s| !kept.contains(&s.mount.as_str()))
        .collect();
    for share in &removed {
        remove(ctx, share);
        reload = true;
    }

    if reload {
        ctx.cmd("systemd ricaricato", SYSTEMCTL, &["daemon-reload"], None);
    }
    let mounted = cifs_mounts(&ctx.fs.read("/proc/mounts").ok().flatten().unwrap_or_default());
    for unit in to_unmount {
        let share = profile
            .shares
            .iter()
            .find(|s| systemd::mount_unit(&s.mount) == unit);
        if share.is_some_and(|s| mounted.contains(&s.mount)) {
            ctx.cmd(
                &format!("{unit} smontata (opzioni nuove)"),
                SYSTEMCTL,
                &["stop", &unit],
                None,
            );
        }
    }
    for unit in to_enable {
        ctx.cmd(
            &format!("{unit} attivo"),
            SYSTEMCTL,
            &["enable", "--now", &unit],
            None,
        );
    }

    if !profile.shares.is_empty() {
        let cred = cifs::credentials_path(profile);
        if !ctx.fs.exists(&cred) {
            ctx.report.push(
                cred,
                Outcome::Skipped,
                Some("manca la password dei dischi: aggiornala dalla pagina Password".into()),
            );
        }
    }
}

/// Toglie una share: ferma e disattiva le unit, le cancella (con backup) e toglie la
/// cartella se è vuota.
fn remove(ctx: &mut Ctx, share: &Share) {
    let mount = systemd::mount_unit(&share.mount);
    let automount = systemd::automount_unit(&share.mount);
    ctx.cmd(
        &format!("{automount} fermato"),
        SYSTEMCTL,
        &["disable", "--now", &automount],
        None,
    );
    ctx.cmd(&format!("{mount} smontata"), SYSTEMCTL, &["stop", &mount], None);
    for unit in [&mount, &automount] {
        let path = unit_path(unit);
        let done = ctx
            .fs
            .backup_copy(&path, UNIT_BACKUP_DIR)
            .and_then(|()| ctx.fs.remove(&path));
        match done {
            Ok(()) => ctx.report.push(
                path,
                Outcome::Changed,
                Some("tolta (backup in /etc/bnw/backup)".into()),
            ),
            Err(e) => ctx.fail(&path, e.to_string()),
        }
    }
    // solo se vuota: una cartella con dentro qualcosa non è più roba nostra
    if std::fs::remove_dir(ctx.fs.path(&share.mount)).is_ok() {
        ctx.report.push(
            share.mount.clone(),
            Outcome::Changed,
            Some("cartella vuota tolta".into()),
        );
    }
}

/// Smonta adesso le share del profilo montate.
pub fn unmount(ctx: &mut Ctx) {
    let Some(profile) = previous_profile(ctx) else {
        return ctx.fail("dischi di rete", "nessun profilo applicato");
    };
    let mounted = cifs_mounts(&ctx.fs.read("/proc/mounts").ok().flatten().unwrap_or_default());
    let mut any = false;
    for share in &profile.shares {
        if mounted.contains(&share.mount) {
            any = true;
            let unit = systemd::mount_unit(&share.mount);
            ctx.cmd(
                &format!("{} smontata", share.mount),
                SYSTEMCTL,
                &["stop", &unit],
                None,
            );
        }
    }
    if !any {
        ctx.report.push(
            "dischi di rete",
            Outcome::Unchanged,
            Some("nessuna share montata".into()),
        );
    }
}
