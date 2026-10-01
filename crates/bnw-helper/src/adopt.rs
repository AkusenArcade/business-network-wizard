//! "Adotta configurazione esistente": una macchina configurata a mano (con il kit
//! `install.sh`) passa all'app senza cambiare comportamento.

use bnw_core::action::Outcome;
use bnw_core::paths::{LEGACY_FILES, PACKAGE_FILES};
use bnw_core::{Profile, validate};

use crate::{Ctx, DETECT_SERVICE, SYSTEMCTL, proxy};

pub fn adopt(ctx: &mut Ctx, profile: &Profile) {
    if let Err(e) = validate::profile(profile) {
        let msg = e.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ");
        return ctx.fail("profilo", msg);
    }
    let missing: Vec<&str> = PACKAGE_FILES
        .iter()
        .copied()
        .filter(|f| !ctx.fs.exists(f))
        .collect();
    if !missing.is_empty() {
        return ctx.fail(
            "file del pacchetto",
            format!("mancano {}: installa prima il pacchetto", missing.join(", ")),
        );
    }

    // Prima i file nuovi (profilo, proxy-detect.conf…), che gli script del pacchetto
    // leggono; poi via quelli vecchi. cntlm.conf resta esattamente com'è.
    proxy::apply(ctx, profile, proxy::CntlmConf::Keep);
    if ctx.report.failed() {
        return;
    }

    let mut retired = false;
    for f in LEGACY_FILES {
        match ctx.fs.retire(f) {
            Ok(Outcome::Skipped) => {}
            Ok(o) => {
                retired = true;
                ctx.report.push(f, o, Some("messo da parte (.bak)".into()));
            }
            Err(e) => ctx.fail(f, e.to_string()),
        }
        match ctx.fs.disarm_backups(f) {
            Ok(names) if !names.is_empty() => ctx.report.push(
                f,
                Outcome::Changed,
                Some(format!(
                    "tolta l'esecuzione ai vecchi backup: {}",
                    names.join(", ")
                )),
            ),
            Ok(_) => {}
            Err(e) => ctx.fail(f, e.to_string()),
        }
    }
    if !retired {
        return;
    }
    ctx.cmd("systemd ricaricato", SYSTEMCTL, &["daemon-reload"], None);
    // il drop-in di tinyproxy ora è quello del pacchetto
    ctx.cmd(
        "tinyproxy riavviato",
        SYSTEMCTL,
        &["restart", "tinyproxy.service"],
        None,
    );
    ctx.cmd(
        "rilevazione della rete",
        SYSTEMCTL,
        &["start", DETECT_SERVICE],
        None,
    );
}
