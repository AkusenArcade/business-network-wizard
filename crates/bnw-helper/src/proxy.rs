//! Azioni del proxy: catena tinyproxy → cntlm, `/etc/environment`, browser, modalità.

use bnw_core::action::{Outcome, ProxyMode};
use bnw_core::render::{browser, cntlm, detect, environment, tinyproxy};
use bnw_core::{Profile, Secret, Target, validate};

use crate::{CNTLM, Ctx, DETECT_SERVICE, PROFILE_PATH, PROXY_MODE, SYSTEMCTL};

const CNTLM_CONF: &str = "/etc/cntlm.conf";
const DIRECT_CONF: &str = "/etc/tinyproxy/direct.conf";
const UPSTREAM_CONF: &str = "/etc/tinyproxy/upstream.conf";
const ACTIVE_CONF: &str = "/etc/tinyproxy/active.conf";
const ENVIRONMENT: &str = "/etc/environment";

pub(crate) fn invalid(ctx: &mut Ctx, what: &str, errors: Vec<validate::Invalid>) {
    let msg = errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    ctx.fail(what, msg);
}

/// Cosa fare di un `cntlm.conf` già presente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CntlmConf {
    /// Rigenera le impostazioni dal profilo, tenendo utenza e hash.
    Update,
    /// Lascialo com'è (adozione: la configurazione esistente non si tocca).
    Keep,
}

pub fn apply(ctx: &mut Ctx, profile: &Profile, cntlm_conf: CntlmConf) {
    if let Err(e) = validate::profile(profile) {
        return invalid(ctx, "profilo", e);
    }
    let toml = match profile.to_toml() {
        Ok(t) => t,
        Err(e) => return ctx.fail("profilo", e.to_string()),
    };
    ctx.file(PROFILE_PATH, ctx.fs.write(PROFILE_PATH, &toml, 0o644));
    let detect_changed = ctx.file(
        detect::PATH,
        ctx.fs
            .write(detect::PATH, &detect::proxy_detect_conf(profile), 0o644),
    );

    let direct = ctx.file(
        DIRECT_CONF,
        ctx.fs
            .write(DIRECT_CONF, &tinyproxy::direct_conf(&profile.proxy), 0o644),
    );
    let upstream = ctx.file(
        UPSTREAM_CONF,
        ctx.fs
            .write(UPSTREAM_CONF, &tinyproxy::upstream_conf(&profile.proxy), 0o644),
    );
    // Si parte sempre in diretto: se la rilevazione fallisce la macchina ha rete.
    ctx.file(ACTIVE_CONF, ctx.fs.symlink_if_missing(ACTIVE_CONF, DIRECT_CONF));

    let cntlm_changed = match ctx.fs.read(CNTLM_CONF) {
        Ok(Some(_)) if cntlm_conf == CntlmConf::Keep => {
            ctx.report
                .push(CNTLM_CONF, Outcome::Unchanged, Some("lasciato com'è".into()));
            Outcome::Unchanged
        }
        Ok(Some(old)) => match cntlm::update_settings(&old, profile) {
            Some(new) => ctx.file(CNTLM_CONF, ctx.fs.write(CNTLM_CONF, &new, 0o600)),
            None => {
                ctx.report.push(
                    CNTLM_CONF,
                    Outcome::Skipped,
                    Some("senza utenza o hash: serve la prima configurazione con la password".into()),
                );
                Outcome::Skipped
            }
        },
        Ok(None) => {
            ctx.report.push(
                CNTLM_CONF,
                Outcome::Skipped,
                Some("non ancora configurato".into()),
            );
            Outcome::Skipped
        }
        Err(e) => {
            ctx.fail(CNTLM_CONF, e.to_string());
            Outcome::Failed
        }
    };

    match ctx.fs.read(ENVIRONMENT) {
        Ok(old) => {
            let new = environment::merge(old.as_deref().unwrap_or(""), profile.proxy.local_port);
            ctx.file(ENVIRONMENT, ctx.fs.write(ENVIRONMENT, &new, 0o644));
        }
        Err(e) => ctx.fail(ENVIRONMENT, e.to_string()),
    }

    // Solo i percorsi in /etc: quello di Zen sotto /opt appartiene al pacchetto e lo
    // sovrascrivono gli aggiornamenti.
    for path in profile.proxy.browsers.iter().map(|b| b.policy_path()) {
        match ctx.fs.read(path) {
            Ok(old) => {
                let merged = browser::merge(old.as_deref(), profile.proxy.local_port);
                match ctx.fs.write(path, &merged.content, 0o644) {
                    Ok(o) => ctx.report.push(path, o, merged.warning),
                    Err(e) => ctx.fail(path, e.to_string()),
                }
            }
            Err(e) => ctx.fail(path, e.to_string()),
        }
    }

    ctx.cmd(
        "tinyproxy abilitato",
        SYSTEMCTL,
        &["enable", "--now", "tinyproxy.service"],
        None,
    );
    // cntlm non va abilitato: lo accende proxy-detect solo quando serve
    ctx.cmd(
        "cntlm non abilitato all'avvio",
        SYSTEMCTL,
        &["disable", "cntlm.service"],
        None,
    );
    if [direct, upstream, detect_changed].contains(&Outcome::Changed) {
        // l'ExecStartPre del drop-in rifà la rilevazione prima di ripartire
        ctx.cmd(
            "tinyproxy riavviato",
            SYSTEMCTL,
            &["restart", "tinyproxy.service"],
            None,
        );
    }
    if cntlm_changed == Outcome::Changed {
        ctx.cmd(
            "cntlm riavviato se attivo",
            SYSTEMCTL,
            &["try-restart", "cntlm.service"],
            None,
        );
    }
    ctx.cmd(
        "rilevazione della rete",
        SYSTEMCTL,
        &["start", DETECT_SERVICE],
        None,
    );
}

pub(crate) fn installed_profile(ctx: &mut Ctx) -> Option<Profile> {
    let text = match ctx.fs.read(PROFILE_PATH) {
        Ok(Some(t)) => t,
        Ok(None) => {
            ctx.fail(PROFILE_PATH, "profilo non ancora applicato");
            return None;
        }
        Err(e) => {
            ctx.fail(PROFILE_PATH, e.to_string());
            return None;
        }
    };
    match Profile::from_toml(&text) {
        Ok(p) => match validate::profile(&p) {
            Ok(()) => Some(p),
            Err(e) => {
                invalid(ctx, PROFILE_PATH, e);
                None
            }
        },
        Err(e) => {
            ctx.fail(PROFILE_PATH, e.to_string());
            None
        }
    }
}

/// Prima configurazione di cntlm. Non lo riavvia: chi chiama fa la verifica NTLM
/// (e la rilevazione) subito dopo, così un 407 si vede prima che cntlm ritenti.
pub fn write_cntlm(ctx: &mut Ctx, domain_user: &str, password: &Secret) {
    let target = Target {
        domain_user: domain_user.to_string(),
        uid: 0,
        gid: 0,
    };
    if let Err(e) = validate::target(&target) {
        return invalid(ctx, "utenza", e);
    }
    if let Err(e) = validate::password(password) {
        return invalid(ctx, "password", e);
    }
    let Some(profile) = installed_profile(ctx) else {
        return;
    };

    // Prima di tutto fermarlo: con gli hash vecchi ritenta a ogni richiesta (407) e il
    // dominio blocca l'account.
    if ctx
        .cmd("cntlm fermato", SYSTEMCTL, &["stop", "cntlm.service"], None)
        .is_none()
    {
        return;
    }
    let domain = profile.company.domain.clone();
    let input = format!("{}\n", password.expose());
    let Some(out) = ctx.cmd(
        "hash NTLM calcolati",
        CNTLM,
        &["-H", "-c", "/dev/null", "-u", domain_user, "-d", &domain],
        Some(&input),
    ) else {
        return;
    };
    let hashes = match cntlm::parse_hash_output(&out.stdout) {
        Ok(h) => h,
        Err(e) => return ctx.fail("hash NTLM calcolati", e.to_string()),
    };
    let content = cntlm::cntlm_conf(&profile, domain_user, &hashes);
    ctx.file(CNTLM_CONF, ctx.fs.write(CNTLM_CONF, &content, 0o600));
}

pub fn set_mode(ctx: &mut Ctx, mode: ProxyMode) {
    ctx.cmd(
        &format!("proxy-mode {}", mode.as_str()),
        PROXY_MODE,
        &[mode.as_str()],
        None,
    );
}
