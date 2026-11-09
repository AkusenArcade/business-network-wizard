//! Password di dominio: un valore, quattro posti (VPN, WiFi, cntlm, CIFS).
//!
//! L'ordine è quello di `cambia-password-dominio.sh`, collaudato:
//! 1. cntlm fermo prima di tutto (lo ferma già `StopCntlm`, prima che l'utente scriva
//!    la password; qui lo si rifà per sicurezza);
//! 2. si calcolano gli hash e si scrivono cntlm, VPN, WiFi e CIFS, ognuno con il suo
//!    `.bak-<data>`; se un posto fallisce gli altri vanno avanti e il rapporto dice
//!    quale;
//! 3. si smontano le share CIFS montate, che tengono in memoria la password vecchia;
//! 4. se la rete attuale vuole il proxy aziendale, si riaccende cntlm e si prova
//!    l'NTLM verso l'esterno: con un 407 cntlm si ferma subito.
//!
//! I secret di NetworkManager si scrivono nel keyfile e poi `nmcli connection reload`,
//! come lo script: la password non passa mai da una riga di comando.

use bnw_core::action::{NtlmCheck, Outcome, Place, TRIAL_STEP};
use bnw_core::keyfile;
use bnw_core::paths::ACTIVE_CONF;
use bnw_core::profile::Profile;
use bnw_core::render::{cifs, cntlm};
use bnw_core::status::Route;
use bnw_core::{Secret, systemd, validate};

use crate::nm;
use crate::proxy::{installed_profile, invalid};
use crate::{CNTLM, Ctx, SYSTEMCTL};

const NM_DIR: &str = "/etc/NetworkManager/system-connections";
const CNTLM_CONF: &str = "/etc/cntlm.conf";
const NMCLI: &str = "/usr/bin/nmcli";
const CURL: &str = "/usr/bin/curl";

/// Annota il posto sull'ultimo passo del rapporto.
fn tag(ctx: &mut Ctx, place: Place) {
    if let Some(s) = ctx.report.steps.last_mut() {
        s.place = Some(place);
    }
}

/// Il keyfile della connessione con quel nome: (percorso, contenuto).
fn find_keyfile(ctx: &Ctx, name: &str) -> std::io::Result<Option<(String, String)>> {
    for path in ctx.fs.list(NM_DIR)? {
        if let Some(text) = ctx.fs.read(&path)?
            && keyfile::connection_id(&text) == Some(name)
        {
            return Ok(Some((path, text)));
        }
    }
    Ok(None)
}

/// Dove sta ogni posto su questa macchina; `None` se il profilo non lo prevede.
fn locate(
    ctx: &mut Ctx,
    profile: &Profile,
    place: Place,
    can_create: bool,
) -> Option<Result<String, String>> {
    let nm = |ctx: &mut Ctx, name: &str| match ctx.nm.find(name) {
        Ok(Some(c)) => Ok(c.filename.unwrap_or_else(|| name.to_string())),
        Ok(None) => Err(format!("connessione «{name}» non trovata in NetworkManager")),
        // senza NetworkManager (--root) si cercano i keyfile
        Err(_) => match find_keyfile(ctx, name) {
            Ok(Some((path, _))) => Ok(path),
            Ok(None) => Err(format!("connessione «{name}» non trovata in {NM_DIR}")),
            Err(e) => Err(e.to_string()),
        },
    };
    match place {
        Place::Vpn => profile.vpn.as_ref().map(|v| v.name.clone()).map(|n| nm(ctx, &n)),
        Place::Wifi => profile.wifi.as_ref().map(|w| w.name.clone()).map(|n| nm(ctx, &n)),
        Place::Cntlm => Some(if ctx.fs.exists(CNTLM_CONF) || can_create {
            Ok(CNTLM_CONF.to_string())
        } else {
            Err("cntlm non ancora configurato".into())
        }),
        Place::Cifs => (!profile.shares.is_empty()).then(|| Ok(cifs::credentials_path(profile))),
    }
}

/// Il segreto di un posto, letto dal suo file. Resta dentro l'helper.
enum Stored {
    Plain(String),
    /// Hash di cntlm: utenza, e l'hash NT se c'è (non dipende da utenza e dominio),
    /// altrimenti NTLMv2.
    Hash {
        user: String,
        nt: Option<String>,
        v2: String,
    },
}

fn stored(place: Place, text: &str) -> Option<Stored> {
    let plain = |v: Option<&str>| v.map(|p| Stored::Plain(p.to_string()));
    match place {
        Place::Vpn => plain(keyfile::get(text, "vpn-secrets", "password")),
        Place::Wifi => plain(keyfile::get(text, "802-1x", "password")),
        Place::Cifs => plain(text.lines().find_map(|l| l.strip_prefix("password="))),
        Place::Cntlm => {
            let hashes = cntlm::parse_hash_output(text).ok()?;
            let user = text.lines().find_map(|l| {
                let mut w = l.split_whitespace();
                (w.next() == Some("Username"))
                    .then(|| w.next().map(str::to_string))
                    .flatten()
            })?;
            Some(Stored::Hash {
                user,
                nt: hashes.nt.map(|h| h.expose().to_string()),
                v2: hashes.ntlmv2.expose().to_string(),
            })
        }
    }
}

/// `PasswordStatus`: per ogni posto il file e la data, e soprattutto se la password
/// è la stessa ovunque. Il confronto si fa qui dentro: per cntlm si calcola l'hash
/// della password degli altri posti (`cntlm -H`, locale) e lo si confronta con quello
/// salvato. Nel rapporto escono solo «uguale» o «diversa», mai un segreto.
pub fn status(ctx: &mut Ctx) {
    let Some(profile) = installed_profile(ctx) else {
        return;
    };
    let mut found: Vec<(Place, usize, Stored)> = Vec::new();
    for place in Place::ALL {
        let Some(loc) = locate(ctx, &profile, place, false) else {
            continue;
        };
        match loc {
            Ok(path) => {
                let text = ctx.fs.read(&path).ok().flatten();
                let secret = text.as_deref().and_then(|t| stored(place, t));
                let detail = match (&text, &secret) {
                    (None, _) => Some("file non trovato".to_string()),
                    (Some(_), None) => Some("nessuna password salvata".to_string()),
                    _ => None,
                };
                let outcome = if detail.is_some() {
                    Outcome::Failed
                } else {
                    Outcome::Unchanged
                };
                ctx.report.push(path.clone(), outcome, detail);
                tag(ctx, place);
                let idx = ctx.report.steps.len() - 1;
                ctx.report.steps[idx].mtime = ctx.fs.mtime(&path);
                if let Some(secret) = secret {
                    found.push((place, idx, secret));
                }
            }
            Err(e) => {
                ctx.report.push(place.label(), Outcome::Failed, Some(e));
                tag(ctx, place);
            }
        }
    }
    ctx.report.password_aligned = compare(ctx, &profile, &found);
}

/// Confronta i segreti trovati e segna i posti diversi dalla maggioranza.
fn compare(ctx: &mut Ctx, profile: &Profile, found: &[(Place, usize, Stored)]) -> Option<bool> {
    // la password in chiaro più frequente fa da riferimento (a parità, l'ordine dei posti)
    let plains: Vec<&str> = found
        .iter()
        .filter_map(|(_, _, s)| match s {
            Stored::Plain(p) => Some(p.as_str()),
            Stored::Hash { .. } => None,
        })
        .collect();
    let reference = plains.iter().copied().max_by_key(|p| {
        let count = plains.iter().filter(|q| *q == p).count();
        (count, std::cmp::Reverse(plains.iter().position(|q| q == p)))
    })?;
    if found.len() < 2 {
        return None;
    }
    let mut aligned = true;
    for (place, idx, secret) in found {
        let same = match secret {
            Stored::Plain(p) => Some(p == reference),
            Stored::Hash { user, nt, v2 } => cntlm_matches(ctx, profile, reference, user, nt.as_deref(), v2),
        };
        match same {
            Some(true) => {}
            Some(false) => {
                aligned = false;
                let step = &mut ctx.report.steps[*idx];
                step.outcome = Outcome::Failed;
                step.detail = Some(format!("password diversa dagli altri posti ({})", place.label()));
            }
            None => {
                ctx.report.steps[*idx].detail = Some("confronto non riuscito".into());
            }
        }
    }
    Some(aligned)
}

/// L'hash salvato in cntlm corrisponde a `password`?
fn cntlm_matches(
    ctx: &mut Ctx,
    profile: &Profile,
    password: &str,
    user: &str,
    nt: Option<&str>,
    v2: &str,
) -> Option<bool> {
    let input = format!("{password}\n");
    let domain = profile.company.domain.clone();
    let out = ctx
        .run
        .run(
            CNTLM,
            &["-H", "-c", "/dev/null", "-u", user, "-d", &domain],
            Some(&input),
        )
        .ok()
        .filter(|o| o.success)?;
    let computed = cntlm::parse_hash_output(&out.stdout).ok()?;
    match (nt, &computed.nt) {
        (Some(stored), Some(c)) => Some(stored.eq_ignore_ascii_case(c.expose())),
        _ => Some(v2.eq_ignore_ascii_case(computed.ntlmv2.expose())),
    }
}

pub fn stop_cntlm(ctx: &mut Ctx) {
    ctx.cmd("cntlm fermato", SYSTEMCTL, &["stop", "cntlm.service"], None);
}

fn route(ctx: &Ctx) -> Option<Route> {
    let link = std::fs::read_link(ctx.fs.path(ACTIVE_CONF)).ok()?;
    Route::from_target(&link.to_string_lossy())
}

/// Riaccende cntlm solo se la rete attuale passa dal proxy aziendale.
pub fn start_cntlm(ctx: &mut Ctx) {
    if route(ctx) == Some(Route::Upstream) {
        ctx.cmd("cntlm riacceso", SYSTEMCTL, &["start", "cntlm.service"], None);
    } else {
        ctx.report.push(
            "cntlm",
            Outcome::Skipped,
            Some("con la rete attuale non serve".into()),
        );
    }
}

/// L'utenza di dominio, dai file che già la contengono.
pub(crate) fn user_from_files(ctx: &Ctx, profile: &Profile) -> Option<String> {
    let read = |p: &str| ctx.fs.read(p).ok().flatten().unwrap_or_default();
    let cntlm_user = read(CNTLM_CONF).lines().find_map(|l| {
        let mut w = l.split_whitespace();
        (w.next() == Some("Username"))
            .then(|| w.next().map(str::to_string))
            .flatten()
    });
    cntlm_user.or_else(|| {
        cifs::parse_credentials(&read(&cifs::credentials_path(profile)))
            .0
            .map(str::to_string)
    })
}

pub fn set(ctx: &mut Ctx, password: &Secret, only: &[Place], domain_user: Option<&str>) {
    if let Err(e) = validate::password(password) {
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
    let Some(profile) = installed_profile(ctx) else {
        return;
    };
    // l'utenza data vince su quella scritta nei file
    let user: Option<String> = domain_user.map(str::to_string);
    let wanted: Vec<Place> = if only.is_empty() {
        Place::ALL.to_vec()
    } else {
        only.to_vec()
    };
    let mut places = Vec::new();
    for place in wanted {
        match locate(ctx, &profile, place, user.is_some()) {
            None => {
                if !only.is_empty() {
                    ctx.report.push(
                        place.label(),
                        Outcome::Skipped,
                        Some("non previsto dal profilo".into()),
                    );
                    tag(ctx, place);
                }
            }
            Some(Err(e)) if place != Place::Cifs => {
                ctx.fail(place.label(), e);
                tag(ctx, place);
            }
            Some(_) => places.push(place),
        }
    }

    let mut cntlm_ok = false;
    if places.contains(&Place::Cntlm) {
        // Prima di tutto: con gli hash vecchi ritenterebbe a ogni richiesta.
        stop_cntlm(ctx);
        if let Some((user, hashes)) = compute_hashes(ctx, &profile, password, user.as_deref()) {
            if trial(ctx, &profile, &user, &hashes) == NtlmCheck::Rejected {
                ctx.report.ntlm = Some(NtlmCheck::Rejected);
                ctx.fail(
                    TRIAL_STEP,
                    "407: il proxy aziendale rifiuta questa password. Non ho scritto niente da \
                     nessuna parte; cntlm resta fermo per non bloccare l'account.",
                );
                return;
            }
            cntlm_ok = write_hashes(ctx, &profile, &user, &hashes);
        }
    }
    // L'utenza per la VPN: quella data o, dopo cntlm, quella scritta nei file. Senza
    // `username` NetworkManager chiede le credenziali a un secret agent e la VPN non sale.
    let vpn_user = user.clone().or_else(|| user_from_files(ctx, &profile));
    let mut nm_changed = false;
    for (place, name, section) in [
        (
            Place::Vpn,
            profile.vpn.as_ref().map(|v| v.name.clone()),
            "vpn-secrets",
        ),
        (
            Place::Wifi,
            profile.wifi.as_ref().map(|w| w.name.clone()),
            "802-1x",
        ),
    ] {
        if let (true, Some(name)) = (places.contains(&place), name) {
            nm_changed |= write_nm_secret(ctx, place, &name, section, password, vpn_user.as_deref())
                == NmWrite::Keyfile;
        }
    }
    if nm_changed {
        ctx.cmd(
            "NetworkManager ricaricato",
            NMCLI,
            &["connection", "reload"],
            None,
        );
    }
    if places.contains(&Place::Cifs) {
        write_cifs(ctx, &profile, password, user.as_deref());
        unmount_shares(ctx, &profile);
    }

    verify(ctx, &profile, places.contains(&Place::Cntlm), cntlm_ok);
}

/// Calcola gli hash della password nuova (`cntlm -H`, password su stdin).
/// L'utenza è quella dei file (`cntlm.conf`, credenziali); `given` serve quando non
/// c'è ancora nessun file, cioè su una macchina nuova.
fn compute_hashes(
    ctx: &mut Ctx,
    profile: &Profile,
    password: &Secret,
    given: Option<&str>,
) -> Option<(String, cntlm::NtlmHashes)> {
    let Some(user) = user_from_files(ctx, profile).or_else(|| given.map(str::to_string)) else {
        ctx.fail(
            CNTLM_CONF,
            "utenza di dominio non trovata (manca la riga Username)",
        );
        tag(ctx, Place::Cntlm);
        return None;
    };
    let input = format!("{}\n", password.expose());
    let domain = profile.company.domain.clone();
    let Some(out) = ctx.cmd(
        "hash NTLM calcolati",
        CNTLM,
        &["-H", "-c", "/dev/null", "-u", &user, "-d", &domain],
        Some(&input),
    ) else {
        tag(ctx, Place::Cntlm);
        return None;
    };
    match cntlm::parse_hash_output(&out.stdout) {
        Ok(h) => Some((user, h)),
        Err(e) => {
            ctx.fail(CNTLM_CONF, e.to_string());
            tag(ctx, Place::Cntlm);
            None
        }
    }
}

const TRIAL_CONF: &str = "/run/bnw/cntlm-prova.conf";

/// Prova la password nuova **prima** di scriverla: un cntlm temporaneo con gli hash
/// nuovi, una richiesta verso l'esterno, e via. Con un 407 non si scrive niente: la
/// password sbagliata non finisce nei quattro posti, e il dominio vede un solo
/// tentativo fallito.
fn trial(ctx: &mut Ctx, profile: &Profile, user: &str, hashes: &cntlm::NtlmHashes) -> NtlmCheck {
    const WHAT: &str = TRIAL_STEP;
    if !profile.proxy.upstream.iter().any(|u| ctx.run.reachable(u)) {
        ctx.report.push(
            WHAT,
            Outcome::Skipped,
            Some(
                "proxy aziendale non raggiungibile da qui: la password si proverà sulla rete aziendale"
                    .into(),
            ),
        );
        return NtlmCheck::NotRun;
    }
    // la configurazione definitiva, ma senza Listen: la porta la sceglie la prova
    let conf: String = cntlm::cntlm_conf(profile, user, hashes)
        .lines()
        .filter(|l| !l.starts_with("Listen"))
        .map(|l| format!("{l}\n"))
        .collect();
    let written = ctx
        .fs
        .ensure_dir("/run/bnw", 0o700)
        .and_then(|()| ctx.fs.write(TRIAL_CONF, &conf, 0o600));
    if let Err(e) = written {
        ctx.report.push(
            WHAT,
            Outcome::Skipped,
            Some(format!("non riuscita ({e}): si prova dopo")),
        );
        return NtlmCheck::NotRun;
    }
    let path = ctx.fs.path(TRIAL_CONF);
    let code = ctx.run.ntlm_trial(&path, profile.proxy.check_url());
    let _ = ctx.fs.remove(TRIAL_CONF);
    match code {
        Ok(code @ 200..=399) => {
            ctx.report.push(
                WHAT,
                Outcome::Changed,
                Some(format!("accettata dal proxy aziendale (HTTP {code})")),
            );
            NtlmCheck::Ok { code }
        }
        Ok(407) => NtlmCheck::Rejected,
        Ok(code) => {
            let what = if code == 0 {
                "nessuna risposta".to_string()
            } else {
                format!("HTTP {code}")
            };
            ctx.report.push(
                WHAT,
                Outcome::Skipped,
                Some(format!("inconcludente ({what}): si prova dopo")),
            );
            NtlmCheck::Inconclusive { code }
        }
        Err(e) => {
            ctx.report.push(
                WHAT,
                Outcome::Skipped,
                Some(format!("non riuscita ({e}): si prova dopo")),
            );
            NtlmCheck::NotRun
        }
    }
}

/// Hash nuovi in `cntlm.conf`, riscrivendo solo le righe `Pass*`; se il file non c'è
/// o non ha un'utenza (macchina nuova) lo si scrive intero dal profilo.
fn write_hashes(ctx: &mut Ctx, profile: &Profile, user: &str, hashes: &cntlm::NtlmHashes) -> bool {
    let old = match ctx.fs.read(CNTLM_CONF) {
        Ok(Some(t)) => t,
        Ok(None) => String::new(),
        Err(e) => {
            ctx.fail(CNTLM_CONF, e.to_string());
            tag(ctx, Place::Cntlm);
            return false;
        }
    };
    // Senza riga Username il file non è una configurazione vera (di solito è l'esempio
    // installato dal pacchetto cntlm): si scrive intero dal profilo.
    let configured = old
        .lines()
        .any(|l| l.split_whitespace().next() == Some("Username"));
    let new = if configured {
        cntlm::replace_hashes(&old, hashes)
    } else {
        cntlm::cntlm_conf(profile, user, hashes)
    };
    let ok = ctx.file(CNTLM_CONF, ctx.fs.write(CNTLM_CONF, &new, 0o600)) != Outcome::Failed;
    tag(ctx, Place::Cntlm);
    ok
}

/// Come è stato scritto un segreto di NetworkManager.
#[derive(PartialEq)]
enum NmWrite {
    Failed,
    /// Via D-Bus: NetworkManager lo sa già.
    Dbus,
    /// Nel keyfile: serve `nmcli connection reload`.
    Keyfile,
}

/// Il segreto della VPN o del WiFi, più `password-flags=0`: NetworkManager lo legge
/// dal proprio archivio invece di chiederlo a un secret agent (su niri non ce n'è).
/// Via D-Bus; senza NetworkManager (--root) direttamente nel keyfile.
fn write_nm_secret(
    ctx: &mut Ctx,
    place: Place,
    name: &str,
    section: &str,
    password: &Secret,
    user: Option<&str>,
) -> NmWrite {
    let conn = match ctx.nm.find(name) {
        Ok(Some(c)) => c,
        Ok(None) => {
            ctx.fail(place.label(), format!("connessione «{name}» non trovata"));
            tag(ctx, place);
            return NmWrite::Failed;
        }
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            return if write_keyfile_secret(ctx, place, name, section, password, user) {
                NmWrite::Keyfile
            } else {
                NmWrite::Failed
            };
        }
        Err(e) => {
            ctx.fail(place.label(), e.to_string());
            tag(ctx, place);
            return NmWrite::Failed;
        }
    };
    let mut settings = conn.settings;
    let mut notes: Vec<String> = Vec::new();
    let mut no_user = false;
    let fixed_flags = "password-flags portato a 0 (prima la chiedeva a un secret agent)".to_string();
    if place == Place::Vpn {
        let mut secrets = ctx
            .nm
            .secrets(&conn.path, "vpn")
            .map(|s| nm::get_dict(&s, "vpn", "secrets"))
            .unwrap_or_default();
        secrets.insert("password".into(), password.expose().to_string());
        nm::set(&mut settings, "vpn", "secrets", nm::value(secrets));
        let mut data = nm::get_dict(&settings, "vpn", "data");
        let mut data_changed = false;
        if data.get("password-flags").map(String::as_str) != Some("0") {
            data.insert("password-flags".into(), "0".into());
            notes.push(fixed_flags);
            data_changed = true;
        }
        if data.get("username").is_none_or(|u| u.trim().is_empty()) {
            match user {
                Some(u) => {
                    data.insert("username".into(), u.into());
                    notes.push(format!("utenza {u} (mancava)"));
                    data_changed = true;
                }
                None => no_user = true,
            }
        }
        if data_changed {
            nm::set(&mut settings, "vpn", "data", nm::value(data));
        }
    } else {
        nm::set(
            &mut settings,
            "802-1x",
            "password",
            nm::value(password.expose().to_string()),
        );
        if nm::get_u32(&settings, "802-1x", "password-flags").unwrap_or(0) != 0 {
            nm::set(&mut settings, "802-1x", "password-flags", nm::value(0u32));
            notes.push(fixed_flags);
        }
    }
    let detail = (!notes.is_empty()).then(|| notes.join(", "));
    if let Some(f) = &conn.filename {
        let _ = ctx.fs.backup_copy(f, crate::NM_BACKUP_DIR);
    }
    let what = conn
        .filename
        .clone()
        .unwrap_or_else(|| format!("connessione «{name}»"));
    match ctx.nm.update(&conn.path, &settings) {
        Ok(()) => {
            ctx.report.push(what, Outcome::Changed, detail);
            tag(ctx, place);
            if no_user {
                missing_vpn_user(ctx);
            }
            NmWrite::Dbus
        }
        Err(e) => {
            ctx.fail(&what, e.to_string());
            tag(ctx, place);
            NmWrite::Failed
        }
    }
}

/// Il segreto direttamente nel keyfile (ripiego senza NetworkManager).
fn write_keyfile_secret(
    ctx: &mut Ctx,
    place: Place,
    name: &str,
    section: &str,
    password: &Secret,
    user: Option<&str>,
) -> bool {
    let (path, text) = match find_keyfile(ctx, name) {
        Ok(Some(found)) => found,
        Ok(None) => {
            ctx.fail(place.label(), format!("connessione «{name}» non trovata"));
            tag(ctx, place);
            return false;
        }
        Err(e) => {
            ctx.fail(place.label(), e.to_string());
            tag(ctx, place);
            return false;
        }
    };
    let flags_section = if place == Place::Vpn { "vpn" } else { "802-1x" };
    let mut new = keyfile::set(&text, section, "password", password.expose());
    let mut notes: Vec<String> = Vec::new();
    let mut no_user = false;
    if keyfile::get(&new, flags_section, "password-flags").is_some_and(|f| f.trim() != "0") {
        new = keyfile::set(&new, flags_section, "password-flags", "0");
        notes.push("password-flags portato a 0 (prima la chiedeva a un secret agent)".to_string());
    }
    if place == Place::Vpn && keyfile::get(&new, "vpn", "username").is_none_or(|u| u.trim().is_empty()) {
        match user {
            Some(u) => {
                new = keyfile::set(&new, "vpn", "username", u);
                notes.push(format!("utenza {u} (mancava)"));
            }
            None => no_user = true,
        }
    }
    let detail = (!notes.is_empty()).then(|| notes.join(", "));
    let result = ctx
        .fs
        .write_backup_in(&path, &new, 0o600, Some(crate::NM_BACKUP_DIR));
    let ok = ctx.file(&path, result) != Outcome::Failed;
    if let Some(s) = ctx.report.steps.last_mut() {
        s.place = Some(place);
        if detail.is_some() {
            s.detail = detail;
        }
    }
    if ok && no_user {
        missing_vpn_user(ctx);
    }
    ok
}

/// La password è salvata, ma la connessione VPN non ha l'utenza e nessun file la
/// conosce: senza, la VPN non si connette.
fn missing_vpn_user(ctx: &mut Ctx) {
    ctx.fail(
        "utenza della VPN",
        "la connessione non ha l'utenza di dominio e non la trovo altrove: la VPN non si \
         connetterebbe. Rifai la configurazione dal wizard indicando l'utenza.",
    );
    tag(ctx, Place::Vpn);
}

/// Il kernel cifs non accetta hash: la password sta in chiaro, `600 root` in una
/// cartella `700`. Utente e dominio restano quelli del file.
fn write_cifs(ctx: &mut Ctx, profile: &Profile, password: &Secret, given: Option<&str>) {
    let path = cifs::credentials_path(profile);
    let old = ctx.fs.read(&path).ok().flatten().unwrap_or_default();
    let (user, domain) = cifs::parse_credentials(&old);
    let user = match user
        .map(str::to_string)
        .or_else(|| user_from_files(ctx, profile))
        .or_else(|| given.map(str::to_string))
    {
        Some(u) => u,
        None => {
            ctx.fail(&path, "utenza di dominio non trovata");
            tag(ctx, Place::Cifs);
            return;
        }
    };
    let domain = domain.unwrap_or(&profile.company.domain).to_string();
    if let Err(e) = ctx.fs.ensure_dir("/etc/samba/credentials", 0o700) {
        ctx.fail(&path, e.to_string());
        tag(ctx, Place::Cifs);
        return;
    }
    let content = cifs::credentials_for(&user, &domain, password);
    ctx.file(&path, ctx.fs.write(&path, &content, 0o600));
    tag(ctx, Place::Cifs);
}

/// Smonta le share del profilo montate adesso: rimontano da sole al primo accesso,
/// con la password nuova.
fn unmount_shares(ctx: &mut Ctx, profile: &Profile) {
    let mounts = ctx.fs.read("/proc/mounts").ok().flatten().unwrap_or_default();
    let mounted: Vec<String> = mounts
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 2 && f[2] == "cifs").then(|| f[1].replace("\\040", " "))
        })
        .collect();
    for share in &profile.shares {
        if mounted.contains(&share.mount) {
            let unit = systemd::mount_unit(&share.mount);
            ctx.cmd(
                &format!("smontato {}", share.mount),
                SYSTEMCTL,
                &["stop", &unit],
                None,
            );
            tag(ctx, Place::Cifs);
        }
    }
}

/// Riaccende la catena e prova l'NTLM verso l'esterno, se la rete lo richiede.
fn verify(ctx: &mut Ctx, profile: &Profile, cntlm_wanted: bool, cntlm_ok: bool) {
    if !cntlm_wanted {
        return;
    }
    if route(ctx) != Some(Route::Upstream) {
        ctx.report.ntlm = Some(NtlmCheck::NotRun);
        ctx.report.push(
            "verifica NTLM",
            Outcome::Skipped,
            Some("con la rete attuale cntlm non serve: partirà da solo sulla rete aziendale o in VPN".into()),
        );
        return;
    }
    if !cntlm_ok {
        ctx.report.push(
            "cntlm",
            Outcome::Skipped,
            Some("lasciato spento: gli hash non sono stati aggiornati".into()),
        );
        return;
    }
    ctx.cmd("cntlm riacceso", SYSTEMCTL, &["start", "cntlm.service"], None);
    ctx.cmd(
        "tinyproxy riavviato",
        SYSTEMCTL,
        &["restart", "tinyproxy.service"],
        None,
    );

    // Come lo script: prima che cntlm e tinyproxy ascoltino, la prova darebbe un 50x
    // di tinyproxy e sembrerebbe inconcludente.
    for port in [profile.proxy.cntlm_port, profile.proxy.local_port] {
        for _ in 0..20 {
            if ctx.run.listening(port) {
                break;
            }
            ctx.run.pause(500);
        }
    }
    let proxy = format!("http://127.0.0.1:{}", profile.proxy.local_port);
    let url = profile.proxy.check_url().to_string();
    let mut code = 0u16;
    // cntlm e tinyproxy impiegano un attimo ad ascoltare: si riprova finché la
    // connessione è rifiutata, non oltre.
    for attempt in 0..10 {
        let out = ctx.run.run(
            CURL,
            &[
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "25",
                "--proxy",
                &proxy,
                "--url",
                &url,
            ],
            None,
        );
        code = out.ok().and_then(|o| o.stdout.trim().parse().ok()).unwrap_or(0);
        if code != 0 || attempt == 9 {
            break;
        }
        ctx.run.pause(1000);
    }
    match code {
        200..=399 => {
            ctx.report.ntlm = Some(NtlmCheck::Ok { code });
            ctx.report.push(
                "verifica NTLM",
                Outcome::Changed,
                Some(format!("password accettata (HTTP {code})")),
            );
        }
        407 => {
            // Subito: ogni richiesta in più è un tentativo sbagliato verso il dominio.
            ctx.run.run(SYSTEMCTL, &["stop", "cntlm.service"], None).ok();
            ctx.report.ntlm = Some(NtlmCheck::Rejected);
            ctx.fail(
                "verifica NTLM",
                "407: il proxy aziendale rifiuta la password. cntlm è stato fermato per non bloccare \
                 l'account: controlla la password e riprova.",
            );
        }
        other => {
            ctx.report.ntlm = Some(NtlmCheck::Inconclusive { code: other });
            let what = if other == 0 {
                "nessuna risposta".to_string()
            } else {
                format!("HTTP {other}")
            };
            ctx.report.push(
                "verifica NTLM",
                Outcome::Skipped,
                Some(format!(
                    "inconcludente ({what}): riprova più tardi con «Prova un URL»"
                )),
            );
        }
    }
}
