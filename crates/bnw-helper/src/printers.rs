//! Stampanti: code CUPS driverless (`-m everywhere`). Una coda esistente con l'URI
//! giusto si corregge (lato di stampa, descrizione, posizione) senza ricrearla; una
//! nuova si crea solo se la stampante risponde, perché CUPS la interroga al momento.

use bnw_core::action::Outcome;
use bnw_core::profile::{Printer, Profile};
use bnw_core::render::printer as render;
use bnw_core::validate;

use crate::proxy::invalid;
use crate::shares::previous_profile;
use crate::vpn::save_profile;
use crate::{Ctx, SYSTEMCTL};

const LPADMIN: &str = "/usr/bin/lpadmin";
const LPSTAT: &str = "/usr/bin/lpstat";
const LPOPTIONS: &str = "/usr/bin/lpoptions";

/// L'URI della coda, se esiste (`lpstat -v`: «device for NOME: URI»).
fn current_uri(ctx: &mut Ctx, name: &str) -> Option<String> {
    let out = ctx
        .run
        .run(LPSTAT, &["-v", name], None)
        .ok()
        .filter(|o| o.success)?;
    out.stdout
        .lines()
        .find_map(|l| l.split_once(": ").map(|(_, uri)| uri.trim().to_string()))
}

/// `host:porta` della stampante, per la prova di raggiungibilità.
fn host_port(uri: &str) -> Option<String> {
    let rest = uri.split_once("://")?.1;
    let authority = rest.split('/').next()?;
    Some(if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:631")
    })
}

pub fn apply(ctx: &mut Ctx, profile: &Profile) {
    let previous = previous_profile(ctx).map(|p| p.printers).unwrap_or_default();
    apply_with(ctx, profile, &previous);
}

/// Come [`apply`], con le stampanti "di prima" passate da chi chiama.
pub fn apply_with(ctx: &mut Ctx, profile: &Profile, previous: &[Printer]) {
    if let Err(e) = validate::profile(profile) {
        return invalid(ctx, "profilo", e);
    }
    if !save_profile(ctx, profile) {
        return;
    }
    if !profile.printers.is_empty()
        && !ctx
            .run
            .run(SYSTEMCTL, &["is-active", "--quiet", "cups.socket"], None)
            .is_ok_and(|o| o.success)
    {
        ctx.cmd(
            "CUPS attivo",
            SYSTEMCTL,
            &["enable", "--now", "cups.socket", "cups.service"],
            None,
        );
    }

    for p in &profile.printers {
        apply_one(ctx, p);
    }
    let kept: Vec<&str> = profile.printers.iter().map(|p| p.name.as_str()).collect();
    for old in previous.iter().filter(|p| !kept.contains(&p.name.as_str())) {
        if current_uri(ctx, &old.name).is_some() {
            let args = render::lpadmin_remove(old);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            ctx.cmd(&format!("stampante {} tolta", old.name), LPADMIN, &args, None);
        }
    }
}

fn apply_one(ctx: &mut Ctx, p: &Printer) {
    let what = format!("stampante {}", p.name);
    if current_uri(ctx, &p.name).as_deref() == Some(p.uri.as_str()) {
        let opts = ctx
            .run
            .run(LPOPTIONS, &["-p", &p.name], None)
            .map(|o| render::parse_lpoptions(&o.stdout))
            .unwrap_or_default();
        match render::lpadmin_fix(p, &opts) {
            None => ctx
                .report
                .push(what, Outcome::Unchanged, Some("già a posto".into())),
            Some(args) => {
                let detail = describe(&args);
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                if ctx.cmd(&what, LPADMIN, &args, None).is_some()
                    && let Some(s) = ctx.report.steps.last_mut()
                {
                    s.detail = Some(detail);
                }
            }
        }
        return;
    }
    // da creare (o con un URI diverso: si ridefinisce)
    let reachable = host_port(&p.uri).is_some_and(|hp| ctx.run.reachable(&hp));
    if !reachable {
        ctx.report.push(
            what,
            Outcome::Skipped,
            Some("stampante non raggiungibile da qui: si aggiunge dalla rete aziendale o in VPN".into()),
        );
        return;
    }
    for args in [render::lpadmin_create(p), render::lpadmin_sides(p)] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        if ctx.cmd(&what, LPADMIN, &args, None).is_none() {
            return;
        }
    }
    if let Some(s) = ctx.report.steps.last_mut() {
        s.detail = Some(format!(
            "aggiunta, {}",
            if p.duplex { "fronte-retro" } else { "solo fronte" }
        ));
    }
}

/// Le correzioni in parole, per il rapporto.
fn describe(args: &[String]) -> String {
    let mut out: Vec<&str> = Vec::new();
    for a in args {
        let word = match a.as_str() {
            "-D" => "descrizione",
            "-L" => "posizione",
            "Duplex-default=None" | "sides-default=one-sided" => "solo fronte",
            s if s.starts_with("Duplex-default=") || s.starts_with("sides-default=") => "fronte-retro",
            _ => continue,
        };
        if !out.contains(&word) {
            out.push(word);
        }
    }
    out.join(", ")
}
