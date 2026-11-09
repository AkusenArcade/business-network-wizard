//! `bnw <comando>`: la riga di comando. Senza argomenti `bnw` apre la GUI (lo decide
//! `bnw-gui`, che chiama [`run`] solo quando c'è un comando).

use std::path::Path;
use std::process::ExitCode;

use bnw_client::{Env, helper, nettest, status, user};
use bnw_core::Profile;
use bnw_core::action::{Action, NtlmCheck, Outcome, Place, ProxyMode, Report, SPREAD_WARNING_SECS};
use bnw_core::status::{Route, Status, service_label};

pub const USAGE: &str = "\
uso: bnw                         apre l'app
     bnw status [--json] [--detect]
                                 stato di proxy, servizi, VPN e WiFi aziendali
     bnw proxy auto|on|off       modalità del proxy (on/off: forzatura manuale)
     bnw proxy test URL          la stessa richiesta diretta e via proxy
     bnw proxy apply PROFILO     applica la parte proxy di un profile.toml
     bnw password [--solo vpn,wifi,cntlm,cifs]
                                 aggiorna la password di dominio dove è salvata
     bnw password --stato        dove sta la password e quando è stata scritta
     bnw profile export FILE.bnw [--ovpn FILE] [--ca FILE]
                                 esporta il profilo aziendale cifrato (VPN, WiFi,
                                 proxy, dischi, stampanti: niente password di dominio)
     bnw profile show FILE.bnw   mostra cosa contiene un profilo
     bnw profile import FILE.bnw importa un profilo e chiede utenza e password (come setup)
     bnw vpn up|down             connette o disconnette la VPN aziendale
     bnw vpn check               ricontrolla e corregge la connessione VPN
     bnw vpn import FILE.ovpn    reimporta la VPN da un .ovpn (la password resta)
     bnw wifi up|down            connette o disconnette il WiFi aziendale
     bnw wifi check              ricontrolla e corregge il WiFi aziendale
     bnw wifi ca FILE.pem        sostituisce la CA del RADIUS (controlla il fingerprint)
     bnw wifi autoconnect on|off connessione automatica al WiFi aziendale
     bnw share add //SERVER/SHARE /mnt/CARTELLA [ETICHETTA]
     bnw share remove /mnt/CARTELLA
     bnw share check             riscrive unit e segnalibri dei dischi di rete
     bnw share umount            smonta adesso i dischi montati
     bnw printer add NOME ipp://HOST/ipp [--duplex] [--location TESTO] [--description TESTO]
     bnw printer remove NOME
     bnw printer check           ricontrolla le code (lato di stampa, posizione…)
     bnw printer test NOME       stampa una pagina di prova
     bnw setup FILE.bnw          prima configurazione di questa macchina da un profilo
     bnw offline-bundle FILE.tar [--search CARTELLA]...
                                 pacchetti per installare l'app su un PC senza internet
     bnw adopt PROFILO           adotta una configurazione fatta a mano";

pub fn run(args: &[String]) -> ExitCode {
    let env = Env::from_env();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["status", rest @ ..] => cmd_status(&env, rest),
        ["proxy", "auto" | "on" | "off"] => {
            let mode = match args[1] {
                "on" => ProxyMode::On,
                "off" => ProxyMode::Off,
                _ => ProxyMode::Auto,
            };
            cmd_helper(&env, &Action::SetMode { mode })
        }
        ["proxy", "test", url] => cmd_test(&env, url),
        ["proxy", "apply", file] => match load_profile(file) {
            Ok(profile) => cmd_helper(&env, &Action::ApplyProxy { profile }),
            Err(e) => fail(&e),
        },
        ["adopt", file] => cmd_adopt(&env, file),
        ["setup", file] => cmd_setup(&env, file),
        ["offline-bundle", out, rest @ ..] => cmd_offline(out, rest),
        ["share", "add", unc, mount, label @ ..] => edit_shares(&env, |shares| {
            let (server, name) = parse_unc(unc).ok_or("serve //server/share")?;
            if shares.iter().any(|s| s.mount == *mount) {
                return Err(format!("{mount} è già usata"));
            }
            shares.push(bnw_core::profile::Share {
                server,
                name,
                mount: mount.to_string(),
                label: (!label.is_empty()).then(|| label.join(" ")),
            });
            Ok(())
        }),
        ["share", "remove", mount] => edit_shares(&env, |shares| {
            let before = shares.len();
            shares.retain(|s| s.mount != *mount);
            if shares.len() == before {
                Err(format!("{mount} non è tra i dischi del profilo"))
            } else {
                Ok(())
            }
        }),
        ["share", "check"] => edit_shares(&env, |_| Ok(())),
        ["share", "umount"] => cmd_helper(&env, &Action::UnmountShares),
        ["printer", "add", name, uri, flags @ ..] => match parse_printer(name, uri, flags) {
            Ok(pr) => edit_printers(&env, |list| {
                if list.iter().any(|p| p.name == pr.name) {
                    return Err(format!("la stampante {} c'è già", pr.name));
                }
                list.push(pr);
                Ok(())
            }),
            Err(e) => fail(&e),
        },
        ["printer", "remove", name] => edit_printers(&env, |list| {
            let before = list.len();
            list.retain(|p| p.name != *name);
            if list.len() == before {
                Err(format!("{name} non è tra le stampanti del profilo"))
            } else {
                Ok(())
            }
        }),
        ["printer", "check"] => edit_printers(&env, |_| Ok(())),
        ["printer", "test", name] => {
            match std::process::Command::new("lp")
                .args(["-d", name, "/usr/share/cups/data/testprint"])
                .status()
            {
                Ok(s) if s.success() => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(e) => fail(&format!("lp: {e}")),
            }
        }
        ["vpn", verb @ ("up" | "down")] => connection(&env, true, verb),
        ["wifi", verb @ ("up" | "down")] => connection(&env, false, verb),
        ["vpn", "check"] => with_profile(&env, |p| Action::ApplyVpn {
            profile: p,
            ovpn: None,
            reimport: false,
            domain_user: None,
            password: None,
        }),
        ["vpn", "import", file] => match std::fs::read(file) {
            Ok(data) => with_profile(&env, |p| Action::ApplyVpn {
                profile: p,
                ovpn: Some(bnw_core::Blob(data)),
                reimport: true,
                domain_user: None,
                password: None,
            }),
            Err(e) => fail(&format!("{file}: {e}")),
        },
        ["wifi", "check"] => with_profile(&env, |p| Action::ApplyWifi {
            profile: p,
            ca: None,
            domain_user: None,
            password: None,
        }),
        ["wifi", "ca", file] => match std::fs::read(file) {
            Ok(data) => with_profile(&env, |p| Action::ApplyWifi {
                profile: p,
                ca: Some(bnw_core::Blob(data)),
                domain_user: None,
                password: None,
            }),
            Err(e) => fail(&format!("{file}: {e}")),
        },
        ["wifi", "autoconnect", v @ ("on" | "off")] => with_profile(&env, |mut p| {
            if let Some(w) = p.wifi.as_mut() {
                w.autoconnect = *v == "on";
            }
            Action::ApplyWifi {
                profile: p,
                ca: None,
                domain_user: None,
                password: None,
            }
        }),
        ["password", "--stato"] => cmd_password_status(&env),
        ["profile", "export", out, rest @ ..] => cmd_export(&env, out, rest),
        ["profile", "show", file] => cmd_show(file).map_or_else(|e| fail(&e), |_| ExitCode::SUCCESS),
        ["profile", "import", file] => cmd_import(&env, file),
        ["password"] => cmd_password(&env, &[]),
        ["password", "--solo", list] => match parse_places(list) {
            Ok(places) => cmd_password(&env, &places),
            Err(e) => fail(&e),
        },
        ["help" | "--help" | "-h"] => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("bnw: {msg}");
    ExitCode::FAILURE
}

fn load_profile(file: &str) -> Result<Profile, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    Profile::from_toml(&text).map_err(|e| format!("{file}: {e}"))
}

pub fn format_status(st: &Status) -> String {
    let mut out = String::new();
    match &st.company {
        Some(c) => out += &format!("profilo:    {c}\n"),
        None => out += "profilo:    nessuno (macchina non configurata dall'app)\n",
    }
    let route = match st.route {
        Some(Route::Upstream) => "proxy aziendale (upstream)",
        Some(Route::Direct) => "diretto (direct)",
        None => "sconosciuta",
    };
    out += &format!("modalità:   {route}");
    match st.forced {
        Some(m) => {
            out += &format!(
                ", forzata a mano ({}): \"bnw proxy auto\" per tornare automatico\n",
                m.as_str()
            )
        }
        None => out += ", automatica\n",
    }
    out += &format!(
        "servizi:    tinyproxy {}, cntlm {}\n",
        service_label(st.tinyproxy.as_deref()),
        service_label(st.cntlm.as_deref())
    );
    for (label, c) in [("VPN", &st.vpn), ("WiFi", &st.wifi)] {
        if let Some(c) = c {
            let s = if c.active { "connessa" } else { "non connessa" };
            out += &format!("{label:<11} {} {s}\n", c.name);
        }
    }
    if let Some(d) = &st.last_decision {
        out += &format!("ultima rilevazione: {d}\n");
    }
    for sh in &st.shares {
        out += &format!(
            "disco       {} ({}) {}\n",
            sh.mount,
            sh.unc,
            if sh.mounted { "montato" } else { "non montato" }
        );
    }
    for pr in &st.printers {
        let state = match pr.state.as_deref() {
            Some("idle") => "pronta",
            Some("printing") => "in stampa",
            Some("disabled") => "disattivata",
            Some(_) => "attiva",
            None => "coda assente",
        };
        out += &format!("stampante   {} {state}\n", pr.name);
    }
    if st.legacy {
        out += "attenzione: ci sono ancora gli script dell'installazione manuale (\"bnw adopt\")\n";
    }
    out
}

fn cmd_status(env: &Env, flags: &[&str]) -> ExitCode {
    let json = flags.contains(&"--json");
    let detect = flags.contains(&"--detect");
    if let Some(f) = flags.iter().find(|f| !["--json", "--detect"].contains(f)) {
        return fail(&format!("opzione sconosciuta: {f}"));
    }
    let st = status::read(env);
    let detected = detect.then(|| status::detect_now(env));
    if json {
        let mut v = serde_json::to_value(&st).unwrap();
        if let Some(d) = &detected {
            v["detect"] = match d {
                Ok(t) => t.clone().into(),
                Err(e) => serde_json::json!({ "error": e }),
            };
        }
        println!("{v}");
    } else {
        print!("{}", format_status(&st));
        match detected {
            Some(Ok(t)) => println!("\n{t}"),
            Some(Err(e)) => println!("\nrilevazione non riuscita: {e}"),
            None => {}
        }
    }
    ExitCode::SUCCESS
}

pub fn format_report(r: &Report) -> String {
    let mut out = String::new();
    for s in &r.steps {
        let mark = match s.outcome {
            Outcome::Changed => "✓",
            Outcome::Unchanged => "=",
            Outcome::Skipped => "-",
            Outcome::Failed => "✗",
        };
        out += &format!("{mark} {}", s.what);
        if let Some(d) = &s.detail {
            out += &format!("  ({d})");
        }
        out += "\n";
    }
    out
}

fn cmd_helper(env: &Env, action: &Action) -> ExitCode {
    match helper::run(env, action) {
        Ok(r) => {
            print!("{}", format_report(&r));
            if r.failed() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_test(env: &Env, url: &str) -> ExitCode {
    if !nettest::valid_url(url) {
        return fail("serve un URL http:// o https://");
    }
    let port = status::installed_profile(env).map_or(8118, |p| p.proxy.local_port);
    let t = nettest::test_url(url, port);
    for (label, p) in [("diretto", &t.direct), ("via proxy", &t.proxy)] {
        match (p.code, &p.error) {
            (Some(c), _) => println!("{label:<10} HTTP {c}  ({:.2} s)", p.seconds),
            (None, Some(e)) => println!("{label:<10} nessuna risposta: {e}"),
            (None, None) => println!("{label:<10} nessuna risposta"),
        }
    }
    if t.direct.code.is_some() && matches!(t.proxy.code, Some(502..=504) | None) {
        println!("\nRisponde solo in diretto: probabilmente va aggiunto alle eccezioni del proxy.");
    }
    ExitCode::SUCCESS
}

fn cmd_adopt(env: &Env, file: &str) -> ExitCode {
    let profile = match load_profile(file) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let code = cmd_helper(env, &Action::Adopt { profile });
    if code != ExitCode::SUCCESS {
        return code;
    }
    let Some(home) = std::env::var_os("HOME") else {
        return code;
    };
    match user::retire_fish(Path::new(&home)) {
        Ok(done) => {
            for p in done {
                println!("✓ {}  (funzione fish sostituita da bnw)", p.display());
            }
            code
        }
        Err(e) => fail(&format!("funzioni fish: {e}")),
    }
}

fn parse_places(list: &str) -> Result<Vec<Place>, String> {
    list.split(',')
        .map(|p| match p.trim() {
            "vpn" => Ok(Place::Vpn),
            "wifi" => Ok(Place::Wifi),
            "cntlm" | "proxy" => Ok(Place::Cntlm),
            "cifs" | "dischi" => Ok(Place::Cifs),
            other => Err(format!("posto sconosciuto: {other} (vpn, wifi, cntlm, cifs)")),
        })
        .collect()
}

fn local_time(secs: i64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(secs, 0)
        .single()
        .map_or_else(|| secs.to_string(), |t| t.format("%d/%m/%Y %H:%M").to_string())
}

fn cmd_password_status(env: &Env) -> ExitCode {
    let r = match helper::run(env, &Action::PasswordStatus) {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string()),
    };
    for s in &r.steps {
        let label = s.place.map_or("?", Place::label);
        let when = s.mtime.map(local_time).unwrap_or_default();
        let note = s
            .detail
            .as_deref()
            .map(|d| format!("  ({d})"))
            .unwrap_or_default();
        let mark = if s.outcome == Outcome::Failed { "✗" } else { " " };
        println!("{mark} {label:<15} {when:<17} {}{note}", s.what);
    }
    match r.password_aligned {
        Some(true) => println!("\nLa password è la stessa in tutti i posti che ne hanno una."),
        Some(false) => println!(
            "\nLa password NON è la stessa ovunque (posti segnati con ✗): un cambio password è \
             rimasto a metà. «bnw password» la riscrive in tutti i posti."
        ),
        None if r.mtime_spread().is_some_and(|d| d > SPREAD_WARNING_SECS) => println!(
            "\nNon ho potuto confrontare le password e le date non sono vicine: un cambio \
             password precedente può essere rimasto a metà."
        ),
        None => {}
    }
    if r.failed() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Dentro una sessione che passa dal proxy (come Claude Code), fermare cntlm la
/// taglierebbe fuori a metà procedura: la vecchia funzione fish si rifiutava, e così qui.
fn behind_own_proxy() -> bool {
    std::env::var_os("CLAUDECODE").is_some()
        && ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"]
            .iter()
            .any(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()))
}

fn cmd_password(env: &Env, only: &[Place]) -> ExitCode {
    if behind_own_proxy() {
        return fail(
            "sei dentro Claude Code e il proxy è attivo: cntlm viene fermato e la sessione \
             perderebbe la rete a metà. Usa un terminale normale o l'app.",
        );
    }
    let needs_cntlm = only.is_empty() || only.contains(&Place::Cntlm);
    if needs_cntlm {
        // Prima di chiedere la password: con gli hash vecchi cntlm ritenta a ogni
        // richiesta e il dominio blocca l'account.
        println!("Fermo cntlm prima di chiederti la password…");
        if let Err(e) = helper::run(env, &Action::StopCntlm) {
            return fail(&e.to_string());
        }
    }
    // Interrotto a metà: cntlm resta fermo. Con la password già cambiata sul dominio,
    // riaccenderlo con gli hash vecchi vorrebbe dire 407 a ripetizione.
    let stopped = |msg: &str| {
        if needs_cntlm {
            eprintln!(
                "cntlm resta fermo: finché non aggiorni la password il proxy aziendale non va. \
                 Se la password non è cambiata, «bnw proxy auto» lo riaccende."
            );
        }
        fail(msg)
    };
    // Si chiede la password finché la prova preventiva la rifiuta: in quel caso non è
    // stato scritto niente.
    let r = loop {
        let Ok(pw) = rpassword::prompt_password("Nuova password di dominio (non viene mostrata): ") else {
            return stopped("impossibile leggere la password dal terminale");
        };
        let Ok(again) = rpassword::prompt_password("Ripetila per conferma: ") else {
            return stopped("impossibile leggere la password dal terminale");
        };
        if pw.is_empty() {
            return stopped("password vuota: non ho toccato niente");
        }
        if pw != again {
            return stopped("le due password non coincidono: non ho toccato niente");
        }
        drop(again);
        let action = Action::SetPassword {
            password: bnw_core::Secret::new(pw),
            only: only.to_vec(),
            domain_user: None,
        };
        let r = match helper::run(env, &action) {
            Ok(r) => r,
            Err(e) => return stopped(&e.to_string()),
        };
        if !r.rejected_before_writing() {
            break r;
        }
        println!(
            "\n407: il proxy aziendale rifiuta questa password. Non ho modificato niente.\n\
             Riscrivila con attenzione (Ctrl+C per smettere): ogni prova sbagliata conta come un \
             tentativo verso il dominio.\n"
        );
    };
    print!("{}", format_report(&r));
    match r.ntlm {
        Some(NtlmCheck::Ok { .. }) => println!("\nIl proxy aziendale accetta la password nuova."),
        Some(NtlmCheck::Rejected) => println!(
            "\n*** 407: la password è stata scritta ma la prova finale la rifiuta. cntlm è fermo \
             per non bloccare l'account: rilancia «bnw password» con quella corretta."
        ),
        Some(NtlmCheck::NotRun) => {
            println!("\nLa prova NTLM si fa sulla rete aziendale o in VPN: «bnw proxy test https://…».")
        }
        Some(NtlmCheck::Inconclusive { .. }) | None => {}
    }
    if only.is_empty() || only.contains(&Place::Vpn) {
        println!(
            "La VPN già connessa resta sulla sessione vecchia: riconnettila per provare la password nuova."
        );
    }
    if r.failed() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn passphrase(confirm: bool) -> Result<String, String> {
    let p = rpassword::prompt_password("Passphrase del profilo: ").map_err(|e| e.to_string())?;
    if confirm {
        if p.chars().count() < bnw_core::bundle::MIN_PASSPHRASE {
            return Err(format!(
                "la passphrase deve avere almeno {} caratteri",
                bnw_core::bundle::MIN_PASSPHRASE
            ));
        }
        let again = rpassword::prompt_password("Ripetila: ").map_err(|e| e.to_string())?;
        if again != p {
            return Err("le due passphrase non coincidono".into());
        }
    }
    Ok(p)
}

fn cmd_export(env: &Env, out: &str, flags: &[&str]) -> ExitCode {
    let mut ovpn: Option<std::path::PathBuf> = None;
    let mut ca: Option<std::path::PathBuf> = None;
    let mut it = flags.iter();
    while let Some(f) = it.next() {
        match (*f, it.next()) {
            ("--ovpn", Some(v)) => ovpn = Some(v.into()),
            ("--ca", Some(v)) => ca = Some(v.into()),
            _ => return fail(&format!("opzione non valida: {f}")),
        }
    }
    if !out.ends_with(".bnw") {
        return fail("il file deve finire in .bnw");
    }
    if Path::new(out).exists() {
        return fail(&format!("{out} esiste già: non lo sovrascrivo"));
    }
    let Some(profile) = status::installed_profile(env) else {
        return fail("nessun profilo applicato su questa macchina");
    };
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    let ovpn = ovpn.or_else(|| bnw_client::bundle::detect_ovpn(&profile, &home));
    let ca = ca.or_else(|| bnw_client::bundle::detect_ca(&profile));
    for (label, p) in [("VPN", &ovpn), ("CA del WiFi", &ca)] {
        if let Some(p) = p {
            println!("{label:<12} {}", p.display());
        }
    }
    let (bundle, warnings) = match bnw_client::bundle::build(&profile, ovpn.as_deref(), ca.as_deref()) {
        Ok(b) => b,
        Err(e) => return fail(&format!("{e} (indicalo con --ovpn o --ca)")),
    };
    for w in &warnings {
        println!("attenzione: {w}");
    }
    print!("\n{}", bnw_client::bundle::summary(&bundle));
    println!("\nIl file contiene la chiave privata della VPN: scegli una passphrase robusta.");
    let pass = match passphrase(true) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let data = match bundle.encrypt(&pass) {
        Ok(d) => d,
        Err(e) => return fail(&e.to_string()),
    };
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .and_then(|mut f| f.write_all(&data));
    match written {
        Ok(()) => {
            println!("Profilo esportato in {out}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("{out}: {e}")),
    }
}

fn open_bundle(file: &str) -> Result<bnw_core::bundle::Bundle, String> {
    let data = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let pass = passphrase(false)?;
    bnw_core::bundle::Bundle::decrypt(&data, &pass).map_err(|e| e.to_string())
}

fn cmd_show(file: &str) -> Result<bnw_core::bundle::Bundle, String> {
    let b = open_bundle(file)?;
    print!("{}", bnw_client::bundle::summary(&b));
    match b.check() {
        Ok(w) => w.iter().for_each(|w| println!("attenzione: {w}")),
        Err(e) => return Err(e.to_string()),
    }
    Ok(b)
}

fn cmd_import(env: &Env, file: &str) -> ExitCode {
    let b = match cmd_show(file) {
        Ok(b) => b,
        Err(e) => return fail(&e),
    };
    print!("Applico questo profilo su questa macchina (proxy, VPN, WiFi, dischi, stampanti)? [s/N] ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let mut answer = String::new();
    let _ = std::io::stdin().read_line(&mut answer);
    if !matches!(answer.trim(), "s" | "S" | "si" | "sì") {
        println!("Non ho applicato niente.");
        return ExitCode::SUCCESS;
    }
    // Come «bnw setup»: utenza e password subito, così la macchina è pronta.
    configure(env, &b)
}

/// Un'azione dell'helper costruita sul profilo applicato.
fn with_profile(env: &Env, make: impl FnOnce(bnw_core::Profile) -> Action) -> ExitCode {
    match status::installed_profile(env) {
        Some(p) => cmd_helper(env, &make(p)),
        None => fail("nessun profilo applicato su questa macchina"),
    }
}

/// Connette o disconnette la VPN o il WiFi del profilo, come utente (nmcli).
fn connection(env: &Env, vpn: bool, verb: &str) -> ExitCode {
    let Some(p) = status::installed_profile(env) else {
        return fail("nessun profilo applicato su questa macchina");
    };
    let name = if vpn {
        p.vpn.map(|v| v.name)
    } else {
        p.wifi.map(|w| w.name)
    };
    let Some(name) = name else {
        return fail(if vpn {
            "il profilo non ha una VPN"
        } else {
            "il profilo non ha un WiFi aziendale"
        });
    };
    let status = std::process::Command::new("nmcli")
        .args(["connection", verb, "id", &name])
        .status();
    match status {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => fail(&format!("nmcli: {e}")),
    }
}

/// `//server/share` o `\\\\server\\share` → (server, share).
pub fn parse_unc(unc: &str) -> Option<(String, String)> {
    let u = unc.replace('\\', "/");
    let rest = u.strip_prefix("//")?;
    let (server, name) = rest.trim_end_matches('/').split_once('/')?;
    (!server.is_empty() && !name.is_empty() && !name.contains('/'))
        .then(|| (server.to_string(), name.to_string()))
}

fn parse_printer(name: &str, uri: &str, flags: &[&str]) -> Result<bnw_core::profile::Printer, String> {
    let mut p = bnw_core::profile::Printer {
        name: name.to_string(),
        uri: uri.to_string(),
        description: None,
        location: None,
        duplex: false,
    };
    let mut it = flags.iter();
    while let Some(f) = it.next() {
        match *f {
            "--duplex" => p.duplex = true,
            "--location" => p.location = Some(it.next().ok_or("manca il testo di --location")?.to_string()),
            "--description" => {
                p.description = Some(it.next().ok_or("manca il testo di --description")?.to_string())
            }
            other => return Err(format!("opzione sconosciuta: {other}")),
        }
    }
    Ok(p)
}

/// Modifica i dischi del profilo applicato, li applica e allinea i segnalibri.
fn edit_shares(
    env: &Env,
    change: impl FnOnce(&mut Vec<bnw_core::profile::Share>) -> Result<(), String>,
) -> ExitCode {
    let Some(mut p) = status::installed_profile(env) else {
        return fail("nessun profilo applicato su questa macchina");
    };
    let before = p.shares.clone();
    if let Err(e) = change(&mut p.shares) {
        return fail(&e);
    }
    if let Err(e) = bnw_core::validate::profile(&p) {
        return fail(&e.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "));
    }
    let after = p.shares.clone();
    let code = cmd_helper(
        env,
        &Action::ApplyShares {
            profile: p,
            owner_uid: user::current_uid(),
        },
    );
    if code == ExitCode::SUCCESS
        && let Some(home) = std::env::var_os("HOME")
    {
        match user::sync_bookmarks(Path::new(&home), &before, &after) {
            Ok(true) => println!("✓ segnalibri aggiornati"),
            Ok(false) => {}
            Err(e) => eprintln!("segnalibri: {e}"),
        }
    }
    code
}

fn edit_printers(
    env: &Env,
    change: impl FnOnce(&mut Vec<bnw_core::profile::Printer>) -> Result<(), String>,
) -> ExitCode {
    let Some(mut p) = status::installed_profile(env) else {
        return fail("nessun profilo applicato su questa macchina");
    };
    if let Err(e) = change(&mut p.printers) {
        return fail(&e);
    }
    if let Err(e) = bnw_core::validate::profile(&p) {
        return fail(&e.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "));
    }
    cmd_helper(env, &Action::ApplyPrinters { profile: p })
}

fn prompt(question: &str) -> String {
    print!("{question}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let mut answer = String::new();
    let _ = std::io::stdin().read_line(&mut answer);
    answer.trim().to_string()
}

/// Prima configurazione: controlli, profilo, utenza e password, applicazione.
fn cmd_setup(env: &Env, file: &str) -> ExitCode {
    if behind_own_proxy() {
        return fail("sei dentro una sessione che passa dal proxy: usa un terminale normale o l'app");
    }
    println!("Controlli:");
    let checks = bnw_client::checks::run();
    for c in &checks {
        println!("  {} {:<28} {}", if c.ok { "✓" } else { "✗" }, c.what, c.why);
    }
    if checks.iter().any(|c| c.required && !c.ok) {
        println!("\n{}", bnw_client::checks::MISSING_HINT);
        return fail("manca qualcosa di indispensabile");
    }
    println!();
    let b = match cmd_show(file) {
        Ok(b) => b,
        Err(e) => return fail(&e),
    };
    configure(env, &b)
}

/// Applica il profilo con l'utenza, poi scrive la password di dominio nei quattro posti.
/// Serve all'import come alla prima configurazione: senza utenza la VPN non si connette.
fn configure(env: &Env, b: &bnw_core::bundle::Bundle) -> ExitCode {
    let hint = b
        .profile
        .company
        .user_hint
        .clone()
        .unwrap_or_else(|| "nome.cognome".into());
    let user = prompt(&format!(
        "\nUtenza di dominio {} (es. {hint}): ",
        b.profile.company.domain
    ));
    if let Err(e) = bnw_core::validate::target(&bnw_core::Target {
        domain_user: user.clone(),
        uid: 0,
        gid: 0,
    }) {
        return fail(&e.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "));
    }

    println!("\nApplico il profilo (proxy, VPN, WiFi, dischi, stampanti)…");
    let before = status::installed_profile(env)
        .map(|p| p.shares)
        .unwrap_or_default();
    if cmd_helper(env, &bnw_client::bundle::apply_action(b, Some(user.clone()))) != ExitCode::SUCCESS {
        println!("Alcuni passi non sono riusciti: li vedi sopra con ✗. Si può rilanciare.");
    }
    if let Some(home) = std::env::var_os("HOME") {
        let _ = user::sync_bookmarks(Path::new(&home), &before, &b.profile.shares);
    }

    println!("\nOra la password di dominio: va in proxy, VPN, WiFi e dischi.");
    loop {
        let Ok(pw) = rpassword::prompt_password("Password di dominio (non viene mostrata): ") else {
            return fail("impossibile leggere la password dal terminale");
        };
        let Ok(again) = rpassword::prompt_password("Ripetila: ") else {
            return fail("impossibile leggere la password dal terminale");
        };
        if pw.is_empty() || pw != again {
            println!("Vuota o diversa: riprova.");
            continue;
        }
        let action = Action::SetPassword {
            password: bnw_core::Secret::new(pw),
            only: Vec::new(),
            domain_user: Some(user.clone()),
        };
        let r = match helper::run(env, &action) {
            Ok(r) => r,
            Err(e) => return fail(&e.to_string()),
        };
        if r.rejected_before_writing() {
            println!("\n407: il proxy aziendale rifiuta questa password. Non ho scritto niente: riprova.\n");
            continue;
        }
        print!("{}", format_report(&r));
        match r.ntlm {
            Some(NtlmCheck::Ok { .. }) => println!("\nFatto: il proxy aziendale accetta la password."),
            Some(NtlmCheck::NotRun) | None => println!(
                "\nFatto. La prova del proxy si fa sulla rete aziendale o in VPN: «bnw proxy test https://www.google.com»."
            ),
            _ => {}
        }
        println!("Apri una sessione nuova (o riavvia) perché le applicazioni vedano il proxy.");
        return if r.failed() {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
    }
}

fn cmd_offline(out: &str, flags: &[&str]) -> ExitCode {
    let mut extra = Vec::new();
    let mut it = flags.iter();
    while let Some(f) = it.next() {
        match (*f, it.next()) {
            ("--search", Some(d)) => extra.push(std::path::PathBuf::from(d)),
            _ => return fail(&format!("opzione non valida: {f}")),
        }
    }
    if Path::new(out).exists() {
        return fail(&format!("{out} esiste già: non lo sovrascrivo"));
    }
    println!("Calcolo i pacchetti…");
    let plan = bnw_client::offline::plan(&extra);
    for (p, path) in &plan.found {
        println!("  ✓ {:<28} {}", p.name, path.display());
    }
    for p in &plan.missing {
        println!(
            "  ✗ {:<28} non trovato (--search CARTELLA per indicare dove sta)",
            p.name
        );
    }
    if plan
        .missing
        .iter()
        .any(|p| p.name == "business-network-wizard" || p.name == "cntlm")
    {
        return fail("mancano pacchetti indispensabili: il bundle non servirebbe");
    }
    if let Err(e) = bnw_client::offline::write(&plan, Path::new(out)) {
        return fail(&format!("{out}: {e}"));
    }
    if !plan.v3().is_empty() {
        println!(
            "\nAttenzione: {} pacchetti sono x86_64_v3 (CachyOS): si installano solo su CPU recenti.",
            plan.v3().len()
        );
    }
    let size = std::fs::metadata(out).map(|m| m.len() / 1024 / 1024).unwrap_or(0);
    println!("\nBundle scritto: {out} ({size} MB). Sul PC nuovo: tar xf e poi sh installa.sh");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percorsi_unc() {
        let ok = Some(("fs1.corp.esempio".to_string(), "ESEMPIO".to_string()));
        assert_eq!(parse_unc("//fs1.corp.esempio/ESEMPIO"), ok);
        assert_eq!(parse_unc(r"\\fs1.corp.esempio\ESEMPIO"), ok);
        assert_eq!(parse_unc("//fs1.corp.esempio/ESEMPIO/"), ok);
        assert_eq!(parse_unc("//server"), None);
        assert_eq!(parse_unc("/mnt/x"), None);
        assert_eq!(parse_unc("//s/a/b"), None);
        let p = parse_printer("P", "ipp://h/ipp", &["--duplex", "--location", "Piano 3"]).unwrap();
        assert!(p.duplex);
        assert_eq!(p.location.as_deref(), Some("Piano 3"));
        assert!(parse_printer("P", "ipp://h/ipp", &["--boh"]).is_err());
    }
}
