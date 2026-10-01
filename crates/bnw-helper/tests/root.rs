//! L'helper su una radice finta: scrive i file giusti, con i permessi giusti, fa i
//! backup e lancia i comandi nell'ordine giusto. Nessun comando viene eseguito.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use bnw_core::Profile;
use bnw_core::Secret;
use bnw_core::action::{Action, Outcome, ProxyMode, Report};
use bnw_helper::sys::{CmdOutput, Fs, Runner};

fn fixture(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/esempio")
        .join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn profile() -> Profile {
    Profile::from_toml(&fixture("profile.toml")).unwrap()
}

/// Annota i comandi (con lo stdin, per controllare il canale dei segreti) e risponde
/// con uscite preparate.
#[derive(Default)]
struct Fake {
    calls: Vec<(String, Option<String>)>,
    cntlm_output: String,
}

impl Runner for Fake {
    fn run(&mut self, program: &str, args: &[&str], stdin: Option<&str>) -> std::io::Result<CmdOutput> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.calls.push((line, stdin.map(str::to_string)));
        let stdout = if program.ends_with("/cntlm") {
            self.cntlm_output.clone()
        } else {
            String::new()
        };
        Ok(CmdOutput {
            success: true,
            stdout,
            stderr: String::new(),
        })
    }
}

fn run(root: &Path, action: &Action, fake: &mut Fake) -> Report {
    let r = bnw_helper::run(action, Fs::new(root, false), fake);
    assert!(!r.failed(), "{r:#?}");
    r
}

fn read(root: &Path, abs: &str) -> String {
    fs::read_to_string(root.join(abs.trim_start_matches('/'))).unwrap()
}

fn mode(root: &Path, abs: &str) -> u32 {
    fs::metadata(root.join(abs.trim_start_matches('/')))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn backups(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        for e in fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() && !p.is_symlink() {
                walk(&p, out);
            } else if p.to_string_lossy().contains(".bak-") {
                out.push(p.to_string_lossy().into_owned());
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

fn outcome(r: &Report, what: &str) -> Outcome {
    r.steps
        .iter()
        .find(|s| s.what == what)
        .unwrap_or_else(|| panic!("manca {what}: {r:#?}"))
        .outcome
}

#[test]
fn apply_proxy_su_radice_vuota_e_poi_rilanciato() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let action = Action::ApplyProxy { profile: profile() };

    let mut fake = Fake::default();
    let r = run(root, &action, &mut fake);

    assert_eq!(
        read(root, "/etc/tinyproxy/direct.conf"),
        fixture("etc/tinyproxy/direct.conf")
    );
    assert_eq!(
        read(root, "/etc/tinyproxy/upstream.conf"),
        fixture("etc/tinyproxy/upstream.conf")
    );
    assert_eq!(
        fs::read_link(root.join("etc/tinyproxy/active.conf")).unwrap(),
        Path::new("/etc/tinyproxy/direct.conf")
    );
    assert_eq!(
        read(root, "/etc/firefox/policies/policies.json"),
        fixture("etc/firefox/policies/policies.json")
    );
    assert_eq!(
        read(root, "/etc/zen/policies/policies.json"),
        fixture("etc/zen/policies/policies.json")
    );
    assert_eq!(
        read(root, "/etc/bnw/proxy-detect.conf"),
        "# Generato da Business Network Wizard: non modificare a mano.\nVPN_NAME=Esempio\nPROXY=10.20.30.40:3128\n"
    );
    assert_eq!(
        Profile::from_toml(&read(root, "/etc/bnw/profile.toml")).unwrap(),
        profile()
    );
    assert!(read(root, "/etc/environment").contains("https_proxy=http://127.0.0.1:8118\n"));
    assert_eq!(mode(root, "/etc/tinyproxy/upstream.conf"), 0o644);
    assert_eq!(outcome(&r, "/etc/cntlm.conf"), Outcome::Skipped);

    let calls: Vec<&str> = fake.calls.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(
        calls,
        [
            "/usr/bin/systemctl enable --now tinyproxy.service",
            "/usr/bin/systemctl disable cntlm.service",
            "/usr/bin/systemctl restart tinyproxy.service",
            "/usr/bin/systemctl start bnw-proxy-detect.service",
        ]
    );

    // Rilanciato: niente cambia, niente backup, tinyproxy non si riavvia.
    let mut fake = Fake::default();
    let r = run(root, &action, &mut fake);
    for s in &r.steps {
        if s.what.starts_with('/') {
            assert_ne!(s.outcome, Outcome::Changed, "{s:?}");
        }
    }
    assert!(backups(root).is_empty(), "{:?}", backups(root));
    assert!(!fake.calls.iter().any(|(c, _)| c.contains("restart")));
}

#[test]
fn apply_proxy_rispetta_i_file_esistenti() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let etc = root.join("etc");
    fs::create_dir_all(etc.join("firefox/policies")).unwrap();
    fs::write(
        etc.join("environment"),
        "LANG=it_IT.UTF-8\nhttp_proxy=http://vecchio:1\n",
    )
    .unwrap();
    fs::write(
        etc.join("firefox/policies/policies.json"),
        r#"{"policies":{"DisableTelemetry":true}}"#,
    )
    .unwrap();
    // cntlm.conf come su la macchina di esempio, con hash finti
    let cntlm = fixture("etc/cntlm.conf.senza-hash").replace(
        "Domain          ESEMPIO\n",
        "Domain          ESEMPIO\nPassNT          AB12\nPassNTLMv2      CD34\n",
    );
    fs::write(etc.join("cntlm.conf"), &cntlm).unwrap();
    fs::set_permissions(etc.join("cntlm.conf"), fs::Permissions::from_mode(0o600)).unwrap();
    // active.conf già su upstream: non va toccato
    fs::create_dir_all(etc.join("tinyproxy")).unwrap();
    std::os::unix::fs::symlink("/etc/tinyproxy/upstream.conf", etc.join("tinyproxy/active.conf")).unwrap();

    let mut fake = Fake::default();
    let r = run(root, &Action::ApplyProxy { profile: profile() }, &mut fake);

    let env = read(root, "/etc/environment");
    assert!(
        env.starts_with("LANG=it_IT.UTF-8\nhttp_proxy=http://127.0.0.1:8118\n"),
        "{env}"
    );
    assert!(read(root, "/etc/firefox/policies/policies.json").contains("\"DisableTelemetry\": true"));
    assert_eq!(
        fs::read_link(etc.join("tinyproxy/active.conf")).unwrap(),
        Path::new("/etc/tinyproxy/upstream.conf")
    );

    // cntlm: cambia solo NoProxy, gli hash restano, i permessi pure
    let new = read(root, "/etc/cntlm.conf");
    assert!(new.contains("PassNT          AB12\nPassNTLMv2      CD34\n"));
    assert!(new.contains("NoProxy         localhost, 127.*, 10.*"));
    assert_eq!(mode(root, "/etc/cntlm.conf"), 0o600);
    assert_eq!(outcome(&r, "/etc/cntlm.conf"), Outcome::Changed);
    assert!(
        fake.calls
            .iter()
            .any(|(c, _)| c == "/usr/bin/systemctl try-restart cntlm.service")
    );

    // un backup per ognuno dei tre file esistenti che sono cambiati
    let mut b = backups(root);
    b.sort();
    assert_eq!(b.len(), 3, "{b:?}");
    let bak = b.iter().find(|p| p.contains("cntlm.conf.bak-")).unwrap();
    assert_eq!(fs::read_to_string(bak).unwrap(), cntlm);
    assert_eq!(fs::metadata(bak).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn profilo_non_valido_non_tocca_niente() {
    let tmp = tempfile::tempdir().unwrap();
    let mut p = profile();
    p.shares[0].mount = "/etc/passwd".into();
    p.proxy.direct.push(bnw_core::profile::DirectRule::Host(
        "x\"\nupstream none \"*".into(),
    ));
    let mut fake = Fake::default();
    let r = bnw_helper::run(
        &Action::ApplyProxy { profile: p },
        Fs::new(tmp.path(), false),
        &mut fake,
    );
    assert!(r.failed());
    assert_eq!(r.steps.len(), 1);
    let detail = r.steps[0].detail.as_deref().unwrap();
    assert!(
        detail.contains("share[0].mount") && detail.contains("proxy.direct[9]"),
        "{detail}"
    );
    assert!(fs::read_dir(tmp.path()).unwrap().next().is_none());
    assert!(fake.calls.is_empty());
}

#[test]
fn write_cntlm_ferma_prima_e_passa_la_password_su_stdin() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    run(
        root,
        &Action::ApplyProxy { profile: profile() },
        &mut Fake::default(),
    );

    let mut fake = Fake {
        cntlm_output: "Password: \nPassLM          1111\nPassNT          2222\nPassNTLMv2      3333    # Only for user 'u', domain 'ESEMPIO'\n".into(),
        ..Default::default()
    };
    let action = Action::WriteCntlm {
        domain_user: "mario.rossi".into(),
        password: Secret::new("pw segreta"),
    };
    run(root, &action, &mut fake);

    assert_eq!(fake.calls[0].0, "/usr/bin/systemctl stop cntlm.service");
    assert_eq!(
        fake.calls[1],
        (
            "/usr/bin/cntlm -H -c /dev/null -u mario.rossi -d ESEMPIO".to_string(),
            Some("pw segreta\n".to_string())
        )
    );
    assert_eq!(
        fake.calls.len(),
        2,
        "cntlm non va riavviato qui: {:?}",
        fake.calls
    );
    let conf = read(root, "/etc/cntlm.conf");
    assert!(conf.starts_with("Username        mario.rossi\nDomain          ESEMPIO\nPassLM          1111\n"));
    assert!(!conf.contains("segreta"));
    assert_eq!(mode(root, "/etc/cntlm.conf"), 0o600);
}

#[test]
fn write_cntlm_rifiuta_password_su_piu_righe() {
    let tmp = tempfile::tempdir().unwrap();
    let mut fake = Fake::default();
    let action = Action::WriteCntlm {
        domain_user: "u".into(),
        password: Secret::new("a\nb"),
    };
    let r = bnw_helper::run(&action, Fs::new(tmp.path(), false), &mut fake);
    assert!(r.failed());
    assert!(fake.calls.is_empty());
}

#[test]
fn write_cntlm_senza_profilo_applicato() {
    let tmp = tempfile::tempdir().unwrap();
    let mut fake = Fake::default();
    let action = Action::WriteCntlm {
        domain_user: "u".into(),
        password: Secret::new("p"),
    };
    let r = bnw_helper::run(&action, Fs::new(tmp.path(), false), &mut fake);
    assert!(r.failed());
    assert!(
        fake.calls.is_empty(),
        "cntlm non va nemmeno fermato: {:?}",
        fake.calls
    );
}

#[test]
fn set_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let mut fake = Fake::default();
    run(tmp.path(), &Action::SetMode { mode: ProxyMode::Off }, &mut fake);
    assert_eq!(fake.calls[0].0, "/usr/bin/proxy-mode off");
}
