//! Dischi di rete e stampanti su una radice finta che imita la macchina di esempio: le unit vere dai
//! fixture, una share montata, un CUPS finto con la STAMPA_P1 com'è oggi.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use bnw_core::Profile;
use bnw_core::action::{Action, Outcome, Report};
use bnw_core::profile::{Printer, Share};
use bnw_helper::sys::{CmdOutput, Fs, Runner};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/esempio")
}

fn profile() -> Profile {
    Profile::from_toml(&fs::read_to_string(fixtures().join("profile.toml")).unwrap()).unwrap()
}

/// Un CUPS finto: code → (URI, opzioni come le stampa lpoptions).
#[derive(Default)]
struct Fake {
    calls: Vec<String>,
    cups: HashMap<String, (String, String)>,
    reachable: bool,
    /// unit attive per `systemctl is-active`
    inactive: Vec<String>,
}

impl Runner for Fake {
    fn run(&mut self, program: &str, args: &[&str], _stdin: Option<&str>) -> std::io::Result<CmdOutput> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        let ok = |stdout: String| {
            Ok(CmdOutput {
                success: true,
                stdout,
                stderr: String::new(),
            })
        };
        match (program, args) {
            ("/usr/bin/systemctl", ["is-active", "--quiet", unit]) => {
                return Ok(CmdOutput {
                    success: !self.inactive.contains(&unit.to_string()),
                    ..Default::default()
                });
            }
            ("/usr/bin/lpstat", ["-v", name]) => {
                return match self.cups.get(*name) {
                    Some((uri, _)) => ok(format!("device for {name}: {uri}\n")),
                    None => Ok(CmdOutput {
                        success: false,
                        ..Default::default()
                    }),
                };
            }
            ("/usr/bin/lpoptions", ["-p", name]) => return ok(self.cups[*name].1.clone()),
            ("/usr/bin/lpadmin", ["-x", name]) => {
                self.cups.remove(*name);
            }
            ("/usr/bin/lpadmin", ["-p", name, "-E", "-v", uri, ..]) => {
                self.cups
                    .insert(name.to_string(), (uri.to_string(), "sides=one-sided".into()));
            }
            _ => {}
        }
        self.calls.push(line);
        ok(String::new())
    }

    fn reachable(&self, host_port: &str) -> bool {
        assert!(host_port.ends_with(":631"), "{host_port}");
        self.reachable
    }
}

fn put(root: &Path, abs: &str, content: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

/// la macchina di esempio: profilo applicato, unit delle 4 share, /mnt/esempio montata, credenziali.
fn esempio(root: &Path) {
    // come lo scrive l'app sul sistema vero
    put(root, "/etc/bnw/profile.toml", &profile().to_toml().unwrap());
    for e in fs::read_dir(fixtures().join("etc/systemd/system"))
        .unwrap()
        .flatten()
    {
        let name = e.file_name().to_string_lossy().to_string();
        put(
            root,
            &format!("/etc/systemd/system/{name}"),
            &fs::read_to_string(e.path()).unwrap(),
        );
    }
    put(
        root,
        "/etc/passwd",
        "root:x:0:0::/root:/bin/bash\ngt:x:1000:1000::/home/utente:/bin/fish\n",
    );
    put(
        root,
        "/proc/mounts",
        "//fs1.corp.esempio/ESEMPIO /mnt/esempio cifs rw 0 0\n",
    );
    put(
        root,
        "/etc/samba/credentials/esempio",
        "username=u\ndomain=D\npassword=p\n",
    );
    for m in ["esempio", "progetti", "area-clienti", "scambio"] {
        fs::create_dir_all(root.join("mnt").join(m)).unwrap();
    }
}

fn shares(root: &Path, fake: &mut Fake, p: Profile) -> Report {
    let r = bnw_helper::run(
        &Action::ApplyShares {
            profile: p,
            owner_uid: Some(1000),
        },
        Fs::new(root, false),
        fake,
    );
    assert!(!r.failed(), "{r:#?}");
    r
}

#[test]
fn share_di_esempio_gia_a_posto() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path());
    let mut fake = Fake::default();
    let r = shares(tmp.path(), &mut fake, profile());
    assert!(r.steps.iter().all(|s| s.outcome != Outcome::Changed), "{r:#?}");
    assert!(fake.calls.is_empty(), "{:?}", fake.calls);
}

#[test]
fn aggiungere_una_share() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root);
    let mut p = profile();
    p.shares.push(Share {
        server: "fs4.corp.esempio".into(),
        name: "NUOVA".into(),
        mount: "/mnt/nuova".into(),
        label: None,
    });
    let mut fake = Fake::default();
    shares(root, &mut fake, p);
    assert!(root.join("etc/systemd/system/mnt-nuova.mount").exists());
    assert!(root.join("mnt/nuova").is_dir());
    assert_eq!(
        fake.calls,
        [
            "/usr/bin/systemctl daemon-reload",
            "/usr/bin/systemctl enable --now mnt-nuova.automount"
        ]
    );
    // il profilo applicato la ricorda
    assert!(
        fs::read_to_string(root.join("etc/bnw/profile.toml"))
            .unwrap()
            .contains("/mnt/nuova")
    );
}

#[test]
fn togliere_una_share() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root);
    let mut p = profile();
    p.shares.retain(|s| s.mount != "/mnt/scambio");
    let mut fake = Fake::default();
    shares(root, &mut fake, p);
    assert_eq!(
        fake.calls,
        [
            "/usr/bin/systemctl disable --now mnt-scambio.automount",
            "/usr/bin/systemctl stop mnt-scambio.mount",
            "/usr/bin/systemctl daemon-reload",
        ]
    );
    assert!(!root.join("etc/systemd/system/mnt-scambio.mount").exists());
    assert!(!root.join("etc/systemd/system/mnt-scambio.automount").exists());
    assert!(!root.join("mnt/scambio").exists(), "cartella vuota tolta");
    let baks = fs::read_dir(root.join("etc/bnw/backup/systemd")).unwrap().count();
    assert_eq!(baks, 2);
    // le altre restano
    assert!(root.join("etc/systemd/system/mnt-esempio.mount").exists());
}

#[test]
fn cartella_non_vuota_resta() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root);
    fs::write(root.join("mnt/scambio/mio.txt"), "x").unwrap();
    let mut p = profile();
    p.shares.retain(|s| s.mount != "/mnt/scambio");
    shares(root, &mut Fake::default(), p);
    assert!(root.join("mnt/scambio/mio.txt").exists());
}

#[test]
fn utente_diverso_cambia_le_unit_e_smonta_quelle_montate() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root);
    put(
        root,
        "/etc/passwd",
        "gt:x:1000:1000::/home/utente:/bin/fish\naltro:x:1001:1001::/home/a:/bin/sh\n",
    );
    let mut fake = Fake::default();
    let r = bnw_helper::run(
        &Action::ApplyShares {
            profile: profile(),
            owner_uid: Some(1001),
        },
        Fs::new(root, false),
        &mut fake,
    );
    assert!(!r.failed(), "{r:#?}");
    let unit = fs::read_to_string(root.join("etc/systemd/system/mnt-esempio.mount")).unwrap();
    assert!(unit.contains("uid=1001,gid=1001"));
    // solo la share montata si smonta, per rimontare con le opzioni nuove
    assert!(
        fake.calls
            .contains(&"/usr/bin/systemctl stop mnt-esempio.mount".to_string())
    );
    assert!(
        !fake
            .calls
            .contains(&"/usr/bin/systemctl stop mnt-progetti.mount".to_string())
    );
    // backup delle unit fuori da /etc/systemd/system
    let leftovers = fs::read_dir(root.join("etc/systemd/system"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".bak-"))
        .count();
    assert_eq!(leftovers, 0);
}

#[test]
fn automount_spento_si_riaccende_e_credenziali_mancanti() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root);
    fs::remove_file(root.join("etc/samba/credentials/esempio")).unwrap();
    let mut fake = Fake {
        inactive: vec!["mnt-progetti.automount".into()],
        ..Default::default()
    };
    let r = shares(root, &mut fake, profile());
    assert_eq!(
        fake.calls,
        ["/usr/bin/systemctl enable --now mnt-progetti.automount"]
    );
    let cred = r
        .steps
        .iter()
        .find(|s| s.what == "/etc/samba/credentials/esempio")
        .unwrap();
    assert_eq!(cred.outcome, Outcome::Skipped);
}

#[test]
fn smonta_ora() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path());
    let mut fake = Fake::default();
    bnw_helper::run(&Action::UnmountShares, Fs::new(tmp.path(), false), &mut fake);
    assert_eq!(fake.calls, ["/usr/bin/systemctl stop mnt-esempio.mount"]);
}

// --- stampanti ---------------------------------------------------------------------

const OPZIONI_ESEMPIO: &str = "copies=1 device-uri=ipp://stampante-p1.corp.esempio/ipp Duplex=DuplexNoTumble printer-info='Multifunzione - Piano 1' printer-location='Esempio Piano 1' sides=one-sided";

fn cups_esempio() -> Fake {
    let mut f = Fake::default();
    f.cups.insert(
        "STAMPA_P1".into(),
        (
            "ipp://stampante-p1.corp.esempio/ipp".into(),
            OPZIONI_ESEMPIO.into(),
        ),
    );
    f
}

fn printers(root: &Path, fake: &mut Fake, p: Profile) -> Report {
    bnw_helper::run(&Action::ApplyPrinters { profile: p }, Fs::new(root, false), fake)
}

#[test]
fn la_stampante_passa_a_solo_fronte() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path());
    let mut fake = cups_esempio();
    let r = printers(tmp.path(), &mut fake, profile());
    assert!(!r.failed(), "{r:#?}");
    assert_eq!(
        fake.calls,
        ["/usr/bin/lpadmin -p STAMPA_P1 -o Duplex-default=None"]
    );
    let step = r.steps.iter().find(|s| s.what == "stampante STAMPA_P1").unwrap();
    assert_eq!(step.detail.as_deref(), Some("solo fronte"));
}

#[test]
fn stampante_gia_a_posto() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path());
    let mut fake = Fake::default();
    fake.cups.insert(
        "STAMPA_P1".into(),
        (
            "ipp://stampante-p1.corp.esempio/ipp".into(),
            OPZIONI_ESEMPIO.replace("DuplexNoTumble", "None"),
        ),
    );
    let r = printers(tmp.path(), &mut fake, profile());
    assert!(fake.calls.is_empty(), "{:?}", fake.calls);
    assert_eq!(
        r.steps
            .iter()
            .find(|s| s.what == "stampante STAMPA_P1")
            .unwrap()
            .outcome,
        Outcome::Unchanged
    );
}

#[test]
fn stampante_nuova_solo_se_raggiungibile() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path());
    let mut p = profile();
    p.printers.push(Printer {
        name: "STAMPA_P3".into(),
        uri: "ipp://stampa-p3.corp.esempio/ipp".into(),
        description: None,
        location: Some("Piano 3".into()),
        duplex: true,
    });
    let mut fake = cups_esempio();
    let r = printers(tmp.path(), &mut fake, p.clone());
    let s = r.steps.iter().find(|s| s.what == "stampante STAMPA_P3").unwrap();
    assert_eq!(s.outcome, Outcome::Skipped);
    assert!(!fake.calls.iter().any(|c| c.contains("STAMPA_P3")));

    let mut fake = cups_esempio();
    fake.reachable = true;
    let r = printers(tmp.path(), &mut fake, p);
    assert!(!r.failed(), "{r:#?}");
    assert!(fake.calls.contains(
        &"/usr/bin/lpadmin -p STAMPA_P3 -o Duplex-default=DuplexNoTumble -o sides-default=two-sided-long-edge".to_string()
    ));
    assert!(fake.cups.contains_key("STAMPA_P3"));
}

#[test]
fn stampante_tolta_dal_profilo() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path());
    let mut p = profile();
    p.printers.clear();
    let mut fake = cups_esempio();
    let r = printers(tmp.path(), &mut fake, p);
    assert!(!r.failed(), "{r:#?}");
    assert_eq!(fake.calls, ["/usr/bin/lpadmin -x STAMPA_P1"]);
    // una coda che il profilo non ha mai avuto non si tocca
    let mut fake = Fake::default();
    fake.cups
        .insert("Altra".into(), ("ipp://x/ipp".into(), String::new()));
    let mut p = profile();
    p.printers.clear();
    printers(tmp.path(), &mut fake, p);
    assert!(fake.cups.contains_key("Altra"));
}
