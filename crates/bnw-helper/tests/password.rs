//! Cambio password su una radice finta che imita la macchina di esempio: keyfile di NetworkManager,
//! cntlm.conf, credenziali CIFS, una share montata, rete aziendale attiva.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use bnw_core::Secret;
use bnw_core::action::{Action, NtlmCheck, Outcome, Place, Report};
use bnw_helper::sys::{CmdOutput, Fs, Runner};

const PW: &str = "Nuova;Password=2026";

struct Fake {
    calls: Vec<(String, Option<String>)>,
    curl_code: &'static str,
    /// Esito della prova con il cntlm temporaneo; `None` = proxy aziendale irraggiungibile.
    trial: Option<u16>,
    /// La configurazione che la prova ha ricevuto.
    trial_conf: Option<String>,
}

impl Fake {
    fn new(curl_code: &'static str) -> Fake {
        Fake {
            calls: Vec::new(),
            curl_code,
            trial: None,
            trial_conf: None,
        }
    }

    fn with_trial(curl_code: &'static str, trial: u16) -> Fake {
        Fake {
            trial: Some(trial),
            ..Fake::new(curl_code)
        }
    }

    fn lines(&self) -> Vec<&str> {
        self.calls.iter().map(|(c, _)| c.as_str()).collect()
    }
}

impl Runner for Fake {
    fn run(&mut self, program: &str, args: &[&str], stdin: Option<&str>) -> std::io::Result<CmdOutput> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.calls.push((line, stdin.map(str::to_string)));
        let stdout = match program {
            "/usr/bin/cntlm" => "PassLM          AAAA\nPassNT          BBBB\nPassNTLMv2      CCCC    # Only for user 'mario.rossi', domain 'ESEMPIO'\n".into(),
            "/usr/bin/curl" => self.curl_code.to_string(),
            _ => String::new(),
        };
        Ok(CmdOutput {
            success: true,
            stdout,
            stderr: String::new(),
        })
    }

    fn pause(&self, _ms: u64) {}

    fn listening(&self, _port: u16) -> bool {
        true
    }

    fn reachable(&self, host_port: &str) -> bool {
        assert_eq!(host_port, "10.20.30.40:3128");
        self.trial.is_some()
    }

    fn ntlm_trial(&mut self, conf: &Path, url: &str) -> std::io::Result<u16> {
        assert_eq!(url, "https://www.google.com");
        let text = fs::read_to_string(conf)?;
        assert_eq!(fs::metadata(conf)?.permissions().mode() & 0o777, 0o600);
        self.trial_conf = Some(text);
        Ok(self.trial.unwrap())
    }
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/esempio")
}

fn put(root: &Path, abs: &str, content: &str, mode: u32) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, content).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
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

const VPN_KEYFILE: &str = "/etc/NetworkManager/system-connections/Esempio.nmconnection";
const WIFI_KEYFILE: &str = "/etc/NetworkManager/system-connections/Esempio-802.1X.nmconnection";
const CRED: &str = "/etc/samba/credentials/esempio";

fn cntlm_old() -> String {
    fs::read_to_string(fixtures().join("etc/cntlm.conf.senza-hash"))
        .unwrap()
        .replace(
            "Domain          ESEMPIO\n",
            "Domain          ESEMPIO\nPassNT          1111\nPassNTLMv2      2222\n",
        )
}

fn esempio(root: &Path, upstream: bool) {
    let profile = fs::read_to_string(fixtures().join("profile.toml")).unwrap();
    put(root, "/etc/bnw/profile.toml", &profile, 0o644);
    put(
        root,
        VPN_KEYFILE,
        "[connection]\nid=Esempio\nuuid=9fa2\ntype=vpn\n\n[vpn]\nusername=mario.rossi\npassword-flags=1\n\n[vpn-secrets]\npassword=Vecchia\n\n[ipv4]\nmethod=auto\n",
        0o600,
    );
    put(
        root,
        WIFI_KEYFILE,
        "[connection]\nid=Esempio-802.1X\ntype=wifi\n\n[802-1x]\neap=peap;\nidentity=mario.rossi\npassword-flags=0\n\n[ipv4]\nmethod=auto\n",
        0o600,
    );
    put(
        root,
        "/etc/NetworkManager/system-connections/Casa.nmconnection",
        "[connection]\nid=Casa\n",
        0o600,
    );
    put(root, "/etc/cntlm.conf", &cntlm_old(), 0o600);
    put(
        root,
        CRED,
        "username=mario.rossi\ndomain=ESEMPIO\npassword=Vecchia\n",
        0o600,
    );
    fs::set_permissions(
        root.join("etc/samba/credentials"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    put(
        root,
        "/proc/mounts",
        "/dev/sda1 / btrfs rw 0 0\n//fs1.corp.esempio/ESEMPIO /mnt/esempio cifs rw 0 0\n",
        0o444,
    );
    let target = if upstream {
        "/etc/tinyproxy/upstream.conf"
    } else {
        "/etc/tinyproxy/direct.conf"
    };
    fs::create_dir_all(root.join("etc/tinyproxy")).unwrap();
    std::os::unix::fs::symlink(target, root.join("etc/tinyproxy/active.conf")).unwrap();
}

fn set(root: &Path, fake: &mut Fake, only: Vec<Place>) -> Report {
    let action = Action::SetPassword {
        password: Secret::new(PW),
        only,
        domain_user: None,
    };
    bnw_helper::run(&action, Fs::new(root, false), fake)
}

#[test]
fn quattro_posti_nell_ordine_giusto() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    let mut fake = Fake::new("200");
    let r = set(root, &mut fake, vec![]);
    assert!(!r.failed(), "{r:#?}");
    assert_eq!(r.ntlm, Some(NtlmCheck::Ok { code: 200 }));

    // l'ordine collaudato: cntlm fermo prima di tutto, verifica alla fine
    let calls = fake.lines();
    assert_eq!(calls[0], "/usr/bin/systemctl stop cntlm.service");
    assert_eq!(
        calls[1],
        "/usr/bin/cntlm -H -c /dev/null -u mario.rossi -d ESEMPIO"
    );
    assert_eq!(fake.calls[1].1.as_deref(), Some(&*format!("{PW}\n")));
    assert_eq!(
        &calls[2..6],
        [
            "/usr/bin/nmcli connection reload",
            "/usr/bin/systemctl stop mnt-esempio.mount",
            "/usr/bin/systemctl start cntlm.service",
            "/usr/bin/systemctl restart tinyproxy.service",
        ]
    );
    assert!(calls[6].starts_with("/usr/bin/curl ") && calls[6].ends_with("--url https://www.google.com"));
    // la password non passa mai negli argomenti
    assert!(calls.iter().all(|c| !c.contains(PW)));

    // VPN: secret nuovo e password-flags corretto
    let vpn = read(root, VPN_KEYFILE);
    assert!(vpn.contains(&format!("[vpn-secrets]\npassword={PW}\n")), "{vpn}");
    assert!(vpn.contains("password-flags=0") && !vpn.contains("password-flags=1"));
    // WiFi: la password mancava, ora c'è nella sezione giusta
    let wifi = read(root, WIFI_KEYFILE);
    assert!(
        wifi.contains(&format!("password-flags=0\npassword={PW}\n\n[ipv4]")),
        "{wifi}"
    );
    // l'altra connessione non si tocca
    assert_eq!(
        read(root, "/etc/NetworkManager/system-connections/Casa.nmconnection"),
        "[connection]\nid=Casa\n"
    );
    // cntlm: solo le righe Pass*
    let conf = read(root, "/etc/cntlm.conf");
    assert_eq!(
        conf.lines()
            .filter(|l| !l.starts_with("Pass"))
            .collect::<Vec<_>>(),
        cntlm_old()
            .lines()
            .filter(|l| !l.starts_with("Pass"))
            .collect::<Vec<_>>()
    );
    assert!(conf.contains("PassLM          AAAA\nPassNT          BBBB\nPassNTLMv2      CCCC\n"));
    // CIFS: utente e dominio tenuti
    assert_eq!(
        read(root, CRED),
        format!("username=mario.rossi\ndomain=ESEMPIO\npassword={PW}\n")
    );

    for f in [VPN_KEYFILE, WIFI_KEYFILE, "/etc/cntlm.conf", CRED] {
        assert_eq!(mode(root, f), 0o600, "{f}");
        let dir = root.join(f.trim_start_matches('/'));
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        // i keyfile di NetworkManager hanno il backup fuori da system-connections
        let bak_dir = if f.starts_with("/etc/NetworkManager/") {
            root.join("etc/bnw/backup/NetworkManager")
        } else {
            dir.parent().unwrap().to_path_buf()
        };
        if f.starts_with("/etc/NetworkManager/") {
            let leftovers = fs::read_dir(dir.parent().unwrap())
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains(".bak-"))
                .count();
            assert_eq!(leftovers, 0, "backup dentro system-connections");
            assert_eq!(mode(root, "/etc/bnw/backup/NetworkManager"), 0o700);
        }
        let bak = fs::read_dir(&bak_dir)
            .unwrap()
            .flatten()
            .find(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{name}.bak-"))
            })
            .unwrap_or_else(|| panic!("manca il backup di {f}"));
        assert_eq!(bak.metadata().unwrap().permissions().mode() & 0o777, 0o600, "{f}");
    }
    assert_eq!(mode(root, "/etc/samba/credentials"), 0o700);

    // ogni posto compare nel rapporto, e la password no
    for p in Place::ALL {
        assert!(
            r.steps
                .iter()
                .any(|s| s.place == Some(p) && s.outcome == Outcome::Changed),
            "{p:?}"
        );
    }
    assert!(!serde_json::to_string(&r).unwrap().contains(PW));
}

#[test]
fn con_un_407_cntlm_si_ferma_subito() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path(), true);
    let mut fake = Fake::new("407");
    let r = set(tmp.path(), &mut fake, vec![]);
    assert!(r.failed());
    assert_eq!(r.ntlm, Some(NtlmCheck::Rejected));
    assert!(!r.rejected_before_writing(), "qui la password è già scritta");
    assert_eq!(
        *fake.lines().last().unwrap(),
        "/usr/bin/systemctl stop cntlm.service"
    );
    let curls = fake
        .lines()
        .iter()
        .filter(|c| c.starts_with("/usr/bin/curl"))
        .count();
    assert_eq!(curls, 1, "un solo tentativo con la password sbagliata");
}

#[test]
fn fuori_dalla_rete_aziendale_non_riaccende_cntlm() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path(), false);
    let mut fake = Fake::new("200");
    let r = set(tmp.path(), &mut fake, vec![]);
    assert!(!r.failed(), "{r:#?}");
    assert_eq!(r.ntlm, Some(NtlmCheck::NotRun));
    assert!(
        !fake
            .lines()
            .iter()
            .any(|c| c.contains("start cntlm") || c.contains("curl"))
    );
}

#[test]
fn solo_la_vpn() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    let mut fake = Fake::new("200");
    let r = set(root, &mut fake, vec![Place::Vpn]);
    assert!(!r.failed(), "{r:#?}");
    assert_eq!(fake.lines(), ["/usr/bin/nmcli connection reload"]);
    assert_eq!(read(root, "/etc/cntlm.conf"), cntlm_old());
    assert!(read(root, CRED).contains("password=Vecchia"));
    assert_eq!(r.ntlm, None);
}

#[test]
fn un_posto_mancante_non_ferma_gli_altri() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    fs::remove_file(root.join(WIFI_KEYFILE.trim_start_matches('/'))).unwrap();
    let mut fake = Fake::new("200");
    let r = set(root, &mut fake, vec![]);
    assert!(r.failed());
    let wifi: Vec<_> = r.steps.iter().filter(|s| s.place == Some(Place::Wifi)).collect();
    assert_eq!(wifi.len(), 1);
    assert_eq!(wifi[0].outcome, Outcome::Failed);
    assert!(wifi[0].detail.as_deref().unwrap().contains("Esempio-802.1X"));
    assert!(read(root, VPN_KEYFILE).contains(PW));
    assert!(read(root, CRED).contains(PW));
    assert_eq!(r.ntlm, Some(NtlmCheck::Ok { code: 200 }));
}

#[test]
fn password_su_piu_righe_non_tocca_niente() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path(), true);
    let mut fake = Fake::new("200");
    let action = Action::SetPassword {
        password: Secret::new("a\nusername=x"),
        only: vec![],
        domain_user: None,
    };
    let r = bnw_helper::run(&action, Fs::new(tmp.path(), false), &mut fake);
    assert!(r.failed());
    assert!(fake.calls.is_empty());
    assert!(read(tmp.path(), CRED).contains("password=Vecchia"));
}

fn status(root: &Path) -> (Report, Fake) {
    let mut fake = Fake::new("200");
    let r = bnw_helper::run(&Action::PasswordStatus, Fs::new(root, false), &mut fake);
    (r, fake)
}

#[test]
fn stato_dei_quattro_posti() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path(), true);
    let (r, fake) = status(tmp.path());
    // l'unico comando è il calcolo dell'hash per il confronto, con la password su stdin
    assert_eq!(
        fake.lines(),
        ["/usr/bin/cntlm -H -c /dev/null -u mario.rossi -d ESEMPIO"]
    );
    assert_eq!(fake.calls[0].1.as_deref(), Some("Vecchia\n"));
    let by = |p: Place| r.steps.iter().find(|s| s.place == Some(p)).unwrap();
    assert_eq!(by(Place::Vpn).outcome, Outcome::Unchanged);
    assert!(by(Place::Vpn).mtime.is_some());
    // il WiFi non ha la password salvata: lo stato lo dice
    assert_eq!(by(Place::Wifi).outcome, Outcome::Failed);
    assert_eq!(
        by(Place::Wifi).detail.as_deref(),
        Some("nessuna password salvata")
    );
    // l'hash NT salvato (1111) non è quello di «Vecchia» (BBBB per il finto cntlm)
    assert_eq!(by(Place::Cntlm).outcome, Outcome::Failed);
    assert!(by(Place::Cntlm).detail.as_deref().unwrap().contains("diversa"));
    assert_eq!(r.password_aligned, Some(false));
    assert_eq!(by(Place::Cifs).what, CRED);
    assert!(!serde_json::to_string(&r).unwrap().contains("Vecchia"));
}

#[test]
fn stato_allineato() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    put(
        root,
        "/etc/cntlm.conf",
        &cntlm_old().replace("PassNT          1111", "PassNT          BBBB"),
        0o600,
    );
    let (r, _) = status(root);
    // dove c'è, la password è la stessa; il WiFi senza password è segnalato a parte
    assert_eq!(r.password_aligned, Some(true), "{r:#?}");
    assert!(r.failed());
    let wifi = read(root, WIFI_KEYFILE).replace("password-flags=0\n", "password-flags=0\npassword=Vecchia\n");
    put(root, WIFI_KEYFILE, &wifi, 0o600);
    let (r, _) = status(root);
    assert_eq!(r.password_aligned, Some(true), "{r:#?}");
    assert!(!r.failed());
}

#[test]
fn dopo_il_cambio_tutto_allineato() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    let mut fake = Fake::new("200");
    assert!(!set(root, &mut fake, vec![]).failed());
    let (r, _) = status(root);
    assert_eq!(r.password_aligned, Some(true), "{r:#?}");
}

#[test]
fn una_password_diversa_tra_le_tre_in_chiaro() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    let wifi = read(root, WIFI_KEYFILE).replace("password-flags=0\n", "password-flags=0\npassword=Altra\n");
    put(root, WIFI_KEYFILE, &wifi, 0o600);
    let (r, _) = status(root);
    assert_eq!(r.password_aligned, Some(false));
    let wrong: Vec<Place> = r
        .steps
        .iter()
        .filter(|s| s.outcome == Outcome::Failed)
        .filter_map(|s| s.place)
        .collect();
    // VPN e CIFS concordano: la diversa è il WiFi (e cntlm, con gli hash finti)
    assert!(wrong.contains(&Place::Wifi) && !wrong.contains(&Place::Vpn) && !wrong.contains(&Place::Cifs));
}

#[test]
fn stop_e_start_di_cntlm() {
    let tmp = tempfile::tempdir().unwrap();
    esempio(tmp.path(), false);
    let mut fake = Fake::new("200");
    bnw_helper::run(&Action::StopCntlm, Fs::new(tmp.path(), false), &mut fake);
    let r = bnw_helper::run(&Action::StartCntlm, Fs::new(tmp.path(), false), &mut fake);
    // in modalità diretta cntlm non va riacceso
    assert_eq!(fake.lines(), ["/usr/bin/systemctl stop cntlm.service"]);
    assert_eq!(r.steps[0].outcome, Outcome::Skipped);
}

fn backups(root: &Path) -> usize {
    fn walk(dir: &Path) -> usize {
        fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| {
                        let p = e.path();
                        if p.is_dir() {
                            walk(&p)
                        } else {
                            usize::from(p.to_string_lossy().contains(".bak-"))
                        }
                    })
                    .sum()
            })
            .unwrap_or(0)
    }
    walk(root)
}

#[test]
fn password_rifiutata_dalla_prova_non_scrive_niente() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    let vpn_before = read(root, VPN_KEYFILE);
    let mut fake = Fake::with_trial("200", 407);
    let r = set(root, &mut fake, vec![]);

    assert!(r.failed());
    assert_eq!(r.ntlm, Some(NtlmCheck::Rejected));
    assert!(r.rejected_before_writing());
    // solo: cntlm fermo e hash calcolati. Nessuna scrittura, nessun riavvio.
    assert_eq!(
        fake.lines(),
        [
            "/usr/bin/systemctl stop cntlm.service",
            "/usr/bin/cntlm -H -c /dev/null -u mario.rossi -d ESEMPIO"
        ]
    );
    assert_eq!(read(root, VPN_KEYFILE), vpn_before);
    assert_eq!(read(root, "/etc/cntlm.conf"), cntlm_old());
    assert!(read(root, CRED).contains("password=Vecchia"));
    assert_eq!(backups(root), 0);
    // la configurazione temporanea, con gli hash, non resta in giro
    assert!(!root.join("run/bnw/cntlm-prova.conf").exists());
    let detail = r.steps.last().unwrap().detail.as_deref().unwrap();
    assert!(detail.contains("Non ho scritto niente"), "{detail}");
}

#[test]
fn password_accettata_dalla_prova_poi_si_scrive() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    let mut fake = Fake::with_trial("200", 200);
    let r = set(root, &mut fake, vec![]);
    assert!(!r.failed(), "{r:#?}");
    let trial = r
        .steps
        .iter()
        .find(|s| s.what == "prova della password nuova")
        .unwrap();
    assert_eq!(trial.outcome, Outcome::Changed);
    // la prova usa gli hash nuovi, i proxy del profilo e nessun Listen fisso
    let conf = fake.trial_conf.unwrap();
    assert!(conf.contains("PassNTLMv2      CCCC\n") && conf.contains("Proxy           10.20.30.40:3128\n"));
    assert!(conf.contains("Username        mario.rossi\nDomain          ESEMPIO\n"));
    assert!(!conf.contains("Listen"), "{conf}");
    assert!(!root.join("run/bnw/cntlm-prova.conf").exists());
    assert!(read(root, VPN_KEYFILE).contains(PW));
    assert_eq!(r.ntlm, Some(NtlmCheck::Ok { code: 200 }));
}

#[test]
fn prova_inconcludente_non_blocca() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    let mut fake = Fake::with_trial("200", 0);
    let r = set(root, &mut fake, vec![]);
    assert!(!r.failed(), "{r:#?}");
    let trial = r
        .steps
        .iter()
        .find(|s| s.what == "prova della password nuova")
        .unwrap();
    assert_eq!(trial.outcome, Outcome::Skipped);
    assert!(read(root, CRED).contains(PW));
}

#[test]
fn macchina_nuova_cntlm_e_credenziali_da_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    fs::remove_file(root.join("etc/cntlm.conf")).unwrap();
    fs::remove_file(root.join("etc/samba/credentials/esempio")).unwrap();
    let mut fake = Fake::new("200");
    // senza utenza non si può
    let r = set(root, &mut fake, vec![Place::Cntlm]);
    assert!(r.failed());
    let action = Action::SetPassword {
        password: Secret::new(PW),
        only: vec![Place::Cntlm, Place::Cifs],
        domain_user: Some("nuovo.utente".into()),
    };
    let mut fake = Fake::new("200");
    let r = bnw_helper::run(&action, Fs::new(root, false), &mut fake);
    assert!(!r.failed(), "{r:#?}");
    let conf = read(root, "/etc/cntlm.conf");
    assert!(
        conf.starts_with("Username        nuovo.utente\nDomain          ESEMPIO\nPassLM"),
        "{conf}"
    );
    assert!(conf.contains("Proxy           10.20.30.40:3128\n"));
    assert_eq!(mode(root, "/etc/cntlm.conf"), 0o600);
    assert_eq!(
        read(root, CRED),
        format!("username=nuovo.utente\ndomain=ESEMPIO\npassword={PW}\n")
    );
    assert!(
        fake.lines()
            .contains(&"/usr/bin/cntlm -H -c /dev/null -u nuovo.utente -d ESEMPIO")
    );
}

#[test]
fn vpn_senza_utenza_la_prende_da_cntlm() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    let vpn = read(root, VPN_KEYFILE).replace("username=mario.rossi\n", "");
    put(root, VPN_KEYFILE, &vpn, 0o600);
    let mut fake = Fake::new("200");
    let r = set(root, &mut fake, vec![]);
    assert!(!r.failed(), "{r:#?}");
    let vpn = read(root, VPN_KEYFILE);
    assert!(vpn.contains("username=mario.rossi"), "{vpn}");
    assert!(vpn.contains(PW));
}

#[test]
fn vpn_senza_utenza_da_nessuna_parte_lo_dice() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    let vpn = read(root, VPN_KEYFILE).replace("username=mario.rossi\n", "");
    put(root, VPN_KEYFILE, &vpn, 0o600);
    // come dopo un import senza utenza: nessun file la conosce
    fs::remove_file(root.join("etc/cntlm.conf")).unwrap();
    fs::remove_file(root.join(CRED.trim_start_matches('/'))).unwrap();
    let mut fake = Fake::new("200");
    let r = set(root, &mut fake, vec![Place::Vpn]);
    assert!(r.failed());
    assert!(r.steps.iter().any(|s| s.what == "utenza della VPN" && s.outcome == Outcome::Failed));
    // la password comunque è stata salvata
    assert!(read(root, VPN_KEYFILE).contains(PW));
}

#[test]
fn cntlm_conf_di_esempio_del_pacchetto_si_riscrive() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    esempio(root, true);
    // come il file installato dal pacchetto cntlm: niente utenza, proxy d'esempio
    put(
        root,
        "/etc/cntlm.conf",
        "#Username\ttestuser\n#Domain\t\tcorp-uk\nProxy\t\t10.0.0.41:8080\nListen\t\t3128\n",
        0o600,
    );
    let action = Action::SetPassword {
        password: Secret::new(PW),
        only: vec![Place::Cntlm],
        domain_user: Some("mario.rossi".into()),
    };
    let mut fake = Fake::new("200");
    let r = bnw_helper::run(&action, Fs::new(root, false), &mut fake);
    assert!(!r.failed(), "{r:#?}");
    let conf = read(root, "/etc/cntlm.conf");
    assert!(conf.starts_with("Username        mario.rossi\nDomain          ESEMPIO\n"), "{conf}");
    assert!(conf.contains("Proxy           10.20.30.40:3128\n"), "{conf}");
    assert!(!conf.contains("10.0.0.41"), "{conf}");
}
