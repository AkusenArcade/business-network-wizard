//! VPN e WiFi con una NetworkManager finta che si comporta come quella vera dove conta:
//! GetSettings non restituisce i segreti, Update sostituisce tutto, e l'importatore
//! `.ovpn` lascia ns-cert-type, challenge-response-flags e password-flags=1.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use bnw_core::action::{Action, Outcome, Report};
use bnw_core::bundle::pem_sha1;
use bnw_core::{Blob, Profile, Secret};
use bnw_helper::nm::{self, Conn, Nm, NoNm, Settings};
use bnw_helper::sys::{CmdOutput, Fs, Runner};

const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUDEMDQ9i9cGPAL9RFyc5utN1C8aowCgYIKoZIzj0EAwIw\n-----END CERTIFICATE-----\n";
const ALTRA_CA: &str = "-----BEGIN CERTIFICATE-----\nQUxUUkEgQ0EgRElWRVJTQQ==\n-----END CERTIFICATE-----\n";
const OVPN: &str = "client\ndev tun\nproto tcp\nremote vpn.esempio.it 443\n<ca>\nCA-VPN\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nCHIAVE-PRIVATA\n</key>\nkey-direction 1\n<tls-auth>\nTA\n</tls-auth>\nns-cert-type server\nauth-user-pass\n";

#[derive(Default)]
struct State {
    conns: Vec<FakeConn>,
    updates: usize,
    next: usize,
}

struct FakeConn {
    path: String,
    settings: Settings,
    secrets: Settings,
    filename: Option<String>,
}

fn clone(s: &Settings) -> Settings {
    s.iter()
        .map(|(k, v)| {
            (
                k.clone(),
                v.iter()
                    .map(|(k, v)| (k.clone(), v.try_clone().unwrap()))
                    .collect(),
            )
        })
        .collect()
}

/// Separa i segreti dalle impostazioni, come fa NetworkManager.
fn split(mut s: Settings) -> (Settings, Settings) {
    let mut secrets = Settings::new();
    for (sec, key) in [("vpn", "secrets"), ("802-1x", "password")] {
        if let Some(v) = s.get_mut(sec).and_then(|m| m.remove(key)) {
            secrets.entry(sec.into()).or_default().insert(key.into(), v);
        }
    }
    (s, secrets)
}

struct FakeNm(Rc<RefCell<State>>);

impl Nm for FakeNm {
    fn find(&mut self, id: &str) -> io::Result<Option<Conn>> {
        let st = self.0.borrow();
        Ok(st
            .conns
            .iter()
            .find(|c| nm::get_str(&c.settings, "connection", "id").as_deref() == Some(id))
            .map(|c| Conn {
                path: c.path.clone(),
                settings: clone(&c.settings),
                filename: c.filename.clone(),
            }))
    }
    fn secrets(&mut self, path: &str, setting: &str) -> io::Result<Settings> {
        let st = self.0.borrow();
        let c = st.conns.iter().find(|c| c.path == path).unwrap();
        let mut out = Settings::new();
        if let Some(m) = c.secrets.get(setting) {
            out.insert(
                setting.into(),
                m.iter()
                    .map(|(k, v)| (k.clone(), v.try_clone().unwrap()))
                    .collect(),
            );
        }
        Ok(out)
    }
    fn update(&mut self, path: &str, settings: &Settings) -> io::Result<()> {
        let mut st = self.0.borrow_mut();
        st.updates += 1;
        let (s, sec) = split(clone(settings));
        let c = st.conns.iter_mut().find(|c| c.path == path).unwrap();
        c.settings = s;
        c.secrets = sec;
        Ok(())
    }
    fn add(&mut self, settings: &Settings) -> io::Result<String> {
        let mut st = self.0.borrow_mut();
        st.next += 1;
        let path = format!("/nm/{}", st.next);
        let (s, sec) = split(clone(settings));
        st.conns.push(FakeConn {
            path: path.clone(),
            settings: s,
            secrets: sec,
            filename: None,
        });
        Ok(path)
    }
    fn delete(&mut self, path: &str) -> io::Result<()> {
        self.0.borrow_mut().conns.retain(|c| c.path != path);
        Ok(())
    }
}

/// Il runner: l'unico comando che conta è l'import, che crea la connessione come
/// farebbe l'importatore vero.
struct FakeRun {
    state: Rc<RefCell<State>>,
    calls: Vec<String>,
}

impl Runner for FakeRun {
    fn run(&mut self, program: &str, args: &[&str], _stdin: Option<&str>) -> io::Result<CmdOutput> {
        self.calls.push(
            std::iter::once(program)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" "),
        );
        if program == "/usr/bin/nmcli" && args[..4] == ["connection", "import", "type", "openvpn"] {
            let file = Path::new(args[5]);
            let text = fs::read_to_string(file).unwrap();
            assert!(
                !text.contains("CHIAVE-PRIVATA"),
                "l'import deve ricevere i file, non i blocchi"
            );
            let mut data: HashMap<String, String> = HashMap::new();
            for l in text.lines() {
                let w: Vec<&str> = l.split_whitespace().collect();
                match w.as_slice() {
                    ["remote", h, p] => drop(data.insert("remote".into(), format!("{h}:{p}"))),
                    ["ca" | "cert" | "key", p] => drop(data.insert(w[0].into(), p.to_string())),
                    ["tls-auth", p] => drop(data.insert("ta".into(), p.to_string())),
                    ["key-direction", d] => drop(data.insert("ta-dir".into(), d.to_string())),
                    _ => {}
                }
            }
            for (k, v) in [
                ("ns-cert-type", "server"),
                ("challenge-response-flags", "2"),
                ("password-flags", "1"),
                ("connection-type", "password-tls"),
            ] {
                data.insert(k.into(), v.into());
            }
            let mut s = Settings::new();
            nm::set(
                &mut s,
                "connection",
                "id",
                nm::value(file.file_stem().unwrap().to_string_lossy().to_string()),
            );
            nm::set(&mut s, "connection", "type", nm::value("vpn"));
            nm::set(
                &mut s,
                "vpn",
                "service-type",
                nm::value("org.freedesktop.NetworkManager.openvpn"),
            );
            nm::set(&mut s, "vpn", "data", nm::value(data));
            let mut st = self.state.borrow_mut();
            st.next += 1;
            let path = format!("/nm/{}", st.next);
            st.conns.push(FakeConn {
                path,
                settings: s,
                secrets: Settings::new(),
                filename: None,
            });
        }
        let stdout = if program == "/usr/bin/cntlm" {
            "PassNT          AAAA\nPassNTLMv2      BBBB\n".to_string()
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

fn profile() -> Profile {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/esempio/profile.toml");
    let mut p = Profile::from_toml(&fs::read_to_string(p).unwrap()).unwrap();
    p.wifi.as_mut().unwrap().ca_sha1 = pem_sha1(CA.as_bytes());
    p
}

struct World {
    tmp: tempfile::TempDir,
    state: Rc<RefCell<State>>,
}

impl World {
    fn new() -> World {
        World {
            tmp: tempfile::tempdir().unwrap(),
            state: Rc::default(),
        }
    }
    fn root(&self) -> &Path {
        self.tmp.path()
    }
    fn run(&self, action: &Action) -> (Report, Vec<String>) {
        let mut run = FakeRun {
            state: self.state.clone(),
            calls: Vec::new(),
        };
        let mut nm = FakeNm(self.state.clone());
        let r = bnw_helper::run_with(action, Fs::new(self.root(), false), &mut run, &mut nm);
        (r, run.calls)
    }
    fn conn(&self, id: &str) -> (Settings, Settings) {
        let st = self.state.borrow();
        let c = st
            .conns
            .iter()
            .find(|c| nm::get_str(&c.settings, "connection", "id").as_deref() == Some(id))
            .unwrap();
        (clone(&c.settings), clone(&c.secrets))
    }
    fn mode(&self, abs: &str) -> u32 {
        fs::metadata(self.root().join(abs.trim_start_matches('/')))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }
}

fn vpn(ovpn: Option<&str>, reimport: bool, password: Option<&str>) -> Action {
    Action::ApplyVpn {
        profile: profile(),
        ovpn: ovpn.map(|o| Blob(o.as_bytes().to_vec())),
        reimport,
        domain_user: Some("mario.rossi".into()),
        password: password.map(Secret::new),
    }
}

fn wifi(p: Profile, ca: Option<&str>, password: Option<&str>) -> Action {
    Action::ApplyWifi {
        profile: p,
        ca: ca.map(|c| Blob(c.as_bytes().to_vec())),
        domain_user: Some("mario.rossi".into()),
        password: password.map(Secret::new),
    }
}

#[test]
fn vpn_nuova_importata_e_corretta() {
    let w = World::new();
    let (r, calls) = w.run(&vpn(Some(OVPN), false, Some("Pw;1")));
    assert!(!r.failed(), "{r:#?}");
    // i blocchi inline sono file 600 in una cartella 700
    let dir = "/etc/bnw/vpn/esempio";
    assert_eq!(w.mode(dir), 0o700);
    for f in ["ca.pem", "cert.pem", "key.pem", "tls-auth.key", "Esempio.ovpn"] {
        assert_eq!(w.mode(&format!("{dir}/{f}")), 0o600, "{f}");
    }
    assert!(
        calls
            .iter()
            .any(|c| c.contains("connection import type openvpn file")
                && c.ends_with("/etc/bnw/vpn/esempio/Esempio.ovpn"))
    );
    let (s, sec) = w.conn("Esempio");
    let data = nm::get_dict(&s, "vpn", "data");
    assert!(!data.contains_key("ns-cert-type") && !data.contains_key("challenge-response-flags"));
    assert_eq!(data["remote-cert-tls"], "server");
    assert_eq!(data["password-flags"], "0");
    assert_eq!(data["username"], "mario.rossi");
    assert!(data["key"].ends_with("/etc/bnw/vpn/esempio/key.pem"));
    // assente vale «no»: full-tunnel
    assert!(!nm::get_bool(&s, "ipv4", "never-default").unwrap_or(false));
    assert_eq!(nm::get_dict(&sec, "vpn", "secrets")["password"], "Pw;1");
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("Pw;1") && !json.contains("CHIAVE"));
}

#[test]
fn vpn_gia_a_posto_non_si_tocca() {
    let w = World::new();
    w.run(&vpn(Some(OVPN), false, Some("Pw")));
    let before = w.state.borrow().updates;
    let (r, calls) = w.run(&vpn(None, false, None));
    assert!(!r.failed(), "{r:#?}");
    assert_eq!(
        w.state.borrow().updates,
        before,
        "nessun Update se è già tutto giusto"
    );
    assert!(calls.is_empty());
    let step = r.steps.iter().find(|s| s.what == "VPN «Esempio»").unwrap();
    assert_eq!(step.outcome, Outcome::Unchanged);
    // e la password resta
    assert_eq!(
        nm::get_dict(&w.conn("Esempio").1, "vpn", "secrets")["password"],
        "Pw"
    );
}

#[test]
fn vpn_esistente_da_correggere_tiene_la_password() {
    let w = World::new();
    // com'era la macchina di esempio prima di install.sh: import grezzo, password salvata, keyfile su disco
    w.run(&vpn(Some(OVPN), false, None));
    {
        let mut st = w.state.borrow_mut();
        let c = &mut st.conns[0];
        let mut data = nm::get_dict(&c.settings, "vpn", "data");
        data.insert("ns-cert-type".into(), "server".into());
        data.insert("password-flags".into(), "1".into());
        nm::set(&mut c.settings, "vpn", "data", nm::value(data));
        let mut secrets = HashMap::new();
        secrets.insert("password".to_string(), "Vecchia".to_string());
        nm::set(&mut c.secrets, "vpn", "secrets", nm::value(secrets));
        c.filename = Some("/etc/NetworkManager/system-connections/Esempio.nmconnection".into());
    }
    let keyfile = w
        .root()
        .join("etc/NetworkManager/system-connections/Esempio.nmconnection");
    fs::create_dir_all(keyfile.parent().unwrap()).unwrap();
    fs::write(&keyfile, "[connection]\nid=Esempio\n").unwrap();
    fs::set_permissions(&keyfile, fs::Permissions::from_mode(0o600)).unwrap();

    let (r, calls) = w.run(&vpn(None, false, None));
    assert!(!r.failed(), "{r:#?}");
    assert!(calls.is_empty(), "nessun reimport: {calls:?}");
    let step = r.steps.iter().find(|s| s.what == "VPN «Esempio»").unwrap();
    assert_eq!(step.outcome, Outcome::Changed);
    assert!(step.detail.as_deref().unwrap().contains("ns-cert-type"));
    let (s, sec) = w.conn("Esempio");
    assert_eq!(nm::get_dict(&s, "vpn", "data")["password-flags"], "0");
    assert_eq!(nm::get_dict(&sec, "vpn", "secrets")["password"], "Vecchia");
    // backup del keyfile fuori da system-connections
    let baks: Vec<_> = fs::read_dir(w.root().join("etc/bnw/backup/NetworkManager"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(baks.len(), 1);
}

#[test]
fn vpn_reimportata_tiene_la_password() {
    let w = World::new();
    w.run(&vpn(Some(OVPN), false, Some("Tenuta")));
    let nuovo = OVPN.replace("vpn.esempio.it", "vpn2.esempio.it");
    let (r, calls) = w.run(&vpn(Some(&nuovo), true, None));
    assert!(!r.failed(), "{r:#?}");
    assert_eq!(w.state.borrow().conns.len(), 1);
    assert!(calls.iter().any(|c| c.contains("import")));
    let (s, sec) = w.conn("Esempio");
    assert_eq!(nm::get_dict(&s, "vpn", "data")["remote"], "vpn2.esempio.it:443");
    assert_eq!(nm::get_dict(&sec, "vpn", "secrets")["password"], "Tenuta");
}

#[test]
fn vpn_senza_ovpn_e_senza_connessione() {
    let w = World::new();
    let (r, _) = w.run(&vpn(None, false, None));
    assert!(r.failed());
}

#[test]
fn wifi_nuovo() {
    let w = World::new();
    let (r, _) = w.run(&wifi(profile(), Some(CA), Some("Pw")));
    assert!(!r.failed(), "{r:#?}");
    let ca = "/etc/bnw/wifi/esempio-802-1x/ca.pem";
    assert_eq!(w.mode(ca), 0o644);
    let (s, sec) = w.conn("Esempio-802.1X");
    assert_eq!(nm::get_bytes(&s, "802-11-wireless", "ssid").unwrap(), b"Esempio");
    assert_eq!(
        nm::get_str(&s, "802-11-wireless-security", "key-mgmt").as_deref(),
        Some("wpa-eap")
    );
    assert_eq!(nm::get_strs(&s, "802-1x", "eap").unwrap(), ["peap"]);
    assert_eq!(
        nm::get_str(&s, "802-1x", "phase2-auth").as_deref(),
        Some("mschapv2")
    );
    assert_eq!(
        nm::get_str(&s, "802-1x", "identity").as_deref(),
        Some("mario.rossi")
    );
    assert_eq!(
        nm::get_str(&s, "802-1x", "domain-suffix-match").as_deref(),
        Some("dc1.corp.esempio")
    );
    assert!(
        nm::cert_path(&nm::get_bytes(&s, "802-1x", "ca-cert").unwrap())
            .unwrap()
            .ends_with(ca)
    );
    assert_eq!(nm::get_bool(&s, "connection", "autoconnect"), Some(false));
    assert_eq!(nm::get_str(&s, "connection", "uuid").map(|u| u.len()), Some(36));
    assert_eq!(nm::get_str(&sec, "802-1x", "password").as_deref(), Some("Pw"));
}

#[test]
fn wifi_con_la_ca_giusta_altrove_resta_com_e() {
    let w = World::new();
    // come la macchina di esempio: la CA sta nella home, con il fingerprint giusto
    let home_ca = w.root().join("home/utente/Documenti/VPN/esempio-root-ca.pem");
    fs::create_dir_all(home_ca.parent().unwrap()).unwrap();
    fs::write(&home_ca, CA).unwrap();
    w.run(&wifi(profile(), Some(CA), Some("Pw")));
    {
        let mut st = w.state.borrow_mut();
        let c = &mut st.conns[0];
        nm::set(
            &mut c.settings,
            "802-1x",
            "ca-cert",
            nm::cert_path_value("/home/utente/Documenti/VPN/esempio-root-ca.pem"),
        );
    }
    let updates = w.state.borrow().updates;
    let (r, _) = w.run(&wifi(profile(), Some(CA), None));
    assert!(!r.failed(), "{r:#?}");
    assert_eq!(w.state.borrow().updates, updates, "niente da cambiare");
    let (s, sec) = w.conn("Esempio-802.1X");
    assert!(
        nm::cert_path(&nm::get_bytes(&s, "802-1x", "ca-cert").unwrap())
            .unwrap()
            .starts_with("/home/utente/")
    );
    assert_eq!(nm::get_str(&sec, "802-1x", "password").as_deref(), Some("Pw"));
}

#[test]
fn wifi_ca_sbagliata_rifiutata() {
    let w = World::new();
    let (r, _) = w.run(&wifi(profile(), Some(ALTRA_CA), Some("Pw")));
    assert!(r.failed());
    assert!(
        r.steps
            .last()
            .unwrap()
            .detail
            .as_deref()
            .unwrap()
            .contains("fingerprint")
    );
    assert!(w.state.borrow().conns.is_empty());
    assert!(!w.root().join("etc/bnw/wifi").exists());
}

#[test]
fn wifi_autoconnect() {
    let w = World::new();
    w.run(&wifi(profile(), Some(CA), Some("Pw")));
    let mut p = profile();
    p.wifi.as_mut().unwrap().autoconnect = true;
    let (r, _) = w.run(&wifi(p, None, None));
    assert!(!r.failed(), "{r:#?}");
    let (s, sec) = w.conn("Esempio-802.1X");
    assert_eq!(nm::get_bool(&s, "connection", "autoconnect"), Some(true));
    assert_eq!(nm::get_str(&sec, "802-1x", "password").as_deref(), Some("Pw"));
    // e il profilo installato lo ricorda
    let saved = fs::read_to_string(w.root().join("etc/bnw/profile.toml")).unwrap();
    assert!(Profile::from_toml(&saved).unwrap().wifi.unwrap().autoconnect);
}

#[test]
fn con_root_finta_networkmanager_non_si_tocca() {
    let tmp = tempfile::tempdir().unwrap();
    let mut run = FakeRun {
        state: Rc::default(),
        calls: Vec::new(),
    };
    let r = bnw_helper::run_with(
        &vpn(Some(OVPN), false, None),
        Fs::new(tmp.path(), false),
        &mut run,
        &mut NoNm,
    );
    assert!(!r.failed(), "{r:#?}");
    assert!(r.steps.iter().any(|s| s.outcome == Outcome::Skipped));
    assert!(tmp.path().join("etc/bnw/vpn/esempio/key.pem").exists());
    assert!(run.calls.is_empty());
}

/// Il cambio di brand e dominio: il profilo nuovo ha VPN, WiFi, dischi e credenziali
/// diversi. Quello vecchio va tolto, non lasciato accanto.
#[test]
fn cambio_di_profilo_toglie_il_vecchio() {
    let w = World::new();
    let root = w.root().to_path_buf();
    put(&root, "/etc/passwd", "gt:x:1000:1000::/home/utente:/bin/fish\n");
    let apply = |p: Profile| Action::ApplyProfile {
        profile: p,
        ovpn: Some(Blob(OVPN.as_bytes().to_vec())),
        ca: Some(Blob(CA.as_bytes().to_vec())),
        domain_user: Some("mario.rossi".into()),
        owner_uid: Some(1000),
    };
    let (r, _) = w.run(&apply(profile()));
    assert!(!r.failed(), "{r:#?}");
    put(
        &root,
        "/etc/samba/credentials/esempio",
        "username=u\ndomain=ESEMPIO\npassword=p\n",
    );
    assert!(root.join("etc/systemd/system/mnt-esempio.mount").exists());
    assert!(root.join("etc/bnw/vpn/esempio/key.pem").exists());

    let mut nuovo = profile();
    nuovo.company.name = "Nuova Banca".into();
    nuovo.company.domain = "NUOVA".into();
    nuovo.vpn.as_mut().unwrap().name = "NuovaBanca".into();
    nuovo.wifi.as_mut().unwrap().name = "NuovaBanca-802.1X".into();
    nuovo.shares = vec![bnw_core::profile::Share {
        server: "fs.nuovabanca.local".into(),
        name: "DATI".into(),
        mount: "/mnt/dati".into(),
        label: None,
    }];
    nuovo.printers.clear();
    let (r, calls) = w.run(&apply(nuovo));
    assert!(!r.failed(), "{r:#?}");

    // VPN e WiFi vecchi tolti, nuovi creati
    let ids: Vec<String> = w
        .state
        .borrow()
        .conns
        .iter()
        .filter_map(|c| nm::get_str(&c.settings, "connection", "id"))
        .collect();
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert!(
        ids.contains(&"NuovaBanca".into()) && ids.contains(&"NuovaBanca-802.1X".into()),
        "{ids:?}"
    );
    assert!(
        !root.join("etc/bnw/vpn/esempio").exists(),
        "la chiave vecchia non resta"
    );
    assert!(root.join("etc/bnw/vpn/nuovabanca/key.pem").exists());
    // credenziali e dischi vecchi via, con backup
    assert!(!root.join("etc/samba/credentials/esempio").exists());
    assert!(root.join("etc/bnw/backup/samba").read_dir().unwrap().count() == 1);
    assert!(!root.join("etc/systemd/system/mnt-esempio.mount").exists());
    assert!(root.join("etc/systemd/system/mnt-dati.automount").exists());
    assert!(calls.contains(&"/usr/bin/systemctl disable --now mnt-esempio.automount".to_string()));
    // il profilo applicato è il nuovo
    let saved = fs::read_to_string(root.join("etc/bnw/profile.toml")).unwrap();
    assert_eq!(Profile::from_toml(&saved).unwrap().company.domain, "NUOVA");
}

fn put(root: &Path, abs: &str, content: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

/// Una macchina nuova, dall'inizio alla fine: profilo, poi password nei quattro posti.
#[test]
fn macchina_nuova_dall_inizio_alla_fine() {
    let w = World::new();
    let root = w.root().to_path_buf();
    put(&root, "/etc/passwd", "nuovo:x:1000:1000::/home/nuovo:/bin/bash\n");
    let (r, _) = w.run(&Action::ApplyProfile {
        profile: profile(),
        ovpn: Some(Blob(OVPN.as_bytes().to_vec())),
        ca: Some(Blob(CA.as_bytes().to_vec())),
        domain_user: Some("nuovo.utente".into()),
        owner_uid: Some(1000),
    });
    assert!(!r.failed(), "{r:#?}");
    // proxy, VPN, WiFi, dischi pronti; manca la password
    assert!(root.join("etc/tinyproxy/upstream.conf").exists());
    assert!(
        r.steps
            .iter()
            .any(|s| s.what == "/etc/samba/credentials/esempio" && s.outcome == Outcome::Skipped)
    );

    let (r, calls) = w.run(&Action::SetPassword {
        password: Secret::new("Prima;Password"),
        only: vec![],
        domain_user: Some("nuovo.utente".into()),
    });
    assert!(!r.failed(), "{r:#?}");
    assert!(
        calls
            .iter()
            .any(|c| c == "/usr/bin/cntlm -H -c /dev/null -u nuovo.utente -d ESEMPIO")
    );
    let conf = fs::read_to_string(root.join("etc/cntlm.conf")).unwrap();
    assert!(conf.starts_with("Username        nuovo.utente\n"), "{conf}");
    let cred = fs::read_to_string(root.join("etc/samba/credentials/esempio")).unwrap();
    assert_eq!(
        cred,
        "username=nuovo.utente\ndomain=ESEMPIO\npassword=Prima;Password\n"
    );
    // i segreti di VPN e WiFi via D-Bus
    assert_eq!(
        nm::get_dict(&w.conn("Esempio").1, "vpn", "secrets")["password"],
        "Prima;Password"
    );
    assert_eq!(
        nm::get_str(&w.conn("Esempio-802.1X").1, "802-1x", "password").as_deref(),
        Some("Prima;Password")
    );
    assert_eq!(
        nm::get_str(&w.conn("Esempio-802.1X").0, "802-1x", "identity").as_deref(),
        Some("nuovo.utente")
    );
    assert!(!serde_json::to_string(&r).unwrap().contains("Prima;Password"));
}
