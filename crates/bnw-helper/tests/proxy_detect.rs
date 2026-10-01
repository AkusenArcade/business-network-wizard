//! `data/proxy-detect --dry-run` eseguito davvero, con una radice finta
//! (`BNW_TEST_ROOT`), un `nmcli` finto e un finto proxy aziendale in ascolto.

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    /// `active_vpns`: le connessioni che `nmcli` dirà attive.
    fn new(conf: &str, active: &[&str]) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("etc/bnw")).unwrap();
        fs::create_dir_all(root.join("etc/tinyproxy")).unwrap();
        fs::create_dir_all(root.join("run")).unwrap();
        fs::write(root.join("etc/bnw/proxy-detect.conf"), conf).unwrap();
        fs::write(root.join("etc/tinyproxy/direct.conf"), "").unwrap();
        std::os::unix::fs::symlink(
            root.join("etc/tinyproxy/direct.conf"),
            root.join("etc/tinyproxy/active.conf"),
        )
        .unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let nmcli = bin.join("nmcli");
        let lines: String = active.iter().map(|a| format!("{a}\n")).collect();
        fs::write(&nmcli, format!("#!/bin/sh\nprintf '%s' '{lines}'\n")).unwrap();
        fs::set_permissions(&nmcli, fs::Permissions::from_mode(0o755)).unwrap();
        Env { dir }
    }

    fn root(&self) -> PathBuf {
        self.dir.path().join("root")
    }

    fn run(&self) -> String {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/proxy-detect");
        let out = Command::new("bash")
            .arg(script)
            .arg("--dry-run")
            .env("BNW_TEST_ROOT", self.root())
            .env(
                "PATH",
                format!("{}:/usr/bin", self.dir.path().join("bin").display()),
            )
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    }
}

/// Una porta su cui non ascolta nessuno.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn vpn_attiva() {
    let e = Env::new(
        "VPN_NAME=Esempio\nPROXY=127.0.0.1:1\n",
        &["Esempio-802.1X", "Esempio", "lo"],
    );
    let out = e.run();
    assert!(
        out.starts_with("rilevato:  upstream  (VPN Esempio attiva)\n"),
        "{out}"
    );
    assert!(out.contains("attuale:   direct\n"), "{out}");
}

#[test]
fn il_nome_della_vpn_deve_coincidere_per_intero() {
    let p = closed_port();
    let e = Env::new(
        &format!("VPN_NAME=Esempio\nPROXY=127.0.0.1:{p}\n"),
        &["Esempio-802.1X"],
    );
    assert!(e.run().starts_with("rilevato:  direct"));
}

#[test]
fn proxy_raggiungibile_senza_vpn() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    let e = Env::new(&format!("VPN_NAME=Esempio\nPROXY=127.0.0.1:{p}\n"), &[]);
    let out = e.run();
    assert!(
        out.starts_with(&format!(
            "rilevato:  upstream  (proxy aziendale 127.0.0.1:{p} raggiungibile"
        )),
        "{out}"
    );
}

#[test]
fn le_righe_proxy_di_cntlm_vincono_sulla_riserva() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    let e = Env::new(&format!("PROXY=127.0.0.1:{}\n", closed_port()), &[]);
    fs::write(
        e.root().join("etc/cntlm.conf"),
        format!("Username u\nProxy           127.0.0.1:{p}\n"),
    )
    .unwrap();
    assert!(e.run().contains(&format!("127.0.0.1:{p} raggiungibile")));
}

#[test]
fn niente_rete_aziendale_e_override_manuale() {
    let e = Env::new(
        &format!("VPN_NAME=Esempio\nPROXY=127.0.0.1:{}\n", closed_port()),
        &[],
    );
    fs::write(e.root().join("run/proxy-mode.manual"), "on\n").unwrap();
    let out = e.run();
    assert!(
        out.starts_with("rilevato:  direct  (ne' VPN ne' proxy aziendale raggiungibili)\n"),
        "{out}"
    );
    assert!(out.contains("override manuale attivo (on)"), "{out}");
}

#[test]
fn i_valori_non_passano_da_una_shell() {
    let e = Env::new("", &[]);
    let marker = e.dir.path().join("eseguito");
    let m = marker.display();
    fs::write(
        e.root().join("etc/bnw/proxy-detect.conf"),
        format!("VPN_NAME=$(touch {m})\nPROXY=127.0.0.1;touch {m}:1\nPROXY=`touch {m}`:2\n"),
    )
    .unwrap();
    let out = e.run();
    assert!(out.starts_with("rilevato:  direct"), "{out}");
    assert!(
        !marker.exists(),
        "un valore della configurazione è stato eseguito"
    );
}
