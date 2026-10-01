//! Il binario `bnw-helper` come lo userà la GUI: azione JSON su stdin, rapporto JSON
//! su stdout.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use bnw_core::action::{Action, Outcome, Report};
use bnw_core::{Profile, Secret};

fn helper(args: &[&str], stdin: &str) -> (i32, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bnw-helper"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap(), String::from_utf8(out.stdout).unwrap())
}

fn profile() -> Profile {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/esempio/profile.toml");
    Profile::from_toml(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn senza_root_ne_radice_rifiuta() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let (code, out) = helper(&[], r#"{"action":"set-mode","mode":"auto"}"#);
    assert_eq!(code, 2);
    assert!(out.contains("serve root"), "{out}");
}

#[test]
fn json_sbagliato_non_ripete_la_password() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_str().unwrap();
    // password di tipo sbagliato: serde direbbe "invalid type: ... SEGRETISSIMA"
    let (code, out) = helper(
        &["--root", root],
        r#"{"action":"write-cntlm","domain_user":"u","password":["SEGRETISSIMA"]}"#,
    );
    assert_eq!(code, 2);
    assert!(!out.contains("SEGRETISSIMA"), "{out}");
    let (code, _) = helper(&["--root", root], r#"{"action":"format-disk"}"#);
    assert_eq!(code, 2);
}

#[test]
fn applica_il_proxy_e_scrive_cntlm_su_radice_finta() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_str().unwrap();

    let apply = serde_json::to_string(&Action::ApplyProxy { profile: profile() }).unwrap();
    let (code, out) = helper(&["--root", root], &apply);
    assert_eq!(code, 0, "{out}");
    let r: Report = serde_json::from_str(&out).unwrap();
    let cmd = r.steps.iter().find(|s| s.what == "tinyproxy abilitato").unwrap();
    assert_eq!(cmd.detail.as_deref(), Some("non eseguito (--root)"));

    // cntlm -H gira davvero (è locale), il resto no
    let write = serde_json::to_string(&Action::WriteCntlm {
        domain_user: "prova.test".into(),
        password: Secret::new("password-finta"),
    })
    .unwrap();
    let (code, out) = helper(&["--root", root], &write);
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("password-finta"));
    let r: Report = serde_json::from_str(&out).unwrap();
    assert!(
        r.steps
            .iter()
            .any(|s| s.what == "/etc/cntlm.conf" && s.outcome == Outcome::Changed)
    );
    let conf = std::fs::read_to_string(tmp.path().join("etc/cntlm.conf")).unwrap();
    let v2 = conf.lines().find(|l| l.starts_with("PassNTLMv2")).unwrap();
    assert_eq!(v2.split_whitespace().nth(1).unwrap().len(), 32, "{v2}");
    assert!(conf.contains("Username        prova.test\nDomain          ESEMPIO\n"));
}
