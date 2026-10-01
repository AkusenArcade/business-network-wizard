//! La prova della password con il cntlm vero (`/usr/bin/cntlm`), ma verso un finto
//! proxy aziendale locale: verifica avvio, attesa della porta, richiesta e chiusura,
//! senza mai contattare il dominio.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread;

use bnw_helper::sys::{RealRunner, Runner};

/// Un finto proxy che a ogni connessione risponde `status` e chiude.
fn fake_upstream(status: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for conn in l.incoming().flatten() {
            let mut conn = conn;
            let mut buf = [0u8; 4096];
            let _ = conn.read(&mut buf);
            let body = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = conn.write_all(body.as_bytes());
        }
    });
    port
}

fn conf(dir: &Path, upstream: u16) -> std::path::PathBuf {
    let p = dir.join("prova.conf");
    std::fs::write(
        &p,
        format!(
            "Username        prova\nDomain          DOM\nPassNTLMv2      0123456789ABCDEF0123456789ABCDEF\n\
             Proxy           127.0.0.1:{upstream}\nAuth            NTLMv2\nGateway         no\n"
        ),
    )
    .unwrap();
    p
}

fn cntlm_running(conf: &Path) -> bool {
    std::process::Command::new("pgrep")
        .args(["-f", &conf.to_string_lossy()])
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn prova_vera_con_finto_proxy() {
    if !Path::new("/usr/bin/cntlm").exists() {
        eprintln!("cntlm non installato: prova saltata");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    for (status, expected) in [("200 OK", 200), ("407 Proxy Authentication Required", 407)] {
        let c = conf(tmp.path(), fake_upstream(status));
        let code = RealRunner.ntlm_trial(&c, "http://esempio.invalid/").unwrap();
        assert_eq!(code, expected, "{status}");
        // il cntlm temporaneo non resta acceso
        assert!(!cntlm_running(&c), "cntlm ancora in esecuzione dopo la prova");
    }
}

#[test]
fn proxy_irraggiungibile() {
    // una porta chiusa: nessuna risposta
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert!(!RealRunner.reachable(&format!("127.0.0.1:{port}")));
    let open = TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(RealRunner.reachable(&open.local_addr().unwrap().to_string()));
}
