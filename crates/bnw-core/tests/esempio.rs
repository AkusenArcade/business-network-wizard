//! Il profilo di la macchina di esempio deve rigenerare i file che oggi sono in uso su la macchina di esempio.
//! I fixture sono copie dei file reali (senza segreti): vedi
//! `tests/fixtures/esempio/README.md`.

use std::fs;
use std::path::PathBuf;

use bnw_core::profile::Browser;
use bnw_core::render::{bookmarks, browser, cifs, cntlm, environment, printer, tinyproxy};
use bnw_core::{Profile, Secret, Target, validate};

fn fixture(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/esempio")
        .join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn profile() -> Profile {
    Profile::from_toml(&fixture("profile.toml")).unwrap()
}

fn target() -> Target {
    Target {
        domain_user: "mario.rossi".into(),
        uid: 1000,
        gid: 1000,
    }
}

/// Confronto riga per riga, con un messaggio che dice dove.
fn same(generated: &str, real: &str, what: &str) {
    if generated == real {
        return;
    }
    for (i, (g, r)) in generated.lines().zip(real.lines()).enumerate() {
        assert_eq!(g, r, "{what}: prima differenza alla riga {}", i + 1);
    }
    assert_eq!(generated, real, "{what}: differisce in lunghezza o a capo finale");
}

#[test]
fn profilo_valido_e_rileggibile() {
    let p = profile();
    validate::profile(&p).unwrap();
    validate::target(&target()).unwrap();
    assert_eq!(Profile::from_toml(&p.to_toml().unwrap()).unwrap(), p);
    assert_eq!(p.company.slug(), "esempio");
}

#[test]
fn tinyproxy() {
    let p = profile();
    same(
        &tinyproxy::direct_conf(&p.proxy),
        &fixture("etc/tinyproxy/direct.conf"),
        "direct.conf",
    );
    same(
        &tinyproxy::upstream_conf(&p.proxy),
        &fixture("etc/tinyproxy/upstream.conf"),
        "upstream.conf",
    );
}

#[test]
fn unit_cifs() {
    let p = profile();
    let units = cifs::units(&p, &target());
    assert_eq!(units.len(), 8);
    for u in &units {
        same(
            &u.content,
            &fixture(&format!("etc/systemd/system/{}", u.name)),
            &u.name,
        );
    }
    assert_eq!(cifs::credentials_path(&p), "/etc/samba/credentials/esempio");
}

#[test]
fn credenziali_cifs() {
    let c = cifs::credentials(&profile(), &target(), &Secret::new("SEGNAPOSTO"));
    assert_eq!(c, "username=mario.rossi\ndomain=ESEMPIO\npassword=SEGNAPOSTO\n");
}

#[test]
fn environment() {
    // /etc/environment com'è appena installato Arch (pacchetto filesystem)
    let arch = "#\n# This file is parsed by pam_env module\n#\n# Syntax: simple \"KEY=VAL\" pairs on separate lines\n#\n";
    let real = fixture("etc/environment");
    same(&environment::merge(arch, 8118), &real, "environment da zero");
    same(&environment::merge(&real, 8118), &real, "environment rilanciato");
}

#[test]
fn policy_browser() {
    let p = profile();
    for b in &p.proxy.browsers {
        let rel = b.policy_path().trim_start_matches('/');
        let real = fixture(rel);
        let fresh = browser::merge(None, p.proxy.local_port);
        assert!(fresh.warning.is_none());
        same(&fresh.content, &real, rel);
        same(
            &browser::merge(Some(&real), p.proxy.local_port).content,
            &real,
            rel,
        );
    }
    assert_eq!(p.proxy.browsers, [Browser::Firefox, Browser::Zen]);
}

#[test]
fn segnalibri() {
    let real = fixture("home/.config/gtk-3.0/bookmarks");
    let p = profile();
    // rilanciare non cambia niente
    same(&bookmarks::merge(&real, &p.shares), &real, "bookmarks");
    // partendo dai soli segnalibri personali si ottiene il file di oggi
    let personal = bookmarks::remove(&real, &p.shares);
    assert_eq!(personal.lines().count(), 3);
    same(
        &bookmarks::merge(&personal, &p.shares),
        &real,
        "bookmarks da zero",
    );
}

#[test]
fn cntlm_conf() {
    // Del cntlm.conf reale c'è solo la versione senza righe Pass* (gli hash non si
    // copiano). Unica differenza motivata: NoProxy, derivato dalle eccezioni (README).
    let h = cntlm::NtlmHashes {
        lm: None,
        nt: Some(Secret::new("AA00")),
        ntlmv2: Secret::new("BB00"),
    };
    let got = cntlm::cntlm_conf(&profile(), "mario.rossi", &h);
    let no_hash: String = got
        .lines()
        .filter(|l| !l.starts_with("Pass"))
        .map(|l| {
            if l.starts_with("NoProxy") {
                "NoProxy         localhost, 127.0.0.*, 10.*, 172.16.*, 192.168.*, *.corp.esempio\n"
                    .to_string()
            } else {
                format!("{l}\n")
            }
        })
        .collect();
    same(&no_hash, &fixture("etc/cntlm.conf.senza-hash"), "cntlm.conf");
    assert!(got.contains(
        "\nNoProxy         localhost, 127.*, 10.*, 172.16.*, 192.168.*, *.corp.esempio, *.esempioprod, esempio.it, *.esempio.it\n"
    ));
    assert!(got.contains("Domain          ESEMPIO\nPassNT          AA00\nPassNTLMv2      BB00\nProxy"));
    // Rilanciare le impostazioni tiene utenza e hash.
    assert_eq!(
        cntlm::update_settings(&got, &profile()).as_deref(),
        Some(got.as_str())
    );
    assert_eq!(cntlm::update_settings("Username u\n", &profile()), None);
    // Al cambio password, sul file reale si toccano solo le righe Pass*.
    let replaced = cntlm::replace_hashes(&fixture("etc/cntlm.conf.senza-hash"), &h);
    assert_eq!(
        replaced
            .lines()
            .filter(|l| !l.starts_with("Pass"))
            .collect::<Vec<_>>(),
        fixture("etc/cntlm.conf.senza-hash").lines().collect::<Vec<_>>()
    );
}

#[test]
fn stampante_solo_fronte() {
    let p = profile();
    let prt = &p.printers[0];
    assert_eq!(
        printer::lpadmin_create(prt),
        [
            "-p",
            "STAMPA_P1",
            "-E",
            "-v",
            "ipp://stampante-p1.corp.esempio/ipp",
            "-m",
            "everywhere",
            "-D",
            "Multifunzione - Piano 1",
            "-L",
            "Esempio Piano 1",
            "-o",
            "printer-error-policy=abort-job",
        ]
    );
    assert_eq!(
        printer::lpadmin_sides(prt),
        [
            "-p",
            "STAMPA_P1",
            "-o",
            "Duplex-default=None",
            "-o",
            "sides-default=one-sided"
        ]
    );
}
