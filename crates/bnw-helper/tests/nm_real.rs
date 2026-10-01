//! Prova con la NetworkManager vera, da lanciare come root e a mano:
//! `pkexec target/debug/deps/nm_real-… --ignored --nocapture`.
//! Crea un WiFi di prova «bnw-prova» (SSID inesistente, CA generata al volo), lo
//! rilegge, lo aggiorna, controlla i segreti e lo cancella. Non tocca altre connessioni.

use std::process::Command;

use bnw_core::Profile;
use bnw_helper::nm::{self, Nm, RealNm};
use bnw_helper::wifi;

const NAME: &str = "bnw-prova";

fn profile() -> Profile {
    let mut p = Profile::from_toml(include_str!("../../../tests/fixtures/esempio/profile.toml")).unwrap();
    let w = p.wifi.as_mut().unwrap();
    w.name = NAME.into();
    w.ssid = "bnw-prova-inesistente".into();
    w.ca_sha1 = None;
    p
}

#[test]
#[ignore = "usa la NetworkManager vera e serve root"]
fn andata_e_ritorno_con_networkmanager() {
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    let ok = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
        ])
        .arg("-keyout")
        .arg(dir.path().join("k.pem"))
        .arg("-out")
        .arg(&ca)
        .args(["-subj", "/CN=bnw-prova", "-days", "1"])
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "openssl non ha generato la CA");
    let ca = ca.to_string_lossy().into_owned();

    let mut nm = RealNm::connect().unwrap();
    if let Some(old) = nm.find(NAME).unwrap() {
        nm.delete(&old.path).unwrap();
    }

    // creazione
    let p = profile();
    let mut s = nm::Settings::new();
    wifi::desired(&mut s, &p, &ca, "utente.prova");
    nm::set(
        &mut s,
        "connection",
        "uuid",
        nm::value(
            std::fs::read_to_string("/proc/sys/kernel/random/uuid")
                .unwrap()
                .trim()
                .to_string(),
        ),
    );
    nm::set(&mut s, "802-11-wireless", "mode", nm::value("infrastructure"));
    nm::set(&mut s, "ipv4", "method", nm::value("auto"));
    nm::set(&mut s, "ipv6", "method", nm::value("auto"));
    nm::set(&mut s, "802-1x", "password", nm::value("prova-1"));
    let path = nm.add(&s).unwrap();
    println!("creata: {path}");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let c = nm.find(NAME).unwrap().expect("la connessione appena creata");
        println!("file: {:?}", c.filename);
        // rileggendo, le impostazioni sono già quelle volute: nessun cambiamento
        let mut again = c.settings;
        let changes = wifi::desired(&mut again, &p, &ca, "utente.prova");
        assert!(
            changes.is_empty(),
            "dopo la creazione restano differenze: {changes:?}"
        );
        let sec = nm.secrets(&c.path, "802-1x").unwrap();
        assert_eq!(
            nm::get_str(&sec, "802-1x", "password").as_deref(),
            Some("prova-1")
        );

        // aggiornamento: autoconnect e password, il resto deve restare
        let mut p2 = p.clone();
        p2.wifi.as_mut().unwrap().autoconnect = true;
        let changes = wifi::desired(&mut again, &p2, &ca, "utente.prova");
        assert_eq!(changes, ["connessione automatica"]);
        nm::set(&mut again, "802-1x", "password", nm::value("prova-2"));
        nm.update(&c.path, &again).unwrap();

        let c = nm.find(NAME).unwrap().unwrap();
        // NetworkManager non restituisce le proprietà al valore di default (autoconnect: sì)
        assert!(nm::get_bool(&c.settings, "connection", "autoconnect").unwrap_or(true));
        assert_eq!(
            nm::get_bytes(&c.settings, "802-11-wireless", "ssid").unwrap(),
            b"bnw-prova-inesistente"
        );
        assert_eq!(
            nm::get_str(&c.settings, "802-1x", "domain-suffix-match").as_deref(),
            Some("dc1.corp.esempio")
        );
        let sec = nm.secrets(&c.path, "802-1x").unwrap();
        assert_eq!(
            nm::get_str(&sec, "802-1x", "password").as_deref(),
            Some("prova-2")
        );
        println!("andata e ritorno: ok");
    }));
    nm.delete(&path).unwrap();
    assert!(nm.find(NAME).unwrap().is_none());
    println!("cancellata");
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
