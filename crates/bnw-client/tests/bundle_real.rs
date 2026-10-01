//! Prova manuale sulla macchina vera (`cargo test -p bnw-client -- --ignored`): trova
//! `.ovpn` e CA come fa l'esportazione, costruisce il profilo, lo cifra e lo riapre in
//! memoria. Non scrive niente su disco e non stampa segreti.

use bnw_client::{Env, bundle, status};
use bnw_core::bundle::Bundle;

#[test]
#[ignore = "usa i file veri di questa macchina"]
fn esportazione_vera_in_memoria() {
    let env = Env::from_env();
    let profile = status::installed_profile(&env).expect("nessun profilo in /etc/bnw");
    let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
    let ovpn = bundle::detect_ovpn(&profile, &home);
    let ca = bundle::detect_ca(&profile);
    println!("ovpn trovato: {ovpn:?}\nCA trovata:   {ca:?}");
    let (b, warnings) = bundle::build(&profile, ovpn.as_deref(), ca.as_deref()).unwrap();
    println!("avvisi: {warnings:?}");
    let enc = b.encrypt("una passphrase di prova").unwrap();
    println!("dimensione cifrata: {} byte", enc.len());
    let back = Bundle::decrypt(&enc, "una passphrase di prova").unwrap();
    assert_eq!(back, b);
    print!("{}", bundle::summary(&back));
}

/// Solo nomi: le direttive dell'`.ovpn` vero e i file che l'import estrarrebbe. Nessun
/// contenuto viene stampato (vedi `bnw_core::ovpn::directives`).
#[test]
#[ignore = "usa i file veri di questa macchina"]
fn struttura_ovpn_vero() {
    let env = Env::from_env();
    let profile = status::installed_profile(&env).unwrap();
    let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
    let path = bundle::detect_ovpn(&profile, &home).unwrap();
    let data = std::fs::read(&path).unwrap();
    let (text, files) = bnw_core::ovpn::externalize(&data, "/etc/bnw/vpn/x").unwrap();
    println!("direttive: {:?}", bnw_core::ovpn::directives(&text));
    println!(
        "file estratti: {:?}",
        files
            .iter()
            .map(|f| (&f.name, f.content.len()))
            .collect::<Vec<_>>()
    );
}
