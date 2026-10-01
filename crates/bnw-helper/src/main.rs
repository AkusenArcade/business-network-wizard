//! `bnw-helper [--root DIR]`: legge un'azione JSON da stdin, stampa il rapporto JSON.
//!
//! In produzione lo lancia `pkexec /usr/lib/bnw/bnw-helper`. Con `--root` lavora in
//! una cartella qualsiasi e i comandi di sistema vengono solo annotati: serve ai test
//! e non richiede root.

use std::io::{Read, Write};
use std::process::ExitCode;

use bnw_core::action::{Action, Outcome, Report};
use bnw_helper::nm::{Nm, NoNm, RealNm};
use bnw_helper::sys::{DryRunner, Fs, RealRunner, Runner};

const MAX_INPUT: u64 = 1 << 20;

fn fail(msg: &str) -> ExitCode {
    let mut r = Report::default();
    r.push("bnw-helper", Outcome::Failed, Some(msg.to_string()));
    print(&r);
    ExitCode::from(2)
}

fn print(r: &Report) {
    let mut out = std::io::stdout().lock();
    let _ = serde_json::to_writer_pretty(&mut out, r);
    let _ = writeln!(out);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = match args.as_slice() {
        [] => None,
        [flag, dir] if flag == "--root" => Some(dir.clone()),
        _ => return fail("uso: bnw-helper [--root DIR] < azione.json"),
    };
    // SAFETY: geteuid non ha precondizioni.
    let is_root = unsafe { libc::geteuid() } == 0;
    if root.is_none() && !is_root {
        return fail("serve root (pkexec), oppure --root DIR per le prove");
    }

    let mut input = String::new();
    if let Err(e) = std::io::stdin().take(MAX_INPUT).read_to_string(&mut input) {
        return fail(&format!("stdin illeggibile: {e}"));
    }
    // Il messaggio d'errore di serde può citare un valore, e il valore può essere la
    // password: si riporta solo dove.
    let action: Action = match serde_json::from_str(&input) {
        Ok(a) => a,
        Err(e) => {
            return fail(&format!(
                "azione non valida (riga {}, colonna {}, {:?})",
                e.line(),
                e.column(),
                e.classify()
            ));
        }
    };
    drop(input);

    let (fs, mut runner): (Fs, Box<dyn Runner>) = match &root {
        Some(dir) => (Fs::new(dir, false), Box::new(DryRunner::default())),
        None => (Fs::new("/", true), Box::new(RealRunner)),
    };
    // NetworkManager solo sul sistema vero: con --root le azioni che lo usano lo dicono
    let mut nm: Box<dyn Nm> = match &root {
        Some(_) => Box::new(NoNm),
        None => match RealNm::connect() {
            Ok(n) => Box::new(n),
            Err(_) => Box::new(NoNm),
        },
    };
    let report = bnw_helper::run_with(&action, fs, runner.as_mut(), nm.as_mut());
    print(&report);
    if report.failed() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
