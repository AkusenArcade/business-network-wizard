//! La parte senza privilegi, condivisa da `bnw-gui` e `bnw`: legge lo stato della
//! macchina, lancia l'helper con pkexec, fa le prove di rete.
//!
//! Le funzioni sono bloccanti: la GUI le chiama con `gio::spawn_blocking`.
//!
//! Variabili per lo sviluppo (non servono in produzione):
//! - `BNW_ROOT=DIR`: legge i file di sistema sotto `DIR` e lancia l'helper con
//!   `--root DIR` senza pkexec, così niente tocca il sistema vero;
//! - `BNW_HELPER=PATH`: l'helper da usare al posto di `/usr/lib/bnw/bnw-helper`.

pub mod bundle;
pub mod checks;
pub mod helper;
pub mod nettest;
pub mod offline;
pub mod status;
pub mod user;

use std::path::PathBuf;

/// Da dove leggere i file di sistema e come lanciare l'helper.
#[derive(Debug, Clone)]
pub struct Env {
    /// `/` in produzione.
    pub root: PathBuf,
    /// `true` con `BNW_ROOT`: helper con `--root`, senza pkexec.
    pub dev_root: bool,
    pub helper: PathBuf,
}

impl Env {
    pub fn from_env() -> Env {
        let root = std::env::var_os("BNW_ROOT").map(PathBuf::from);
        Env {
            dev_root: root.is_some(),
            root: root.unwrap_or_else(|| PathBuf::from("/")),
            helper: std::env::var_os("BNW_HELPER")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(bnw_core::paths::HELPER)),
        }
    }

    /// Percorso reale di un percorso assoluto di sistema.
    pub fn path(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }
}
