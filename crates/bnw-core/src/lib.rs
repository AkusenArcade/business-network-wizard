//! Nucleo di Business Network Wizard: il profilo aziendale, la sua validazione e i
//! generatori puri (profilo → testo dei file di sistema). Niente GTK, niente I/O.

pub mod action;
pub mod bundle;
pub mod keyfile;
pub mod ovpn;
pub mod paths;
pub mod profile;
pub mod render;
pub mod status;
pub mod systemd;
pub mod target;
pub mod validate;

pub use profile::Profile;
pub use target::{Blob, Secret, Target};
