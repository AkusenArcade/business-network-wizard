//! Generatori puri: dal profilo al testo dei file di sistema. Non leggono né scrivono
//! file; quelli che aggiornano un file esistente ricevono il contenuto attuale e
//! restituiscono quello nuovo.

pub mod bookmarks;
pub mod browser;
pub mod cifs;
pub mod cntlm;
pub mod detect;
pub mod environment;
pub mod printer;
pub mod tinyproxy;

/// L'indirizzo locale su cui ascolta tinyproxy, come lo vedono le applicazioni.
pub fn local_proxy_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}
