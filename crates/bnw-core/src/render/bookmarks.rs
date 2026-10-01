//! Segnalibri GTK (`~/.config/gtk-3.0/bookmarks`) per le share. Il file è dell'utente
//! e contiene anche i suoi segnalibri: si aggiungono e tolgono solo le righe delle
//! share, riconosciute dal loro URI.

use crate::profile::Share;

fn uri(share: &Share) -> String {
    format!("file://{}", share.mount)
}

fn line_uri(line: &str) -> &str {
    line.split_once(' ').map_or(line, |(u, _)| u)
}

/// Aggiunge in fondo le share che mancano. Una share già presente con un'etichetta
/// diversa resta com'è: l'utente può averla rinominata.
pub fn merge(existing: &str, shares: &[Share]) -> String {
    let mut out: String = existing.lines().map(|l| format!("{l}\n")).collect();
    for share in shares {
        let u = uri(share);
        if !out.lines().any(|l| line_uri(l) == u) {
            out += &format!("{u} {}\n", share.label());
        }
    }
    out
}

/// Toglie i segnalibri di queste share.
pub fn remove(existing: &str, shares: &[Share]) -> String {
    let uris: Vec<String> = shares.iter().map(uri).collect();
    existing
        .lines()
        .filter(|l| !uris.iter().any(|u| u == line_uri(l)))
        .map(|l| format!("{l}\n"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(mount: &str) -> Share {
        Share {
            server: "fs1.x.local".into(),
            name: "S".into(),
            mount: mount.into(),
            label: None,
        }
    }

    #[test]
    fn non_duplica_e_toglie_solo_le_sue() {
        let old = "file:///home/u/Doc Doc\nfile:///mnt/a Rinominata\n";
        let new = merge(old, &[share("/mnt/a"), share("/mnt/b")]);
        assert_eq!(
            new,
            "file:///home/u/Doc Doc\nfile:///mnt/a Rinominata\nfile:///mnt/b S (fs1)\n"
        );
        assert_eq!(
            remove(&new, &[share("/mnt/a"), share("/mnt/b")]),
            "file:///home/u/Doc Doc\n"
        );
    }
}
