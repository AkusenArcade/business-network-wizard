//! La parte utente dell'adozione: le funzioni fish del kit (`vpn-up`, `vpn-down`,
//! `vpn-pass`, `pass-dominio`) sono sostituite da `bnw` e vanno messe da parte.
//! Stanno nella home, quindi non servono privilegi.

use std::fs;
use std::path::{Path, PathBuf};

pub const FISH_FILES: [&str; 5] = [
    ".config/fish/functions/vpn-up.fish",
    ".config/fish/functions/vpn-down.fish",
    ".config/fish/functions/vpn-pass.fish",
    ".config/fish/functions/pass-dominio.fish",
    ".config/fish/completions/pass-dominio.fish",
];

/// Quelle ancora presenti.
pub fn legacy_fish(home: &Path) -> Vec<PathBuf> {
    FISH_FILES
        .iter()
        .map(|f| home.join(f))
        .filter(|p| p.exists())
        .collect()
}

/// Le rinomina in `.bak-<data>`: fish carica solo i `.fish`, quindi spariscono dalla
/// shell ma restano recuperabili. Restituisce i nuovi nomi.
pub fn retire_fish(home: &Path) -> std::io::Result<Vec<PathBuf>> {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let mut done = Vec::new();
    for p in legacy_fish(home) {
        let mut bak = p.clone().into_os_string();
        bak.push(format!(".bak-{stamp}"));
        fs::rename(&p, &bak)?;
        done.push(PathBuf::from(bak));
    }
    Ok(done)
}

/// L'utente che esegue l'app (il proprietario di `/proc/self`).
pub fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// Allinea i segnalibri GTK alle share: toglie quelle che non ci sono più, aggiunge le
/// nuove, lascia stare tutto il resto (segnalibri personali compresi).
pub fn sync_bookmarks(
    home: &Path,
    before: &[bnw_core::profile::Share],
    after: &[bnw_core::profile::Share],
) -> std::io::Result<bool> {
    use bnw_core::render::bookmarks;
    let path = home.join(".config/gtk-3.0/bookmarks");
    let old = fs::read_to_string(&path).unwrap_or_default();
    let gone: Vec<_> = before
        .iter()
        .filter(|b| !after.iter().any(|a| a.mount == b.mount))
        .cloned()
        .collect();
    let new = bookmarks::merge(&bookmarks::remove(&old, &gone), after);
    if new == old {
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(&path, new)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segnalibri_seguono_le_share() {
        use bnw_core::profile::Share;
        let tmp = tempfile::tempdir().unwrap();
        let s = |m: &str| Share {
            server: "fs.x".into(),
            name: "N".into(),
            mount: m.into(),
            label: None,
        };
        let bm = tmp.path().join(".config/gtk-3.0/bookmarks");
        fs::create_dir_all(bm.parent().unwrap()).unwrap();
        fs::write(&bm, "file:///home/u/Doc Doc\nfile:///mnt/a N (fs)\n").unwrap();
        assert!(sync_bookmarks(tmp.path(), &[s("/mnt/a")], &[s("/mnt/b")]).unwrap());
        assert_eq!(
            fs::read_to_string(&bm).unwrap(),
            "file:///home/u/Doc Doc\nfile:///mnt/b N (fs)\n"
        );
        assert!(!sync_bookmarks(tmp.path(), &[s("/mnt/b")], &[s("/mnt/b")]).unwrap());
        assert!(current_uid().is_some());
    }

    #[test]
    fn mette_da_parte_solo_le_funzioni_del_kit() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join(".config/fish/functions");
        fs::create_dir_all(&f).unwrap();
        fs::write(f.join("vpn-up.fish"), "").unwrap();
        fs::write(f.join("mia.fish"), "").unwrap();
        assert_eq!(legacy_fish(tmp.path()).len(), 1);
        let done = retire_fish(tmp.path()).unwrap();
        assert_eq!(done.len(), 1);
        assert!(done[0].to_string_lossy().contains("vpn-up.fish.bak-"));
        assert!(f.join("mia.fish").exists());
        assert!(legacy_fish(tmp.path()).is_empty());
    }
}
