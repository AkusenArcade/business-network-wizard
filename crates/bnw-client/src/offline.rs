//! Il bundle per l'installazione offline: i pacchetti dell'app e delle dipendenze che
//! di solito mancano, presi dalla cache di pacman di questa macchina, più uno script che
//! li installa. Serve dove l'unica rete è quella aziendale: lì pacman vorrebbe il proxy,
//! che ancora non c'è.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// I pacchetti per cui si fa il bundle (con le loro dipendenze).
pub const WANTED: [&str; 7] = [
    "business-network-wizard",
    "tinyproxy",
    "cntlm",
    "cifs-utils",
    "openvpn",
    "networkmanager-openvpn",
    "cups",
];

/// Quello che un desktop Arch/CachyOS ha già: le loro dipendenze non vanno nel bundle.
pub const BASE: [&str; 6] = [
    "base",
    "systemd",
    "networkmanager",
    "gtk4",
    "libadwaita",
    "polkit",
];

/// Un pacchetto installato: nome, versione (con l'epoch), architettura.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    pub arch: String,
}

impl Pkg {
    pub fn file_name(&self) -> String {
        format!("{}-{}-{}.pkg.tar.zst", self.name, self.version, self.arch)
    }

    /// I pacchetti CachyOS ottimizzati non si installano su CPU più vecchie.
    pub fn needs_v3(&self) -> bool {
        self.arch.starts_with("x86_64_v")
    }
}

/// Il nome da una dipendenza come la scrive `pactree` (`glibc>=2.27` → `glibc`).
pub fn dep_name(dep: &str) -> &str {
    dep.split(['<', '>', '=', ':']).next().unwrap_or(dep).trim()
}

/// Le righe di `expac -Q '%n %v %a'`.
pub fn parse_expac(out: &str) -> Vec<Pkg> {
    out.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            Some(Pkg {
                name: w.next()?.into(),
                version: w.next()?.into(),
                arch: w.next()?.into(),
            })
        })
        .collect()
}

fn closure(roots: &[&str]) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    for root in roots {
        if let Ok(out) = Command::new("pactree").args(["-lu", root]).output() {
            for l in String::from_utf8_lossy(&out.stdout).lines() {
                deps.insert(dep_name(l).to_string());
            }
        }
    }
    deps
}

/// Risolve nomi (anche virtuali, come `sh`) nei pacchetti installati.
fn resolve(names: &BTreeSet<String>) -> Vec<Pkg> {
    if names.is_empty() {
        return Vec::new();
    }
    let out = Command::new("expac")
        .arg("-Q")
        .arg("%n %v %a")
        .args(names)
        .output();
    let mut pkgs = out
        .map(|o| parse_expac(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default();
    pkgs.sort();
    pkgs.dedup();
    pkgs
}

/// I pacchetti da mettere nel bundle: le dipendenze di [`WANTED`] meno quelle di [`BASE`].
pub fn packages() -> Vec<Pkg> {
    let base: BTreeSet<String> = resolve(&closure(&BASE)).into_iter().map(|p| p.name).collect();
    resolve(&closure(&WANTED))
        .into_iter()
        .filter(|p| !base.contains(&p.name))
        .collect()
}

/// Dove cercare i file dei pacchetti: la cache di pacman, quelle degli helper AUR
/// (dove finiscono `cntlm` e l'app installati da AUR), più le cartelle indicate.
pub fn find(pkg: &Pkg, extra: &[PathBuf]) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    [
        PathBuf::from("/var/cache/pacman/pkg"),
        home.join(".cache/paru/clone").join(&pkg.name),
        home.join(".cache/yay").join(&pkg.name),
    ]
    .into_iter()
    .chain(extra.iter().cloned())
    .map(|d| d.join(pkg.file_name()))
    .find(|p| p.is_file())
}

pub struct Plan {
    pub found: Vec<(Pkg, PathBuf)>,
    pub missing: Vec<Pkg>,
}

impl Plan {
    pub fn v3(&self) -> Vec<&Pkg> {
        self.found
            .iter()
            .map(|(p, _)| p)
            .filter(|p| p.needs_v3())
            .collect()
    }
}

pub fn plan(extra: &[PathBuf]) -> Plan {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for p in packages() {
        match find(&p, extra) {
            Some(path) => found.push((p, path)),
            None => missing.push(p),
        }
    }
    Plan { found, missing }
}

const INSTALL: &str = r#"#!/bin/sh
# Installa i pacchetti di questo bundle (Business Network Wizard), senza rete.
set -e
cd "$(dirname "$0")"
sudo pacman -U --needed pkg/*.pkg.tar.zst
echo
echo "Fatto. Apri «Rete aziendale» dal launcher e premi «Configura…»."
"#;

/// Scrive il bundle: `pkg/` con i pacchetti (e le firme, se ci sono), `installa.sh`,
/// `LEGGIMI.txt`.
pub fn write(plan: &Plan, out: &Path) -> std::io::Result<()> {
    let file = std::fs::File::create(out)?;
    let mut tar = tar::Builder::new(file);
    let date = chrono_free_date();
    let mut readme = format!(
        "Business Network Wizard: installazione offline ({date})\n\n\
         1. Copia questo file sul PC nuovo ed estrailo: tar xf {name}\n\
         2. Lancia: sh installa.sh   (chiede la password di amministratore)\n\
         3. Apri «Rete aziendale» e premi «Configura…» con il profilo .bnw.\n\n\
         Pacchetti ({n}):\n",
        name = out
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        n = plan.found.len(),
    );
    for (p, _) in &plan.found {
        readme += &format!("  {} {} ({})\n", p.name, p.version, p.arch);
    }
    let v3 = plan.v3();
    if !v3.is_empty() {
        readme += "\nAttenzione: alcuni pacchetti sono le versioni CachyOS ottimizzate (x86_64_v3) e si \
                   installano solo su CPU recenti (Intel Haswell / AMD Excavator o successive). Su un PC \
                   più vecchio servono le versioni x86_64 normali.\n";
    }
    if !plan.missing.is_empty() {
        readme += "\nNON inclusi (non trovati nella cache di pacman): ";
        readme += &plan
            .missing
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        readme += "\n";
    }
    let mut add = |name: &str, data: &[u8], mode: u32| -> std::io::Result<()> {
        let mut h = tar::Header::new_ustar();
        h.set_size(data.len() as u64);
        h.set_mode(mode);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut h, name, data)
    };
    add("LEGGIMI.txt", readme.as_bytes(), 0o644)?;
    add("installa.sh", INSTALL.as_bytes(), 0o755)?;
    for (p, path) in &plan.found {
        tar.append_path_with_name(path, format!("pkg/{}", p.file_name()))?;
        let sig = PathBuf::from(format!("{}.sig", path.display()));
        if sig.is_file() {
            tar.append_path_with_name(&sig, format!("pkg/{}.sig", p.file_name()))?;
        }
    }
    tar.into_inner()?.sync_all()
}

/// La data di oggi, `AAAA-MM-GG`.
fn chrono_free_date() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nomi_e_file() {
        assert_eq!(dep_name("glibc>=2.27"), "glibc");
        assert_eq!(dep_name("linux-api-headers>=4.10"), "linux-api-headers");
        assert_eq!(dep_name("sh"), "sh");
        let p = parse_expac("cups 2:2.4.19-1 x86_64\ntinyproxy 1.11.3-1.1 x86_64_v3\n");
        assert_eq!(p[0].file_name(), "cups-2:2.4.19-1-x86_64.pkg.tar.zst");
        assert!(!p[0].needs_v3() && p[1].needs_v3());
    }

    #[test]
    fn bundle_con_pacchetti_finti() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("cntlm-0.92.3-5-x86_64.pkg.tar.zst");
        std::fs::write(&pkg, b"finto").unwrap();
        let plan = Plan {
            found: vec![(
                Pkg {
                    name: "cntlm".into(),
                    version: "0.92.3-5".into(),
                    arch: "x86_64".into(),
                },
                pkg,
            )],
            missing: vec![Pkg {
                name: "cups".into(),
                version: "1".into(),
                arch: "x86_64".into(),
            }],
        };
        let out = tmp.path().join("bundle.tar");
        write(&plan, &out).unwrap();
        let mut ar = tar::Archive::new(std::fs::File::open(&out).unwrap());
        let names: Vec<String> = ar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "LEGGIMI.txt",
                "installa.sh",
                "pkg/cntlm-0.92.3-5-x86_64.pkg.tar.zst"
            ]
        );
    }
}
