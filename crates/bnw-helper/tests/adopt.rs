//! "Adotta" su una radice finta che imita la macchina di esempio: file reali dai fixture, script
//! manuali al loro posto, pacchetto installato.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use bnw_core::Profile;
use bnw_core::action::{Action, Outcome, Report};
use bnw_core::paths::{LEGACY_FILES, PACKAGE_FILES};
use bnw_helper::sys::{CmdOutput, Fs, Runner};

#[derive(Default)]
struct Fake {
    calls: Vec<String>,
}

impl Runner for Fake {
    fn run(&mut self, program: &str, args: &[&str], _stdin: Option<&str>) -> std::io::Result<CmdOutput> {
        self.calls.push(
            std::iter::once(program)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" "),
        );
        Ok(CmdOutput {
            success: true,
            ..Default::default()
        })
    }
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/esempio")
}

fn profile() -> Profile {
    Profile::from_toml(&fs::read_to_string(fixtures().join("profile.toml")).unwrap()).unwrap()
}

fn put(root: &Path, abs: &str, content: &str, mode: u32) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, content).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
}

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

/// la macchina di esempio com'è oggi, senza segreti veri.
fn esempio(root: &Path, with_package: bool) -> String {
    for rel in [
        "etc/tinyproxy/direct.conf",
        "etc/tinyproxy/upstream.conf",
        "etc/environment",
        "etc/firefox/policies/policies.json",
        "etc/zen/policies/policies.json",
    ] {
        put(
            root,
            rel,
            &fs::read_to_string(fixtures().join(rel)).unwrap(),
            0o644,
        );
    }
    std::os::unix::fs::symlink(
        "/etc/tinyproxy/upstream.conf",
        root.join("etc/tinyproxy/active.conf"),
    )
    .unwrap();
    let cntlm = fs::read_to_string(fixtures().join("etc/cntlm.conf.senza-hash"))
        .unwrap()
        .replace(
            "Domain          ESEMPIO\n",
            "Domain          ESEMPIO\nPassNTLMv2      ABCD\n",
        );
    put(root, "/etc/cntlm.conf", &cntlm, 0o600);
    for f in LEGACY_FILES {
        put(root, f, "#!/bin/sh\n", 0o755);
    }
    put(
        root,
        "/etc/NetworkManager/dispatcher.d/90-proxy-vpn.bak-20260920-170025",
        "#!/bin/sh\n",
        0o755,
    );
    if with_package {
        for f in PACKAGE_FILES {
            put(root, f, "#!/bin/sh\n", 0o755);
        }
    }
    cntlm
}

fn run(root: &Path, fake: &mut Fake) -> Report {
    bnw_helper::run(&Action::Adopt { profile: profile() }, Fs::new(root, false), fake)
}

#[test]
fn adotta_esempio() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let cntlm = esempio(root, true);
    // Zen di sistema sotto /opt: è del pacchetto, non va toccato
    let zen_opt = "{\n  \"policies\": {\n    \"DisableAppUpdate\": true\n  }\n}\n";
    put(
        root,
        "/opt/zen-browser-bin/distribution/policies.json",
        zen_opt,
        0o644,
    );

    let mut fake = Fake::default();
    let r = run(root, &mut fake);
    assert!(!r.failed(), "{r:#?}");
    assert_eq!(
        fs::read_to_string(root.join("opt/zen-browser-bin/distribution/policies.json")).unwrap(),
        zen_opt
    );

    // i file di tinyproxy e dei browser erano già identici: non si toccano
    for f in [
        "/etc/tinyproxy/upstream.conf",
        "/etc/tinyproxy/direct.conf",
        "/etc/environment",
        "/etc/zen/policies/policies.json",
    ] {
        let s = r.steps.iter().find(|s| s.what == f).unwrap();
        assert_eq!(s.outcome, Outcome::Unchanged, "{f}");
    }
    assert_eq!(
        fs::read_link(root.join("etc/tinyproxy/active.conf")).unwrap(),
        Path::new("/etc/tinyproxy/upstream.conf")
    );
    assert!(root.join("etc/bnw/profile.toml").exists());
    // cntlm.conf intatto, nessun backup, nessun riavvio di cntlm
    assert_eq!(fs::read_to_string(root.join("etc/cntlm.conf")).unwrap(), cntlm);
    assert!(
        !fake
            .calls
            .iter()
            .any(|c| c.contains("cntlm.service") && !c.contains("disable"))
    );

    // gli script manuali sono in .bak e non più eseguibili
    for f in LEGACY_FILES {
        let p = root.join(f.trim_start_matches('/'));
        assert!(!p.exists(), "{f} è ancora lì");
        let dir = p.parent().unwrap();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let baks: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{name}.bak-"))
            })
            .collect();
        assert!(!baks.is_empty(), "manca il backup di {f}");
        for b in baks {
            assert_eq!(mode(&b.path()), 0o644, "{:?}", b.path());
        }
    }
    // compreso il vecchio backup eseguibile del dispatcher
    assert_eq!(
        mode(&root.join("etc/NetworkManager/dispatcher.d/90-proxy-vpn.bak-20260920-170025")),
        0o644
    );
    // i file del pacchetto restano
    for f in PACKAGE_FILES {
        assert_eq!(mode(&root.join(f.trim_start_matches('/'))), 0o755);
    }

    let tail: Vec<&str> = fake
        .calls
        .iter()
        .rev()
        .take(3)
        .rev()
        .map(String::as_str)
        .collect();
    assert_eq!(
        tail,
        [
            "/usr/bin/systemctl daemon-reload",
            "/usr/bin/systemctl restart tinyproxy.service",
            "/usr/bin/systemctl start bnw-proxy-detect.service",
        ]
    );

    // rilanciata non trova più niente da mettere da parte
    let mut fake = Fake::default();
    let r = run(root, &mut fake);
    assert!(!r.failed(), "{r:#?}");
    assert!(!fake.calls.iter().any(|c| c.contains("daemon-reload")));
}

#[test]
fn senza_pacchetto_non_tocca_niente() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let _ = esempio(root, false);

    let mut fake = Fake::default();
    let r = run(root, &mut fake);
    assert!(r.failed());
    assert!(
        r.steps[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("/usr/lib/bnw/proxy-detect")
    );
    assert!(fake.calls.is_empty());
    assert!(!root.join("etc/bnw").exists());
    for f in LEGACY_FILES {
        assert!(root.join(f.trim_start_matches('/')).exists());
    }
}
