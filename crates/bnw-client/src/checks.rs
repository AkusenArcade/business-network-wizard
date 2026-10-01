//! I controlli del primo passo del wizard: cosa serve sulla macchina e perché. Se manca
//! qualcosa lo si dice con il motivo, invece di fallire a metà configurazione.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub what: &'static str,
    pub ok: bool,
    /// Perché serve, o cosa fare se manca.
    pub why: &'static str,
    /// Senza questo la configurazione non può partire.
    pub required: bool,
}

/// `(cosa, file che lo prova, perché, obbligatorio)`
const FILES: [(&str, &[&str], &str, bool); 7] = [
    ("NetworkManager", &["/usr/bin/nmcli"], "gestisce VPN e WiFi", true),
    (
        "tinyproxy",
        &["/usr/bin/tinyproxy"],
        "il proxy locale a cui puntano le applicazioni",
        true,
    ),
    (
        "cntlm",
        &["/usr/bin/cntlm"],
        "l'autenticazione NTLM verso il proxy aziendale (pacchetto AUR)",
        true,
    ),
    (
        "OpenVPN per NetworkManager",
        &[
            "/usr/lib/NetworkManager/libnm-vpn-plugin-openvpn.so",
            "/usr/lib/NetworkManager/nm-openvpn-service",
        ],
        "la VPN aziendale (networkmanager-openvpn)",
        false,
    ),
    ("cifs-utils", &["/usr/bin/mount.cifs"], "i dischi di rete", false),
    ("CUPS", &["/usr/bin/lpadmin"], "le stampanti", false),
    (
        "helper dell'app",
        &["/usr/lib/bnw/bnw-helper"],
        "le modifiche di sistema (pacchetto business-network-wizard)",
        true,
    ),
];

fn polkit_agent_running() -> bool {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return false;
    };
    dir.flatten().any(|e| {
        std::fs::read(e.path().join("cmdline")).is_ok_and(|c| {
            let c = String::from_utf8_lossy(&c).to_lowercase();
            c.contains("polkit") && (c.contains("agent") || c.contains("authentication"))
        })
    })
}

pub fn run() -> Vec<Check> {
    let mut out: Vec<Check> = FILES
        .iter()
        .map(|(what, files, why, required)| Check {
            what,
            ok: files.iter().any(|f| Path::new(f).exists()),
            why,
            required: *required,
        })
        .collect();
    out.push(Check {
        what: "agente polkit",
        ok: polkit_agent_running(),
        why: "chiede la password di amministratore quando l'app cambia il sistema",
        required: true,
    });
    out
}

/// Cosa fare se mancano dei pacchetti: per installarli serve internet non aziendale,
/// perché sulla rete dell'ufficio pacman vorrebbe il proxy che ancora non c'è.
pub const MISSING_HINT: &str = "Per installare i pacchetti che mancano serve una connessione internet non aziendale \
(per esempio l'hotspot del telefono): sulla rete dell'ufficio pacman avrebbe bisogno del proxy, che non è ancora \
configurato.";
