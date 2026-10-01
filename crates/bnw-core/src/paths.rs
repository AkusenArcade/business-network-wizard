//! Percorsi di sistema che l'app legge o scrive, condivisi da helper, GUI e `bnw`.

pub const PROFILE: &str = "/etc/bnw/profile.toml";
pub const ACTIVE_CONF: &str = "/etc/tinyproxy/active.conf";
/// Forzatura manuale di `proxy-mode` (`on`/`off`); sparisce al riavvio.
pub const MANUAL: &str = "/run/proxy-mode.manual";
pub const HELPER: &str = "/usr/lib/bnw/bnw-helper";
pub const PROXY_DETECT: &str = "/usr/lib/bnw/proxy-detect";

/// I file del pacchetto che prendono il posto di quelli manuali. Se ne manca uno,
/// l'adozione non parte: si resterebbe senza rilevazione della rete.
pub const PACKAGE_FILES: [&str; 6] = [
    "/usr/lib/bnw/proxy-detect",
    "/usr/bin/proxy-mode",
    "/usr/lib/NetworkManager/dispatcher.d/90-bnw-proxy",
    "/usr/lib/systemd/system/bnw-proxy-detect.service",
    "/usr/lib/systemd/system/tinyproxy.service.d/bnw.conf",
    "/usr/lib/systemd/system/cntlm.service.d/bnw.conf",
];

/// Gli script e gli override dell'installazione manuale. Sono i nomi usati dal kit,
/// non dati aziendali.
pub const LEGACY_FILES: [&str; 6] = [
    "/usr/local/bin/proxy-detect",
    "/usr/local/bin/proxy-mode",
    "/etc/NetworkManager/dispatcher.d/90-proxy-vpn",
    "/etc/systemd/system/proxy-detect.service",
    "/etc/systemd/system/tinyproxy.service.d/override.conf",
    "/etc/systemd/system/cntlm.service.d/override.conf",
];
