//! `/etc/bnw/proxy-detect.conf`: i pochi dati del profilo che servono agli script
//! `proxy-detect` e `proxy-mode`. Righe `CHIAVE=valore`, lette senza `source`: il
//! valore non passa mai da una shell.

use crate::profile::Profile;

pub const PATH: &str = "/etc/bnw/proxy-detect.conf";

pub fn proxy_detect_conf(profile: &Profile) -> String {
    let mut out = String::from("# Generato da Business Network Wizard: non modificare a mano.\n");
    if let Some(vpn) = &profile.vpn {
        out += &format!("VPN_NAME={}\n", vpn.name);
    }
    for u in &profile.proxy.upstream {
        out += &format!("PROXY={u}\n");
    }
    out
}
