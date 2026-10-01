//! `/etc/tinyproxy/direct.conf` e `/etc/tinyproxy/upstream.conf`. `active.conf` è
//! un symlink all'uno o all'altro e lo sposta `proxy-detect`.

use crate::profile::Proxy;

fn common(proxy: &Proxy) -> String {
    format!(
        "User tinyproxy
Group tinyproxy
Port {port}
Listen 127.0.0.1
Timeout 600
DefaultErrorFile \"/usr/share/tinyproxy/default.html\"
StatFile \"/usr/share/tinyproxy/stats.html\"
LogLevel Warning
MaxClients 100
Allow 127.0.0.1
Allow ::1
DisableViaHeader Yes
",
        port = proxy.local_port
    )
}

/// Modalità diretta: fuori dalla rete aziendale tinyproxy si connette da solo.
pub fn direct_conf(proxy: &Proxy) -> String {
    let mut out = String::from("# tinyproxy - modalita DIRETTA (VPN non attiva)\n");
    out += &common(proxy);
    out += "# Nessuna direttiva \"upstream\": tinyproxy si connette direttamente.\n";
    out
}

/// Modalità proxy aziendale: le eccezioni vanno dirette, il resto a cntlm.
pub fn upstream_conf(proxy: &Proxy) -> String {
    let mut out = String::from("# tinyproxy - modalita PROXY AZIENDALE (VPN attiva)\n");
    if let Some(pac) = &proxy.pac {
        out += &format!("# Regole tradotte da {pac}\n");
    }
    out += &common(proxy);
    out += "\n# Reti private e domini interni -> DIRETTO";
    if proxy.pac.is_some() {
        out += " (come le isInNet() del PAC)";
    }
    out += "\n";
    for rule in &proxy.direct {
        if let Some(note) = rule.note() {
            for line in note.trim().lines() {
                out += &format!("# {}\n", line.trim_end()).replace("# \n", "#\n");
            }
        }
        out += &format!("upstream none \"{}\"\n", rule.host());
    }
    out += &format!(
        "\n# Tutto il resto -> cntlm, che autentica in NTLM verso {}\n",
        proxy.upstream.join(", ")
    );
    out += &format!("upstream http 127.0.0.1:{}\n", proxy.cntlm_port);
    out
}
