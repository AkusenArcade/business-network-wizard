//! File `.ovpn`: i blocchi inline (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`…) diventano
//! file separati prima dell'import in NetworkManager. Così i certificati e la chiave
//! finiscono in una cartella di sistema `700` scelta da noi, e non dove l'importatore
//! li mette da solo (la home di chi lo lancia: sotto pkexec sarebbe `/root`).

/// I blocchi inline che OpenVPN accetta anche come percorso di file.
const INLINE: [&str; 6] = ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"];

/// Un file estratto: nome nella cartella di destinazione e contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    pub name: String,
    pub content: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OvpnError {
    #[error("il file non è testo UTF-8")]
    NotText,
    #[error("blocco <{0}> non chiuso")]
    Unclosed(String),
    #[error("manca la direttiva «remote»: non sembra un profilo OpenVPN client")]
    NoRemote,
}

/// Riscrive l'`.ovpn` con i blocchi inline sostituiti da `direttiva <dir>/<nome>` e
/// restituisce i file da scrivere in `dir`.
pub fn externalize(ovpn: &[u8], dir: &str) -> Result<(String, Vec<Extracted>), OvpnError> {
    let text = std::str::from_utf8(ovpn).map_err(|_| OvpnError::NotText)?;
    let mut out = String::new();
    let mut files = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let t = line.trim();
        let tag = INLINE.iter().find(|tag| t == format!("<{tag}>")).copied();
        let Some(tag) = tag else {
            out += line;
            out += "\n";
            continue;
        };
        let close = format!("</{tag}>");
        let mut body = String::new();
        loop {
            let Some(l) = lines.next() else {
                return Err(OvpnError::Unclosed(tag.to_string()));
            };
            if l.trim() == close {
                break;
            }
            body += l;
            body += "\n";
        }
        let name = match tag {
            "ca" => "ca.pem",
            "cert" => "cert.pem",
            "key" => "key.pem",
            "tls-auth" => "tls-auth.key",
            "tls-crypt" => "tls-crypt.key",
            _ => "tls-crypt-v2.key",
        };
        out += &format!("{tag} {dir}/{name}\n");
        files.push(Extracted {
            name: name.to_string(),
            content: body,
        });
    }
    if !out.lines().any(|l| l.split_whitespace().next() == Some("remote")) {
        return Err(OvpnError::NoRemote);
    }
    Ok((out, files))
}

/// Le direttive presenti: solo i nomi, mai i valori. Sicura per costruzione anche su
/// un `.ovpn` con chiavi inline: salta il contenuto dei blocchi `<…>` e accetta solo
/// parole fatte di minuscole, cifre e trattini (le righe base64 no).
pub fn directives(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with("</") {
            in_block = false;
            continue;
        }
        if t.starts_with('<') {
            in_block = true;
            continue;
        }
        if in_block {
            continue;
        }
        let Some(w) = t.split_whitespace().next() else {
            continue;
        };
        if w.len() <= 32
            && w.starts_with(|c: char| c.is_ascii_lowercase())
            && w.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            out.push(w.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const OVPN: &str = "client\ndev tun\nproto tcp\nremote vpn.esempio.it 443\n<ca>\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n</ca>\n<cert>\nBBB\n</cert>\n<key>\nCHIAVE\n</key>\nkey-direction 1\n<tls-auth>\nTA\n</tls-auth>\nns-cert-type server\nauth-user-pass\n";

    #[test]
    fn estrae_i_blocchi() {
        let (text, files) = externalize(OVPN.as_bytes(), "/etc/bnw/vpn/esempio").unwrap();
        assert!(text.contains("ca /etc/bnw/vpn/esempio/ca.pem\ncert /etc/bnw/vpn/esempio/cert.pem\nkey /etc/bnw/vpn/esempio/key.pem\nkey-direction 1\ntls-auth /etc/bnw/vpn/esempio/tls-auth.key\n"), "{text}");
        assert!(!text.contains("CHIAVE") && !text.contains('<'));
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["ca.pem", "cert.pem", "key.pem", "tls-auth.key"]);
        assert_eq!(files[2].content, "CHIAVE\n");
        assert_eq!(
            directives(&text),
            [
                "auth-user-pass",
                "ca",
                "cert",
                "client",
                "dev",
                "key",
                "key-direction",
                "ns-cert-type",
                "proto",
                "remote",
                "tls-auth"
            ]
        );
    }

    #[test]
    fn le_direttive_non_mostrano_mai_i_blocchi() {
        // anche sul file originale, con le chiavi inline
        let d = directives(OVPN);
        assert!(
            d.iter()
                .all(|w| !["chiave", "aaa", "bbb", "ta"].contains(&w.as_str())),
            "{d:?}"
        );
        assert!(directives("<key>\nabcdefgh\n</key>\nclient\n") == ["client"]);
    }

    #[test]
    fn errori() {
        assert_eq!(
            externalize(b"client\n<key>\nX\n", "/d"),
            Err(OvpnError::Unclosed("key".into()))
        );
        assert_eq!(externalize(b"client\ndev tun\n", "/d"), Err(OvpnError::NoRemote));
        assert_eq!(externalize(&[0xff, 0xfe], "/d"), Err(OvpnError::NotText));
    }
}
