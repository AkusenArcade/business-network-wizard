//! Keyfile di NetworkManager (`/etc/NetworkManager/system-connections/*.nmconnection`):
//! formato INI. Qui solo le operazioni che servono ai segreti: leggere una chiave e
//! riscriverne una lasciando intatto tutto il resto, commenti e ordine compresi.

/// Valore di `chiave` nella `[sezione]`, se c'è.
pub fn get<'a>(text: &'a str, section: &str, key: &str) -> Option<&'a str> {
    let mut cur = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') {
            cur = Some(&t[1..t.len() - 1]);
            continue;
        }
        if cur == Some(section)
            && let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            return Some(v);
        }
    }
    None
}

/// Il nome della connessione (`[connection] id=`).
pub fn connection_id(text: &str) -> Option<&str> {
    get(text, "connection", "id")
}

/// Imposta `chiave=valore` nella `[sezione]`: sostituisce la riga se c'è, altrimenti
/// la aggiunge in fondo alla sezione (prima delle righe vuote, che la chiuderebbero
/// visivamente), o crea la sezione in fondo al file.
pub fn set(text: &str, section: &str, key: &str, value: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut cur: Option<String> = None;
    let mut done = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') {
            if cur.as_deref() == Some(section) && !done {
                let blanks = out.iter().rev().take_while(|l| l.trim().is_empty()).count();
                let at = out.len() - blanks;
                out.insert(at, format!("{key}={value}"));
                done = true;
            }
            cur = Some(t[1..t.len() - 1].to_string());
        }
        if cur.as_deref() == Some(section)
            && !done
            && line.split_once('=').is_some_and(|(k, _)| k.trim() == key)
        {
            out.push(format!("{key}={value}"));
            done = true;
            continue;
        }
        out.push(line.to_string());
    }
    if !done {
        if cur.as_deref() != Some(section) {
            if out.last().is_some_and(|l| !l.trim().is_empty()) {
                out.push(String::new());
            }
            out.push(format!("[{section}]"));
        } else {
            while out.last().is_some_and(|l| l.trim().is_empty()) {
                out.pop();
            }
        }
        out.push(format!("{key}={value}"));
    }
    out.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    const VPN: &str = "[connection]\nid=Esempio\nuuid=9fa2\ntype=vpn\n\n[vpn]\nca=/x/ca.pem\npassword-flags=1\n\n[vpn-secrets]\npassword=vecchia\n\n[ipv4]\nmethod=auto\n";

    #[test]
    fn legge() {
        assert_eq!(connection_id(VPN), Some("Esempio"));
        assert_eq!(get(VPN, "vpn", "password-flags"), Some("1"));
        assert_eq!(get(VPN, "vpn", "manca"), None);
    }

    #[test]
    fn sostituisce_solo_la_riga() {
        let new = set(VPN, "vpn-secrets", "password", "nuova=con;segni");
        assert_eq!(new, VPN.replace("password=vecchia", "password=nuova=con;segni"));
        assert_eq!(get(&new, "vpn-secrets", "password"), Some("nuova=con;segni"));
    }

    #[test]
    fn aggiunge_in_fondo_alla_sezione() {
        let text = "[connection]\nid=W\n\n[802-1x]\neap=peap;\nidentity=u\n\n[ipv4]\nmethod=auto\n";
        let new = set(text, "802-1x", "password", "p");
        assert_eq!(
            new,
            "[connection]\nid=W\n\n[802-1x]\neap=peap;\nidentity=u\npassword=p\n\n[ipv4]\nmethod=auto\n"
        );
    }

    #[test]
    fn sezione_mancante_o_ultima() {
        let new = set("[connection]\nid=W\n", "vpn-secrets", "password", "p");
        assert_eq!(new, "[connection]\nid=W\n\n[vpn-secrets]\npassword=p\n");
        let new = set("[vpn-secrets]\nx=1\n\n", "vpn-secrets", "password", "p");
        assert_eq!(new, "[vpn-secrets]\nx=1\npassword=p\n");
    }
}
