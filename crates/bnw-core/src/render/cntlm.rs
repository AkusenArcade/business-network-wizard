//! `/etc/cntlm.conf`: autenticazione NTLMv2 verso il proxy aziendale.
//!
//! Il file contiene gli hash della password di dominio. Si scrive per intero solo alla
//! prima configurazione; al cambio password si riscrivono **solo** le righe `Pass*`
//! ([`replace_hashes`]), come fa `cambia-password-dominio.sh`.

use crate::profile::{DirectRule, Profile};
use crate::target::Secret;

/// Gli hash prodotti da `cntlm -H`. `PassLM` e `PassNT` ci sono solo con le
/// versioni di cntlm che li stampano; per `Auth NTLMv2` basta `PassNTLMv2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmHashes {
    pub lm: Option<Secret>,
    pub nt: Option<Secret>,
    pub ntlmv2: Secret,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CntlmError {
    #[error("cntlm non ha generato l'hash PassNTLMv2")]
    MissingNtlmv2,
    #[error("valore di hash non valido nella riga {0}")]
    BadHash(&'static str),
}

/// Legge l'uscita di `cntlm -H -u <utente> -d <dominio>`. Le righe hanno la forma
/// `PassNTLMv2      ABCDEF…    # Only for user 'x', domain 'y'`.
pub fn parse_hash_output(output: &str) -> Result<NtlmHashes, CntlmError> {
    let mut lm = None;
    let mut nt = None;
    let mut v2 = None;
    for line in output.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut parts = line.split_whitespace();
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (slot, name) = match key {
            "PassLM" => (&mut lm, "PassLM"),
            "PassNT" => (&mut nt, "PassNT"),
            "PassNTLMv2" => (&mut v2, "PassNTLMv2"),
            _ => continue,
        };
        if !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CntlmError::BadHash(name));
        }
        *slot = Some(Secret::new(value));
    }
    Ok(NtlmHashes {
        lm,
        nt,
        ntlmv2: v2.ok_or(CntlmError::MissingNtlmv2)?,
    })
}

fn hash_lines(h: &NtlmHashes) -> String {
    let mut out = String::new();
    if let Some(lm) = &h.lm {
        out += &format!("PassLM          {}\n", lm.expose());
    }
    if let Some(nt) = &h.nt {
        out += &format!("PassNT          {}\n", nt.expose());
    }
    out += &format!("PassNTLMv2      {}\n", h.ntlmv2.expose());
    out
}

/// Le eccezioni del profilo nella sintassi a caratteri jolly di cntlm. È una rete di
/// sicurezza: le eccezioni le applica già tinyproxy, che a cntlm non le inoltra.
/// Le reti CIDR che non cadono sul confine di un ottetto si restringono all'ottetto
/// successivo (`172.16.0.0/12` → `172.16.*`): meglio una rete in meno che una in più.
pub fn no_proxy(direct: &[DirectRule]) -> String {
    let mut out: Vec<String> = Vec::new();
    for rule in direct {
        let host = rule.host();
        let item = if let Some((ip, bits)) = host.split_once('/') {
            let Ok(bits) = bits.parse::<u32>() else { continue };
            let octets: Vec<&str> = ip.split('.').collect();
            if octets.len() != 4 || bits > 32 {
                continue;
            }
            let keep = bits.div_ceil(8) as usize;
            if keep == 4 {
                ip.to_string()
            } else {
                format!("{}.*", octets[..keep].join("."))
            }
        } else if let Some(suffix) = host.strip_prefix('.') {
            format!("*.{suffix}")
        } else {
            host.to_string()
        };
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out.join(", ")
}

/// Il file completo, per la prima configurazione.
pub fn cntlm_conf(profile: &Profile, domain_user: &str, hashes: &NtlmHashes) -> String {
    let mut out = String::new();
    out += &format!("Username        {domain_user}\n");
    out += &format!("Domain          {}\n", profile.company.domain);
    out += &hash_lines(hashes);
    for upstream in &profile.proxy.upstream {
        out += &format!("Proxy           {upstream}\n");
    }
    out += &format!("NoProxy         {}\n", no_proxy(&profile.proxy.direct));
    out += &format!("Listen          127.0.0.1:{}\n", profile.proxy.cntlm_port);
    out += "Auth            NTLMv2\n";
    out += "Gateway         no\n";
    out
}

/// Rigenera le impostazioni dal profilo (proxy, eccezioni, porta, dominio) tenendo
/// l'utenza e gli hash del file esistente. `None` se il file non ha ancora utenza e
/// hash: allora serve la password, e lo fa la prima configurazione.
pub fn update_settings(existing: &str, profile: &Profile) -> Option<String> {
    let user = existing.lines().find_map(|l| {
        let mut parts = l.split_whitespace();
        (parts.next() == Some("Username")).then(|| parts.next()).flatten()
    })?;
    let hashes = parse_hash_output(existing).ok()?;
    Some(cntlm_conf(profile, user, &hashes))
}

/// Sostituisce le righe `PassLM`/`PassNT`/`PassNTLMv2` lasciando intatto il resto.
/// Le nuove righe vanno al posto della prima riga `Pass*` trovata; se non ce n'è
/// nessuna, dopo `Domain` (o in cima al file). Un'eventuale `Password` in chiaro
/// sparisce: sarebbe quella vecchia.
pub fn replace_hashes(existing: &str, hashes: &NtlmHashes) -> String {
    let is_pass = |l: &str| {
        matches!(
            l.split_whitespace().next(),
            Some("PassLM" | "PassNT" | "PassNTLMv2" | "Password")
        )
    };
    let mut out = String::new();
    let mut written = false;
    for line in existing.lines() {
        if is_pass(line) {
            if !written {
                out += &hash_lines(hashes);
                written = true;
            }
            continue;
        }
        out += line;
        out += "\n";
    }
    if written {
        return out;
    }
    // Nessuna riga Pass*: inserisci dopo Domain.
    let mut result = String::new();
    for line in out.lines() {
        result += line;
        result += "\n";
        if !written && line.split_whitespace().next() == Some("Domain") {
            result += &hash_lines(hashes);
            written = true;
        }
    }
    if !written {
        result = hash_lines(hashes) + &result;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hashes(tag: &str) -> NtlmHashes {
        NtlmHashes {
            lm: Some(Secret::new(format!("{tag}11"))),
            nt: Some(Secret::new(format!("{tag}22"))),
            ntlmv2: Secret::new(format!("{tag}33")),
        }
    }

    #[test]
    fn legge_output_di_cntlm() {
        let out = "Password: \nPassLM          AAAA\nPassNT          BBBB\n\
                   PassNTLMv2      CCCC    # Only for user 'x', domain 'Y'\n";
        let h = parse_hash_output(out).unwrap();
        assert_eq!(h.lm.unwrap().expose(), "AAAA");
        assert_eq!(h.nt.unwrap().expose(), "BBBB");
        assert_eq!(h.ntlmv2.expose(), "CCCC");
    }

    #[test]
    fn senza_ntlmv2_e_un_errore() {
        assert_eq!(parse_hash_output("PassNT  AB\n"), Err(CntlmError::MissingNtlmv2));
        assert_eq!(parse_hash_output(""), Err(CntlmError::MissingNtlmv2));
        assert_eq!(
            parse_hash_output("PassNTLMv2 zz'\n"),
            Err(CntlmError::BadHash("PassNTLMv2"))
        );
    }

    #[test]
    fn hash_nel_debug_non_compaiono() {
        let s = format!("{:?}", hashes("DEAD"));
        assert!(!s.contains("DEAD"), "{s}");
    }

    #[test]
    fn riscrive_solo_le_righe_pass() {
        let old = "Username        u\nDomain          D\nPassLM          OLD1\n\
                   PassNT          OLD2\nPassNTLMv2      OLD3\n# commento\nProxy  1.2.3.4:3128\n";
        let new = replace_hashes(old, &hashes("AB"));
        assert_eq!(
            new,
            "Username        u\nDomain          D\nPassLM          AB11\n\
             PassNT          AB22\nPassNTLMv2      AB33\n# commento\nProxy  1.2.3.4:3128\n"
        );
        // idempotente
        assert_eq!(replace_hashes(&new, &hashes("AB")), new);
    }

    #[test]
    fn senza_righe_pass_le_mette_dopo_domain() {
        let old = "Username u\nDomain D\nProxy p:1\n";
        let new = replace_hashes(old, &hashes("CD"));
        assert!(
            new.starts_with("Username u\nDomain D\nPassLM          CD11\n"),
            "{new}"
        );
        assert!(new.ends_with("Proxy p:1\n"));
    }

    #[test]
    fn no_proxy_dalle_eccezioni() {
        let d: Vec<DirectRule> = [
            "localhost",
            "127.0.0.0/8",
            "172.16.0.0/12",
            "10.1.2.3/32",
            ".corp.esempio",
            "x.it",
            ".corp.esempio",
        ]
        .iter()
        .map(|s| DirectRule::Host(s.to_string()))
        .collect();
        assert_eq!(
            no_proxy(&d),
            "localhost, 127.*, 172.16.*, 10.1.2.3, *.corp.esempio, x.it"
        );
    }
}
