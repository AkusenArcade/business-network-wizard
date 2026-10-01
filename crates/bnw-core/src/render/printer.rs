//! Code CUPS driverless: gli argomenti di `lpadmin`, senza shell di mezzo.

use crate::profile::Printer;

/// Crea (o ridefinisce) la coda. `-m everywhere` interroga la stampante al momento,
/// quindi serve la rete aziendale.
pub fn lpadmin_create(p: &Printer) -> Vec<String> {
    let mut args = vec![
        "-p".into(),
        p.name.clone(),
        "-E".into(),
        "-v".into(),
        p.uri.clone(),
    ];
    args.extend(["-m".into(), "everywhere".into()]);
    if let Some(d) = &p.description {
        args.extend(["-D".into(), d.clone()]);
    }
    if let Some(l) = &p.location {
        args.extend(["-L".into(), l.clone()]);
    }
    args.extend(["-o".into(), "printer-error-policy=abort-job".into()]);
    args
}

/// Lato di stampa predefinito, in una seconda chiamata come faceva `install.sh`: il
/// driver generato da CUPS chiama l'opzione `Duplex`, non `sides`, quindi si impostano
/// tutte e due in modo coerente.
pub fn lpadmin_sides(p: &Printer) -> Vec<String> {
    let (duplex, sides) = if p.duplex {
        ("DuplexNoTumble", "two-sided-long-edge")
    } else {
        ("None", "one-sided")
    };
    vec![
        "-p".into(),
        p.name.clone(),
        "-o".into(),
        format!("Duplex-default={duplex}"),
        "-o".into(),
        format!("sides-default={sides}"),
    ]
}

pub fn lpadmin_remove(p: &Printer) -> Vec<String> {
    vec!["-x".into(), p.name.clone()]
}

/// Le opzioni di una coda da `lpoptions -p NOME`: `chiave=valore` separati da spazi,
/// con valori tra apici e backslash di escape (anche dentro gli apici).
pub fn parse_lpoptions(out: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut chars = out.trim().chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c.is_whitespace() {
                break;
            }
            key.push(c);
            chars.next();
        }
        let mut value = String::new();
        if chars.peek() == Some(&'=') {
            chars.next();
            let mut quoted = false;
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(n) = chars.next() {
                            value.push(n);
                        }
                    }
                    '\'' => quoted = !quoted,
                    c if c.is_whitespace() && !quoted => break,
                    c => value.push(c),
                }
            }
        }
        map.insert(key, value);
    }
    map
}

/// Cosa va corretto su una coda esistente: argomenti per un `lpadmin` in più, o nulla.
pub fn lpadmin_fix(p: &Printer, current: &std::collections::HashMap<String, String>) -> Option<Vec<String>> {
    let mut args = vec!["-p".to_string(), p.name.clone()];
    let (duplex, sides) = if p.duplex {
        ("DuplexNoTumble", "two-sided-long-edge")
    } else {
        ("None", "one-sided")
    };
    if current.get("Duplex").is_some_and(|d| d != duplex) {
        args.extend(["-o".into(), format!("Duplex-default={duplex}")]);
    }
    if current.get("sides").map(String::as_str) != Some(sides) {
        args.extend(["-o".into(), format!("sides-default={sides}")]);
    }
    if let Some(d) = &p.description
        && current.get("printer-info") != Some(d)
    {
        args.extend(["-D".into(), d.clone()]);
    }
    if let Some(l) = &p.location
        && current.get("printer-location") != Some(l)
    {
        args.extend(["-L".into(), l.clone()]);
    }
    (args.len() > 2).then_some(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L'uscita vera di `lpoptions -p STAMPA_P1` su la macchina di esempio (accorciata).
    const OPZIONI_ESEMPIO: &str = "copies=1 device-uri=ipp://stampante-p1.corp.esempio/ipp Duplex=DuplexNoTumble finishings=3 marker-names='Black\\ Toner,Cyan\\ Toner,staples' printer-info='Multifunzione - Piano 1' printer-location='Esempio Piano 1' printer-is-shared=true sides=one-sided";

    fn prt() -> Printer {
        Printer {
            name: "STAMPA_P1".into(),
            uri: "ipp://stampante-p1.corp.esempio/ipp".into(),
            description: Some("Multifunzione - Piano 1".into()),
            location: Some("Esempio Piano 1".into()),
            duplex: false,
        }
    }

    #[test]
    fn legge_lpoptions() {
        let o = parse_lpoptions(OPZIONI_ESEMPIO);
        assert_eq!(o["device-uri"], "ipp://stampante-p1.corp.esempio/ipp");
        assert_eq!(o["printer-info"], "Multifunzione - Piano 1");
        assert_eq!(o["marker-names"], "Black Toner,Cyan Toner,staples");
        assert_eq!(o["Duplex"], "DuplexNoTumble");
    }

    #[test]
    fn corregge_solo_quello_che_serve() {
        // la macchina di esempio oggi: Duplex fronte-retro e sides solo fronte, in disaccordo
        let fix = lpadmin_fix(&prt(), &parse_lpoptions(OPZIONI_ESEMPIO)).unwrap();
        assert_eq!(fix, ["-p", "STAMPA_P1", "-o", "Duplex-default=None"]);
        let ok = parse_lpoptions(&OPZIONI_ESEMPIO.replace("DuplexNoTumble", "None"));
        assert_eq!(lpadmin_fix(&prt(), &ok), None);
        let mut p = prt();
        p.location = Some("Piano 7".into());
        assert_eq!(
            lpadmin_fix(&p, &ok).unwrap(),
            ["-p", "STAMPA_P1", "-L", "Piano 7"]
        );
    }
}
