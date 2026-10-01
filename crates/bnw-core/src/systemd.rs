//! Nomi delle unit systemd, come `systemd-escape --path`.

/// Escape di un percorso in nome di unit: `/mnt/area-clienti` diventa
/// `mnt-area\x2dclienti`.
pub fn escape_path(path: &str) -> String {
    let trimmed: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if trimmed.is_empty() {
        return "-".to_string();
    }
    let joined = trimmed.join("/");
    let mut out = String::new();
    for (i, b) in joined.bytes().enumerate() {
        match b {
            b'/' => out.push('-'),
            b'.' if i == 0 => out.push_str("\\x2e"),
            b if b.is_ascii_alphanumeric() || b == b':' || b == b'_' || b == b'.' => out.push(b as char),
            b => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

pub fn mount_unit(path: &str) -> String {
    format!("{}.mount", escape_path(path))
}

pub fn automount_unit(path: &str) -> String {
    format!("{}.automount", escape_path(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn come_systemd_escape() {
        assert_eq!(escape_path("/mnt/esempio"), "mnt-esempio");
        assert_eq!(escape_path("/mnt/area-clienti"), "mnt-area\\x2dclienti");
        assert_eq!(escape_path("//mnt//a b/"), "mnt-a\\x20b");
        assert_eq!(escape_path("/.nascosta"), "\\x2enascosta");
        assert_eq!(escape_path("/"), "-");
        assert_eq!(mount_unit("/mnt/progetti"), "mnt-progetti.mount");
    }
}
