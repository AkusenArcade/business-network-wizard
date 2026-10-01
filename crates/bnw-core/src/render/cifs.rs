//! Share CIFS: file credenziali e coppia di unit `.mount` + `.automount` per share.

use crate::profile::{Profile, Share};
use crate::systemd;
use crate::target::{Secret, Target};

/// `/etc/samba/credentials/<azienda>`: il kernel cifs non accetta hash, quindi la
/// password sta in chiaro (il file è `600 root`).
pub fn credentials_path(profile: &Profile) -> String {
    format!("/etc/samba/credentials/{}", profile.company.slug())
}

pub fn credentials(profile: &Profile, target: &Target, password: &Secret) -> String {
    credentials_for(&target.domain_user, &profile.company.domain, password)
}

/// Utente e dominio di un file credenziali esistente (la password non si legge).
pub fn parse_credentials(text: &str) -> (Option<&str>, Option<&str>) {
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    (field("username"), field("domain"))
}

/// Il file credenziali con una password nuova, tenendo utente e dominio.
pub fn credentials_for(user: &str, domain: &str, password: &Secret) -> String {
    format!(
        "username={user}\ndomain={domain}\npassword={}\n",
        password.expose()
    )
}

/// Un file di unit da scrivere in `/etc/systemd/system/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitFile {
    pub name: String,
    pub content: String,
}

pub fn mount_unit(profile: &Profile, target: &Target, share: &Share) -> UnitFile {
    let reach = match &profile.vpn {
        Some(vpn) => format!("Raggiungibile solo con la VPN {} attiva.", vpn.name),
        None => "Raggiungibile solo dalla rete aziendale.".to_string(),
    };
    let content = format!(
        "[Unit]
Description=Share aziendale {unc}
# {reach}
After=network-online.target
Wants=network-online.target

[Mount]
What={unc}
Where={mount}
Type=cifs
Options=credentials={cred},uid={uid},gid={gid},file_mode=0644,dir_mode=0755,iocharset=utf8,mfsymlinks,nofail,_netdev,soft
# Senza VPN il server non risponde: fallisci in fretta invece di bloccare chi legge la cartella.
TimeoutSec=20
",
        unc = share.unc(),
        mount = share.mount,
        cred = credentials_path(profile),
        uid = target.uid,
        gid = target.gid,
    );
    UnitFile {
        name: systemd::mount_unit(&share.mount),
        content,
    }
}

/// Monta al primo accesso e smonta dopo 10 minuti di inattività.
pub fn automount_unit(share: &Share) -> UnitFile {
    let content = format!(
        "[Unit]
Description=Automount della share aziendale {unc}

[Automount]
Where={mount}
TimeoutIdleSec=600

[Install]
WantedBy=multi-user.target
",
        unc = share.unc(),
        mount = share.mount,
    );
    UnitFile {
        name: systemd::automount_unit(&share.mount),
        content,
    }
}

/// Tutte le unit del profilo, nell'ordine delle share.
pub fn units(profile: &Profile, target: &Target) -> Vec<UnitFile> {
    profile
        .shares
        .iter()
        .flat_map(|s| [mount_unit(profile, target, s), automount_unit(s)])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utente_e_dominio_dalle_credenziali() {
        assert_eq!(
            parse_credentials("username=u.x\ndomain=D\npassword=p=q\n"),
            (Some("u.x"), Some("D"))
        );
        assert_eq!(parse_credentials("password=x\n"), (None, None));
    }
}
