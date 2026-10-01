//! Il protocollo tra la GUI (o `bnw`) e `bnw-helper`: una [`Action`] in JSON sullo
//! stdin dell'helper, un [`Report`] in JSON sul suo stdout. I segreti viaggiano solo
//! così, mai negli argomenti (`/proc/*/cmdline` è leggibile da tutti).

use serde::{Deserialize, Serialize};

use crate::profile::Profile;
use crate::target::{Blob, Secret};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
// Una sola azione per processo: la differenza di dimensione tra varianti non conta.
#[allow(clippy::large_enum_variant)]
pub enum Action {
    /// Scrive la catena del proxy dal profilo: `/etc/bnw/`, tinyproxy, impostazioni di
    /// cntlm (tenendo gli hash), `/etc/environment`, policy dei browser.
    ApplyProxy { profile: Profile },
    /// Prima configurazione di cntlm: calcola gli hash e scrive `/etc/cntlm.conf`.
    /// Il profilo lo prende da `/etc/bnw/profile.toml`.
    WriteCntlm { domain_user: String, password: Secret },
    /// Forzatura della modalità del proxy (`proxy-mode`).
    SetMode { mode: ProxyMode },
    /// Prende in carico una configurazione fatta a mano (`install.sh`): applica il
    /// profilo, poi mette in `.bak` gli script manuali che il pacchetto sostituisce.
    Adopt { profile: Profile },
    /// Primo passo del cambio password: ferma cntlm prima che l'utente scriva la
    /// password nuova, così non ritenta con gli hash vecchi (407 → account bloccato).
    StopCntlm,
    /// Annulla `StopCntlm`: riaccende cntlm se la modalità attuale lo richiede.
    StartCntlm,
    /// Scrive la password di dominio nei posti indicati (tutti quelli configurati se
    /// `only` è vuoto), smonta le share, poi verifica l'NTLM verso l'esterno.
    SetPassword {
        password: Secret,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        only: Vec<Place>,
        /// L'utenza di dominio: serve su una macchina nuova, dove nessun file la
        /// contiene ancora (e `cntlm.conf` va creato da zero).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_user: Option<String>,
    },
    /// Applica un profilo intero (import, prima configurazione, cambio di profilo):
    /// legge il profilo applicato prima una volta sola, toglie quello che nel nuovo non
    /// c'è più (VPN e WiFi con un altro nome, dischi, stampanti, credenziali di
    /// un'altra azienda), poi applica proxy, VPN, WiFi, dischi e stampanti.
    ApplyProfile {
        profile: Profile,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ovpn: Option<Blob>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca: Option<Blob>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner_uid: Option<u32>,
    },
    /// Dove sta la password e quando è stata scritta l'ultima volta.
    PasswordStatus,
    /// La VPN del profilo: importa l'`.ovpn` se la connessione non c'è (o se
    /// `reimport`), poi applica le correzioni. Senza `ovpn` applica solo le correzioni
    /// alla connessione esistente. La password, se c'è, va nei secret.
    ApplyVpn {
        profile: Profile,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ovpn: Option<Blob>,
        #[serde(default)]
        reimport: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<Secret>,
    },
    /// I dischi di rete del profilo: unit `.mount` + `.automount`, cartelle, automount
    /// attivi. Le share che c'erano nel profilo applicato e ora no vengono tolte.
    /// `owner_uid`: l'utente a cui appartengono i file montati (sotto pkexec vale
    /// comunque `PKEXEC_UID`).
    ApplyShares {
        profile: Profile,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner_uid: Option<u32>,
    },
    /// Smonta adesso le share montate (rimontano da sole al primo accesso).
    UnmountShares,
    /// Le stampanti del profilo: code CUPS driverless, lato di stampa, descrizione e
    /// posizione. Quelle che c'erano nel profilo applicato e ora no vengono tolte.
    ApplyPrinters { profile: Profile },
    /// Il WiFi aziendale 802.1X del profilo: crea o aggiorna la connessione. Senza `ca`
    /// tiene quella attuale (che deve avere il fingerprint del profilo).
    ApplyWifi {
        profile: Profile,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca: Option<Blob>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<Secret>,
    },
}

/// I posti dove sta la password di dominio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Place {
    /// Secret della connessione VPN in NetworkManager.
    Vpn,
    /// Secret 802.1X del WiFi aziendale in NetworkManager.
    Wifi,
    /// Hash NTLMv2 in `/etc/cntlm.conf`.
    Cntlm,
    /// Password in chiaro nel file credenziali CIFS.
    Cifs,
}

impl Place {
    pub const ALL: [Place; 4] = [Place::Vpn, Place::Wifi, Place::Cntlm, Place::Cifs];

    pub fn label(self) -> &'static str {
        match self {
            Place::Vpn => "VPN",
            Place::Wifi => "WiFi aziendale",
            Place::Cntlm => "proxy (cntlm)",
            Place::Cifs => "dischi di rete",
        }
    }
}

/// Esito della prova NTLM verso l'esterno dopo il cambio password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum NtlmCheck {
    /// Il proxy aziendale ha accettato le credenziali.
    Ok { code: u16 },
    /// 407: password rifiutata. cntlm è stato fermato.
    Rejected,
    /// Né sì né no (rete assente, timeout…): `code` 0 se non c'è stata risposta.
    Inconclusive { code: u16 },
    /// cntlm non serve con la rete attuale: la prova si fa sulla rete aziendale.
    NotRun,
}

impl Action {
    /// Nome breve, per i log.
    pub fn name(&self) -> &'static str {
        match self {
            Action::ApplyProxy { .. } => "apply-proxy",
            Action::WriteCntlm { .. } => "write-cntlm",
            Action::SetMode { .. } => "set-mode",
            Action::Adopt { .. } => "adopt",
            Action::StopCntlm => "stop-cntlm",
            Action::StartCntlm => "start-cntlm",
            Action::SetPassword { .. } => "set-password",
            Action::PasswordStatus => "password-status",
            Action::ApplyVpn { .. } => "apply-vpn",
            Action::ApplyWifi { .. } => "apply-wifi",
            Action::ApplyShares { .. } => "apply-shares",
            Action::UnmountShares => "unmount-shares",
            Action::ApplyPrinters { .. } => "apply-printers",
            Action::ApplyProfile { .. } => "apply-profile",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// Rileva la rete: VPN attiva o proxy aziendale raggiungibile.
    Auto,
    /// Sempre attraverso il proxy aziendale, fino ad `auto` o al riavvio.
    On,
    /// Sempre diretto, fino ad `auto` o al riavvio.
    Off,
}

impl ProxyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyMode::Auto => "auto",
            ProxyMode::On => "on",
            ProxyMode::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Il passo ha cambiato qualcosa.
    Changed,
    /// Era già tutto a posto.
    Unchanged,
    /// Non applicabile qui (es. browser non installato).
    Skipped,
    Failed,
}

/// Un passo dell'azione, come le righe di `install.sh`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub what: String,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Il posto della password a cui si riferisce il passo, se c'è.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<Place>,
    /// Ultima modifica del file del passo (secondi Unix), per `PasswordStatus`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub steps: Vec<Step>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntlm: Option<NtlmCheck>,
    /// Per `PasswordStatus`: la password è la stessa in tutti i posti? `None` se non
    /// si è potuto confrontare (meno di due posti con una password).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_aligned: Option<bool>,
}

impl Report {
    pub fn push(&mut self, what: impl Into<String>, outcome: Outcome, detail: Option<String>) {
        self.steps.push(Step {
            what: what.into(),
            outcome,
            detail,
            place: None,
            mtime: None,
        });
    }

    pub fn failed(&self) -> bool {
        self.steps.iter().any(|s| s.outcome == Outcome::Failed)
    }

    /// Distanza in secondi tra la scrittura più vecchia e la più recente dei posti
    /// della password: se è grande, un aggiornamento è rimasto a metà.
    pub fn mtime_spread(&self) -> Option<i64> {
        let times: Vec<i64> = self.steps.iter().filter_map(|s| s.mtime).collect();
        Some(times.iter().max()? - times.iter().min()?)
    }
}

/// Il passo della prova della password nuova con un cntlm temporaneo, prima di
/// scriverla.
pub const TRIAL_STEP: &str = "prova della password nuova";

impl Report {
    /// La password è stata rifiutata dalla prova preventiva: non è stato scritto niente.
    pub fn rejected_before_writing(&self) -> bool {
        self.ntlm == Some(NtlmCheck::Rejected)
            && self
                .steps
                .iter()
                .any(|s| s.what == TRIAL_STEP && s.outcome == Outcome::Failed)
    }
}

/// Oltre questa distanza le date dei posti della password si considerano lontane.
pub const SPREAD_WARNING_SECS: i64 = 10 * 60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_con_il_tag_action() {
        let a = Action::SetMode { mode: ProxyMode::Off };
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(j, r#"{"action":"set-mode","mode":"off"}"#);
        assert_eq!(serde_json::from_str::<Action>(&j).unwrap(), a);
    }

    #[test]
    fn la_password_non_finisce_nel_debug() {
        let a = Action::WriteCntlm {
            domain_user: "u".into(),
            password: Secret::new("SEGRETA"),
        };
        assert!(!format!("{a:?}").contains("SEGRETA"));
        assert!(serde_json::to_string(&a).unwrap().contains("SEGRETA"));
    }

    #[test]
    fn i_file_non_finiscono_nel_debug() {
        let p =
            crate::Profile::from_toml(include_str!("../../../tests/fixtures/esempio/profile.toml")).unwrap();
        let a = Action::ApplyVpn {
            profile: p,
            ovpn: Some(Blob(b"<key>\nCHIAVE\n</key>\n".to_vec())),
            reimport: false,
            domain_user: None,
            password: None,
        };
        let dbg = format!("{a:?}");
        assert!(!dbg.contains("CHIAVE") && dbg.contains("Blob(20 byte)"), "{dbg}");
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<Action>(&json).unwrap(), a);
    }
}
