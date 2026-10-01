//! `bnw-helper`: la parte che gira come root (via pkexec). Esegue una sola
//! [`Action`] per invocazione, con parametri rivalidati qui anche se la GUI li ha già
//! controllati.

pub mod adopt;
pub mod nm;
pub mod password;
pub mod printers;
pub mod profile;
pub mod proxy;
pub mod shares;
pub mod sys;
pub mod vpn;
pub mod wifi;

use bnw_core::action::{Action, Outcome, Report};

use sys::{Fs, Runner};

pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
pub const CNTLM: &str = "/usr/bin/cntlm";
pub const PROXY_MODE: &str = "/usr/bin/proxy-mode";
pub const DETECT_SERVICE: &str = "bnw-proxy-detect.service";
pub const PROFILE_PATH: &str = bnw_core::paths::PROFILE;
/// Backup dei keyfile di NetworkManager: fuori da `system-connections`, che carica
/// quello che trova.
pub const NM_BACKUP_DIR: &str = "/etc/bnw/backup/NetworkManager";

pub struct Ctx<'a> {
    pub fs: Fs,
    pub run: &'a mut dyn Runner,
    pub nm: &'a mut dyn nm::Nm,
    pub report: Report,
}

impl Ctx<'_> {
    /// Annota l'esito di una scrittura di file.
    fn file(&mut self, what: &str, result: std::io::Result<Outcome>) -> Outcome {
        match result {
            Ok(o) => {
                self.report.push(what, o, None);
                o
            }
            Err(e) => {
                self.report.push(what, Outcome::Failed, Some(e.to_string()));
                Outcome::Failed
            }
        }
    }

    /// Esegue un comando e ne annota l'esito. `stdin` non finisce mai nel rapporto.
    fn cmd(
        &mut self,
        what: &str,
        program: &str,
        args: &[&str],
        stdin: Option<&str>,
    ) -> Option<sys::CmdOutput> {
        let result = self.run.run(program, args, stdin);
        match result {
            Ok(out) if out.success => {
                let detail = self.run.dry().then(|| "non eseguito (--root)".to_string());
                self.report.push(what, Outcome::Changed, detail);
                Some(out)
            }
            Ok(out) => {
                let msg = out.stderr.trim();
                let msg = if msg.is_empty() { "uscito con errore" } else { msg };
                self.report.push(what, Outcome::Failed, Some(msg.to_string()));
                None
            }
            Err(e) => {
                self.report
                    .push(what, Outcome::Failed, Some(format!("{program}: {e}")));
                None
            }
        }
    }

    fn fail(&mut self, what: &str, detail: impl Into<String>) {
        self.report.push(what, Outcome::Failed, Some(detail.into()));
    }
}

/// Esegue un'azione senza NetworkManager (le azioni che lo usano lo dicono).
pub fn run(action: &Action, fs: Fs, runner: &mut dyn Runner) -> Report {
    run_with(action, fs, runner, &mut nm::NoNm)
}

pub fn run_with(action: &Action, fs: Fs, runner: &mut dyn Runner, nm: &mut dyn nm::Nm) -> Report {
    let mut ctx = Ctx {
        fs,
        run: runner,
        nm,
        report: Report::default(),
    };
    match action {
        Action::ApplyProxy { profile } => proxy::apply(&mut ctx, profile, proxy::CntlmConf::Update),
        Action::WriteCntlm {
            domain_user,
            password,
        } => proxy::write_cntlm(&mut ctx, domain_user, password),
        Action::SetMode { mode } => proxy::set_mode(&mut ctx, *mode),
        Action::Adopt { profile } => adopt::adopt(&mut ctx, profile),
        Action::StopCntlm => password::stop_cntlm(&mut ctx),
        Action::StartCntlm => password::start_cntlm(&mut ctx),
        Action::SetPassword {
            password,
            only,
            domain_user,
        } => password::set(&mut ctx, password, only, domain_user.as_deref()),
        Action::PasswordStatus => password::status(&mut ctx),
        Action::ApplyVpn {
            profile,
            ovpn,
            reimport,
            domain_user,
            password,
        } => vpn::apply(
            &mut ctx,
            profile,
            ovpn.as_ref().map(|b| b.0.as_slice()),
            *reimport,
            domain_user.as_deref(),
            password.as_ref(),
        ),
        Action::ApplyShares { profile, owner_uid } => shares::apply(&mut ctx, profile, *owner_uid),
        Action::UnmountShares => shares::unmount(&mut ctx),
        Action::ApplyPrinters { profile } => printers::apply(&mut ctx, profile),
        Action::ApplyProfile {
            profile,
            ovpn,
            ca,
            domain_user,
            owner_uid,
        } => profile::apply(
            &mut ctx,
            profile,
            ovpn.as_ref().map(|b| b.0.as_slice()),
            ca.as_ref().map(|b| b.0.as_slice()),
            domain_user.as_deref(),
            *owner_uid,
        ),
        Action::ApplyWifi {
            profile,
            ca,
            domain_user,
            password,
        } => wifi::apply(
            &mut ctx,
            profile,
            ca.as_ref().map(|b| b.0.as_slice()),
            domain_user.as_deref(),
            password.as_ref(),
        ),
    }
    ctx.report
}
