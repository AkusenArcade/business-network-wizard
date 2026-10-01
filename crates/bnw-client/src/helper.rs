//! Come si lancia `bnw-helper`: `pkexec <helper>`, azione JSON su stdin, rapporto
//! JSON su stdout.

use std::io::Write;
use std::process::{Command, Stdio};

use bnw_core::action::{Action, Report};

use crate::Env;

/// La riga di comando dell'helper. La GUI la usa con `gio::Subprocess`.
pub fn argv(env: &Env) -> Vec<String> {
    let helper = env.helper.to_string_lossy().into_owned();
    if env.dev_root {
        vec![helper, "--root".into(), env.root.to_string_lossy().into_owned()]
    } else {
        vec!["pkexec".into(), helper]
    }
}

pub fn request(action: &Action) -> String {
    serde_json::to_string(action).expect("un'azione si serializza sempre")
}

#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    #[error("impossibile avviare l'helper: {0}")]
    Spawn(std::io::Error),
    /// pkexec esce con 126 se l'utente annulla, 127 se non è autorizzato.
    #[error("autorizzazione negata o annullata")]
    NotAuthorized,
    #[error("risposta dell'helper illeggibile (uscita {code}): {stderr}")]
    BadReply { code: i32, stderr: String },
}

/// Interpreta l'uscita del processo helper.
pub fn parse_reply(code: i32, stdout: &str, stderr: &str) -> Result<Report, HelperError> {
    match serde_json::from_str::<Report>(stdout) {
        Ok(r) => Ok(r),
        Err(_) if code == 126 || code == 127 => Err(HelperError::NotAuthorized),
        Err(_) => Err(HelperError::BadReply {
            code,
            stderr: stderr.trim().to_string(),
        }),
    }
}

/// Esegue un'azione e aspetta il rapporto (per `bnw`).
pub fn run(env: &Env, action: &Action) -> Result<Report, HelperError> {
    let argv = argv(env);
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(HelperError::Spawn)?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request(action).as_bytes())
        .map_err(HelperError::Spawn)?;
    let out = child.wait_with_output().map_err(HelperError::Spawn)?;
    parse_reply(
        out.status.code().unwrap_or(-1),
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
    )
}
