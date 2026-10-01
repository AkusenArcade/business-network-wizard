//! Il contatto con il sistema: file sotto una radice (quella vera o una finta per i
//! test) e comandi esterni. Nessuna shell: i comandi sono programma + argomenti.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use bnw_core::action::Outcome;

/// File di sistema visti da una radice. In produzione la radice è `/` e i file
/// diventano `root:root`; con `--root` si lavora in una cartella qualsiasi.
pub struct Fs {
    root: PathBuf,
    stamp: String,
    chown: bool,
}

impl Fs {
    pub fn new(root: impl Into<PathBuf>, chown: bool) -> Self {
        Fs {
            root: root.into(),
            stamp: chrono::Local::now().format("%Y%m%d-%H%M%S").to_string(),
            chown,
        }
    }

    /// Percorso reale di un percorso assoluto di sistema.
    pub fn path(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }

    pub fn exists(&self, abs: &str) -> bool {
        self.path(abs).symlink_metadata().is_ok()
    }

    pub fn read(&self, abs: &str) -> io::Result<Option<String>> {
        match fs::read_to_string(self.path(abs)) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Scrive il file solo se il contenuto o i permessi sono diversi. Prima di
    /// sovrascrivere fa un `.bak-<data>`; la scrittura è atomica (file temporaneo +
    /// rename), così un file di configurazione non resta mai a metà.
    pub fn write(&self, abs: &str, content: &str, mode: u32) -> io::Result<Outcome> {
        self.write_backup_in(abs, content, mode, None)
    }

    /// Come [`Fs::write`], ma il backup va in `backup_dir` (cartella `700`) invece che
    /// accanto al file: serve per le cartelle che caricano tutto quello che contengono,
    /// come quella dei keyfile di NetworkManager.
    pub fn write_backup_in(
        &self,
        abs: &str,
        content: &str,
        mode: u32,
        backup_dir: Option<&str>,
    ) -> io::Result<Outcome> {
        let path = self.path(abs);
        let old = fs::read(&path).ok();
        let old_mode = path.metadata().ok().map(|m| m.permissions().mode() & 0o7777);
        if old.as_deref() == Some(content.as_bytes()) {
            if old_mode == Some(mode) {
                return Ok(Outcome::Unchanged);
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            return Ok(Outcome::Changed);
        }
        let dir = path.parent().expect("percorso assoluto");
        self.mkdir(dir)?;
        if old.is_some() {
            let bak = match backup_dir {
                None => self.backup_path(&path),
                Some(d) => {
                    self.ensure_dir(d, 0o700)?;
                    self.backup_path(&self.path(d).join(path.file_name().expect("file")))
                }
            };
            fs::copy(&path, bak)?;
        }
        let name = path.file_name().unwrap().to_string_lossy();
        let tmp = dir.join(format!(".{name}.bnw-tmp"));
        let _ = fs::remove_file(&tmp);
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(content.as_bytes())?;
            f.sync_all()?;
        }
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        if self.chown {
            std::os::unix::fs::chown(&tmp, Some(0), Some(0))?;
        }
        fs::rename(&tmp, &path)?;
        Ok(Outcome::Changed)
    }

    /// Crea il symlink solo se al suo posto non c'è niente: se c'è già, lo sposta
    /// `proxy-detect`.
    pub fn symlink_if_missing(&self, link: &str, target: &str) -> io::Result<Outcome> {
        let path = self.path(link);
        if path.symlink_metadata().is_ok() {
            return Ok(Outcome::Unchanged);
        }
        self.mkdir(path.parent().unwrap())?;
        std::os::unix::fs::symlink(target, &path)?;
        Ok(Outcome::Changed)
    }

    /// Ultima modifica, in secondi Unix.
    pub fn mtime(&self, abs: &str) -> Option<i64> {
        use std::os::unix::fs::MetadataExt;
        self.path(abs).metadata().ok().map(|m| m.mtime())
    }

    /// I file (non le cartelle) di una cartella, come percorsi assoluti di sistema.
    pub fn list(&self, abs: &str) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(self.path(abs)) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_file()) {
                out.push(format!(
                    "{}/{}",
                    abs.trim_end_matches('/'),
                    e.file_name().to_string_lossy()
                ));
            }
        }
        out.sort();
        Ok(out)
    }

    /// Crea la cartella con quei permessi, se manca (se c'è non la tocca).
    pub fn ensure_dir(&self, abs: &str, mode: u32) -> io::Result<()> {
        let path = self.path(abs);
        if path.is_dir() {
            return Ok(());
        }
        self.mkdir(path.parent().expect("percorso assoluto"))?;
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        if self.chown {
            std::os::unix::fs::chown(&path, Some(0), Some(0))?;
        }
        Ok(())
    }

    /// Copia di sicurezza di `abs` in `dir` (cartella `700`), con la data nel nome.
    pub fn backup_copy(&self, abs: &str, dir: &str) -> io::Result<()> {
        let path = self.path(abs);
        if !path.is_file() {
            return Ok(());
        }
        self.ensure_dir(dir, 0o700)?;
        let dest = self.backup_path(&self.path(dir).join(path.file_name().expect("file")));
        fs::copy(&path, dest).map(|_| ())
    }

    /// Cancella una cartella dell'app con tutto il contenuto. Solo sotto `/etc/bnw/`:
    /// altrove non si cancellano alberi interi.
    pub fn remove_tree(&self, abs: &str) -> io::Result<bool> {
        if !abs.starts_with("/etc/bnw/") || abs.contains("..") {
            return Err(io::Error::other(format!("{abs}: fuori da /etc/bnw")));
        }
        match fs::remove_dir_all(self.path(abs)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Cancella un file, se c'è.
    pub fn remove(&self, abs: &str) -> io::Result<()> {
        match fs::remove_file(self.path(abs)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Mette da parte un file: lo rinomina in `.bak-<data>` e gli toglie l'esecuzione
    /// (il dispatcher di NetworkManager esegue anche i `.bak`).
    pub fn retire(&self, abs: &str) -> io::Result<Outcome> {
        let path = self.path(abs);
        if path.symlink_metadata().is_err() {
            return Ok(Outcome::Skipped);
        }
        let bak = self.backup_path(&path);
        fs::rename(&path, &bak)?;
        if !bak.is_symlink() {
            fs::set_permissions(&bak, fs::Permissions::from_mode(0o644))?;
        }
        Ok(Outcome::Changed)
    }

    /// Toglie l'esecuzione ai vecchi backup `<file>.bak-*` accanto a `abs`.
    pub fn disarm_backups(&self, abs: &str) -> io::Result<Vec<String>> {
        let path = self.path(abs);
        let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
            return Ok(Vec::new());
        };
        let prefix = format!("{}.bak-", name.to_string_lossy());
        let mut done = Vec::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return Ok(done);
        };
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            let meta = e.path().symlink_metadata()?;
            if n.starts_with(&prefix) && meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                fs::set_permissions(e.path(), fs::Permissions::from_mode(0o644))?;
                done.push(n);
            }
        }
        done.sort();
        Ok(done)
    }

    fn mkdir(&self, dir: &Path) -> io::Result<()> {
        if dir.is_dir() {
            return Ok(());
        }
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))
    }

    fn backup_path(&self, path: &Path) -> PathBuf {
        let mut p = path.as_os_str().to_owned();
        p.push(format!(".bak-{}", self.stamp));
        PathBuf::from(p)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CmdOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Esegue un comando esterno. `stdin` è l'unico canale per i segreti.
pub trait Runner {
    fn run(&mut self, program: &str, args: &[&str], stdin: Option<&str>) -> io::Result<CmdOutput>;

    /// `true` se i comandi vengono solo annotati e non eseguiti.
    fn dry(&self) -> bool {
        false
    }

    /// Attesa tra un tentativo e l'altro (nelle prove non aspetta).
    fn pause(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    /// C'è qualcuno in ascolto su `127.0.0.1:port`?
    fn listening(&self, port: u16) -> bool {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300)).is_ok()
    }

    /// Il proxy aziendale (`host:porta`) risponde? Di base no: solo l'esecuzione vera
    /// prova davvero.
    fn reachable(&self, _host_port: &str) -> bool {
        false
    }

    /// Avvia un cntlm temporaneo con la configurazione `conf` su una porta libera, fa una
    /// richiesta a `url` attraverso di lui e lo chiude. Restituisce il codice HTTP (0 =
    /// nessuna risposta). Di base non disponibile: solo l'esecuzione vera la fa.
    fn ntlm_trial(&mut self, _conf: &Path, _url: &str) -> io::Result<u16> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "prova NTLM non disponibile",
        ))
    }
}

/// Esecuzione vera.
pub struct RealRunner;

impl Runner for RealRunner {
    fn run(&mut self, program: &str, args: &[&str], stdin: Option<&str>) -> io::Result<CmdOutput> {
        exec(program, args, stdin)
    }

    fn reachable(&self, host_port: &str) -> bool {
        use std::net::ToSocketAddrs;
        let Ok(addrs) = host_port.to_socket_addrs() else {
            return false;
        };
        addrs
            .into_iter()
            .any(|a| std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_secs(2)).is_ok())
    }

    fn ntlm_trial(&mut self, conf: &Path, url: &str) -> io::Result<u16> {
        let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        let listen = format!("127.0.0.1:{port}");
        // -f: in primo piano, così resta figlio nostro e lo si chiude con certezza
        let mut child = Command::new(crate::CNTLM)
            .arg("-f")
            .arg("-c")
            .arg(conf)
            .args(["-l", &listen])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut ready = false;
        for _ in 0..50 {
            if self.listening(port) {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let result = if ready {
            let proxy = format!("http://{listen}");
            exec(
                "/usr/bin/curl",
                &[
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "--max-time",
                    "20",
                    "--proxy",
                    &proxy,
                    "--url",
                    url,
                ],
                None,
            )
            .map(|o| o.stdout.trim().parse().unwrap_or(0))
        } else {
            Ok(0)
        };
        let _ = child.kill();
        let _ = child.wait();
        result
    }
}

fn exec(program: &str, args: &[&str], stdin: Option<&str>) -> io::Result<CmdOutput> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("LANG", "C.UTF-8")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    Ok(CmdOutput {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Per `--root`: annota i comandi senza eseguirli, tranne quelli che non toccano il
/// sistema (il calcolo degli hash di cntlm, che non usa la rete né file).
#[derive(Default)]
pub struct DryRunner {
    pub log: Vec<String>,
}

impl Runner for DryRunner {
    fn run(&mut self, program: &str, args: &[&str], stdin: Option<&str>) -> io::Result<CmdOutput> {
        self.log.push(
            std::iter::once(program)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" "),
        );
        if program == crate::CNTLM && args.first() == Some(&"-H") {
            return exec(program, args, stdin);
        }
        Ok(CmdOutput {
            success: true,
            ..Default::default()
        })
    }

    fn dry(&self) -> bool {
        true
    }

    fn pause(&self, _ms: u64) {}

    fn listening(&self, _port: u16) -> bool {
        true
    }
}
