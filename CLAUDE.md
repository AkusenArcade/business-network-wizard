# Business Network Wizard

Applicazione GTK4 in Rust che configura da zero, e poi mantiene, l'accesso alla rete
aziendale su una macchina Linux (Arch/CachyOS, NetworkManager): proxy NTLM, VPN OpenVPN,
WiFi 802.1X, dischi di rete CIFS, stampanti CUPS, password di dominio. Tutto da GUI.

**Il piano è in `PIANO.md`**: perimetro, formato del profilo `.bnw`, architettura,
schermate, procedura di cambio password, fasi e decisioni. Le note sull'ambiente di
sviluppo dell'autore, se ci sono, stanno in `CLAUDE.local.md` (non versionato).

## Architettura

- `bnw-core`: profilo (serde + toml), validazione, generatori puri, protocollo delle azioni
  (`action.rs`), profilo cifrato `.bnw` (age + tar). Niente GTK, niente I/O di sistema.
- `bnw-helper`: la parte root, lanciata con pkexec. Un'azione JSON su stdin, un rapporto
  JSON su stdout. NetworkManager via D-Bus (zbus), systemd e CUPS con comandi senza shell.
- `bnw-client`: la parte utente condivisa da GUI e CLI (stato, invocazione dell'helper,
  prove di rete, segnalibri, bundle offline).
- `bnw-cli`: libreria con i comandi `bnw …`.
- `bnw-gui`: il binario `bnw` (gtk4-rs + libadwaita-rs): senza argomenti apre l'app.
- `data/`: script `proxy-detect`, `proxy-mode`, dispatcher, unit, drop-in, policy polkit.

## Regole

- L'app è **generica**: nessun dato di un'azienda nel codice o nei test. I test usano
  l'azienda di fantasia di `tests/fixtures/esempio/`.
- **Mai** nel repository: hash NTLM, password, keyfile di NetworkManager, chiavi private,
  e nemmeno dati interni reali di un'azienda (indirizzi, nomi di server, utenze).
- **Mai stampare** il contenuto di file con segreti (`.ovpn`, `cntlm.conf`, credenziali,
  keyfile), nemmeno filtrato: solo comandi che per costruzione non mostrano valori.
- Niente di ciò che si sviluppa tocca `/etc` della macchina: l'helper ha `--root` per le
  prove. Le prove di sistema si fanno con l'utente presente, o in una VM.
- Attenzione al **blocco dell'account di dominio**: cntlm con hash sbagliati ritenta a ogni
  richiesta. Qualunque prova che tocchi cntlm o le credenziali va concordata prima.
- I segreti passano solo da stdin dell'helper e da D-Bus, mai sulla riga di comando.
- Commenti e documentazione in italiano, identificatori in inglese.

## Sviluppo

- `cargo test`; `cargo clippy --all-targets` pulito.
- Senza toccare il sistema: `BNW_ROOT=<cartella> BNW_HELPER=target/debug/bnw-helper
  target/debug/bnw` (helper con `--root`, senza pkexec).
- Schermate: `gtk4-broadwayd :7`, poi `GDK_BACKEND=broadway BROADWAY_DISPLAY=:7
  BNW_SCREENSHOT=<prefisso> [BNW_SCREENSHOT_ACTION=<azione>]`.
- NetworkManager **non restituisce le proprietà al valore di default** (es.
  `autoconnect=true`): leggere sempre con il default giusto.
- Prova con la NetworkManager vera (come root): `tests/nm_real.rs`, ignorato di default.
- Pacchetto dal repository locale: `packaging/local/PKGBUILD`; per AUR:
  `packaging/aur/PKGBUILD` (sorgenti dal tag `v<versione>`).
