# Business Network Wizard — piano

Applicazione GTK4 che configura da zero, e poi mantiene, l'accesso alla rete aziendale su
una macchina Linux: proxy NTLM, VPN, WiFi 802.1X, dischi di rete, password di dominio.
Tutto da GUI, senza terminale. Scritta in **Rust** (gtk4-rs + libadwaita).

Nasce per sostituire un kit fatto a mano (un `install.sh` più alcuni script di
manutenzione, tra cui `cambia-password-dominio.sh`) usato su una macchina di riferimento.
Il comportamento finale deve essere lo stesso: l'app ne porta la logica, passo per passo.

La shell desktop resta generica: dell'azienda non sa nulla (vedi §8).

---

## 1. Obiettivo e perimetro

**Dentro**

| Area | Cosa fa l'app |
|---|---|
| Proxy | catena `app → tinyproxy :8118 → cntlm :3128 → proxy aziendale`, commutazione automatica (VPN attiva **o** proxy aziendale raggiungibile), forzatura AUTO/ON/OFF, eccezioni (domini diretti), `/etc/environment`, policy proxy di Firefox e Zen |
| VPN | import `.ovpn` con le correzioni che oggi fa `install.sh` (`password-flags=0`, `remote-cert-tls`, niente `challenge-response-flags`), certificati nella home giusta, connetti e disconnetti |
| WiFi 802.1X | profilo PEAP/MSCHAPv2 con CA, `domain-suffix-match`, identità, `password-flags=0`, scelta dell'autoconnect |
| Dischi di rete | share CIFS in automount on-demand (`mnt-*.mount` e `.automount`, 10 minuti di inattività), file credenziali, segnalibri GTK, aggiungi, rimuovi, stato, smonta |
| Password di dominio | **un campo, quattro posti**: hash NTLMv2 di cntlm, secret VPN, secret WiFi, credenziali CIFS, nella stessa procedura sicura di `cambia-password-dominio.sh` |
| Diagnosi | stato di tutto, "perché direct/upstream", log (`proxy-detect`, `cntlm`, `wpa_supplicant`), test "diretto vs proxy" su un URL |

| Stampanti | code CUPS **driverless** (`ipp://…/ipp`, `-m everywhere`) come la `STAMPA_P1`: aggiungi e rimuovi, lato di stampa predefinito (di norma solo fronte), e l'elenco delle code pubblicate in AD come aiuto facoltativo |

Le funzioni fish (`vpn-up`, `vpn-down`, `vpn-pass`, `pass-dominio`) **vengono abbandonate**.
Al loro posto ci sono l'app e un piccolo comando `bnw` (`bnw status`, `bnw proxy auto|on|off`,
`bnw vpn up|down`), che serve anche come aggancio per un eventuale indicatore nella barra.

**Fuori, per ora**
- Cambiare la password **sul dominio**. L'app aggiorna le copie locali quando la password
  è scaduta ed è stata cambiata altrove (Windows, portale).
- Kerberos per CIFS (`sec=krb5`). Resta un'alternativa futura.

---

## 2. L'idea chiave: il "profilo aziendale"

Oggi i dati di Esempio sono sparsi tra gli script: `FALLBACK_PROXY`, `VPN_NAME`, le righe
`upstream none`, i nomi delle share. L'app li separa dal codice.

Un **profilo aziendale** è un archivio `.bnw` **cifrato con passphrase**, che contiene:

```
esempio.bnw/
  profile.toml          # tutto ciò che non è segreto (esempio sotto)
  vpn/Esempio.ovpn       # contiene la chiave privata del certificato VPN
  wifi/root-ca.pem      # CA del RADIUS
```

```toml
[company]
name   = "Esempio"
domain = "ESEMPIO"             # dominio NTLM per cntlm e CIFS
user_hint = "nome.cognome"

[proxy]
upstream  = ["10.20.30.40:3128"]
local_port = 8118
cntlm_port = 3128
direct = ["localhost", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
          "192.168.0.0/16", ".corp.esempio", ".esempioprod", "esempio.it", ".esempio.it"]
browsers = ["firefox", "zen"]
pac = "http://proxy.corp.esempio/proxy.pac"   # solo documentazione

[vpn]
name = "Esempio"
file = "vpn/Esempio.ovpn"
full_tunnel = true

[wifi]
name   = "Esempio-802.1X"
ssid   = "Esempio"
eap    = "peap"
phase2 = "mschapv2"
ca     = "wifi/root-ca.pem"
ca_sha1 = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
domain_suffix_match = "dc1.corp.esempio"
autoconnect = false

[[share]]
server = "fs1.corp.esempio"
name = "ESEMPIO"
mount = "/mnt/esempio"

[[share]]
server = "fs2.corp.esempio"
name = "PROGETTI"
mount = "/mnt/progetti"
# … AreaClienti, SCAMBIO
```

Il profilo completo della macchina di riferimento, quello verificato dai test, è
`tests/fixtures/esempio/profile.toml`. Le eccezioni del proxy possono avere una nota
(`{ host = "esempio.it", note = "…" }`), che finisce come commento in `upstream.conf`.
L'utenza di dominio e l'uid/gid locale non stanno nel profilo: sono della macchina.

Il profilo **non contiene password di dominio**: le scrive l'app sulla macchina di
destinazione. Contiene però la chiave privata della VPN, ed è per questo che è cifrato.

**Formato**: un tar con dentro `profile.toml` e i file, cifrato con
[age](https://age-encryption.org) in modalità passphrase (scrypt + ChaCha20-Poly1305),
tramite il crate `age`. Si usa un formato standard, non uno inventato: in emergenza si
decifra anche a mano con `age -d esempio.bnw | tar x`. La passphrase si chiede all'import e
all'export e non viene salvata.

**Stato (v0.3.0)**: esportazione e importazione esistono già (`bnw profile export|show|import`,
menu ☰ dell'app). L'esportazione trova da sola l'`.ovpn` (Documenti/Scaricati) e la CA che il
WiFi usa davvero (`802-1x.ca-cert`); calcola il fingerprint della CA se manca. All'apertura
l'archivio è controllato: solo file regolari citati dal profilo, percorsi relativi semplici,
dimensioni limitate, fingerprint della CA, avviso se la CA del WiFi è quella della VPN o se
l'`.ovpn` non ha la chiave privata. Per ora l'importazione applica il proxy; VPN, WiFi, dischi
e stampanti arriveranno con le fasi 5 e 6.

**Editor (v0.8.0)**: menu ☰ → «Modifica profilo aziendale…». Si parte dal profilo applicato,
da un `.bnw` o da zero; si modifica tutto (azienda, proxy ed eccezioni, VPN con il suo
`.ovpn`, WiFi con la CA, dischi, stampanti) con la validazione in tempo reale, e si salva
come `.bnw` cifrato oppure si applica a questa macchina («applica profilo», che toglie
quello che il profilo nuovo non ha più). È lo strumento per un cambio di dominio.

Il `[[printer]]` del profilo:

```toml
[[printer]]
name = "STAMPA_P1"
uri = "ipp://stampante-p1.corp.esempio/ipp"
description = "Multifunzione - Piano 1"
location = "Esempio Piano 1"
duplex = false   # predefinito: solo fronte
```

Così il flusso su un PC nuovo diventa:
1. installi l'app;
2. apri il wizard e importi `esempio.bnw` da una chiavetta;
3. scrivi utente e password di dominio;
4. premi Applica.

Il wizard permette anche di compilare tutto a mano (profilo vuoto) e di **esportare** il
profilo dalla macchina già configurata. Il primo profilo nasce dalla macchina di riferimento.

---

## 3. Architettura

```
┌───────────────────────────── utente ──────────────────────────────┐
│  bnw  (GTK4 + libadwaita, Rust: gtk4-rs + libadwaita-rs)            │
│   ├─ Wizard (prima configurazione)                                  │
│   └─ Gestione: Stato · Proxy · VPN · WiFi · Dischi · Stampanti ·    │
│                Password · Log                                       │
│         │ legge senza privilegi: NetworkManager e systemd via D-Bus │
│         │ (zbus), readlink, /run/…, journalctl, lpstat              │
│         ▼ azioni con privilegi                                      │
└─────────┼──────────────────────────────────────────────────────────┘
          │ pkexec /usr/lib/bnw/bnw-helper <azione>   (JSON su stdin)
┌─────────▼──────────────────────── root ───────────────────────────┐
│  bnw-helper: poche azioni, argomenti validati, nessuna shell       │
│   apply-proxy · set-mode · write-cntlm · apply-shares ·            │
│   set-password · unmount-shares · restart · env · browser-policy  │
│   printer-add · printer-remove                                     │
└────────────────────────────────────────────────────────────────────┘
   file installati dal pacchetto (non generati):
   /usr/lib/bnw/proxy-detect  /usr/bin/proxy-mode
   /usr/lib/NetworkManager/dispatcher.d/90-bnw-proxy
   /usr/lib/systemd/system/bnw-proxy-detect.service  + drop-in per tinyproxy
   /usr/share/polkit-1/actions/it.akusen.bnw.policy
```

Scelte:

- **Rust, un workspace cargo con quattro crate**: `bnw-core` (profilo, generatori,
  cifratura; nessuna dipendenza da GTK), `bnw-gui` (gtk4-rs + libadwaita-rs),
  `bnw-helper` (root) e `bnw-cli`. La GUI e l'helper condividono i tipi del core: le
  azioni dell'helper sono un `enum` serializzato, quindi GUI e helper non possono
  divergere.
- **NetworkManager via D-Bus con `zbus`**. libnm non ha un binding Rust maturo. I profili
  (OpenVPN, 802.1X) si costruiscono come dizionari di impostazioni (`AddConnection`,
  `Update`) e i segreti passano solo via D-Bus, mai su una riga di comando. È la parte che
  richiede più lavoro: ha una fase a sé (§11). L'import `.ovpn` passa comunque da
  `nmcli connection import`, l'unico che sa tradurre il file, seguito dalle correzioni via
  D-Bus.
- **I processi in background non bloccano la GUI**: le letture D-Bus girano in async
  (`zbus` sul main loop di glib); i comandi esterni (`systemctl`, `lpadmin`, pkexec)
  girano con `gio::Subprocess`.
- **Helper con pkexec e un'azione polkit** (`auth_admin_keep`), un binario Rust: una password di
  amministratore per sessione, chiesta dall'agente polkit già avviato da niri. I segreti
  arrivano all'helper **su stdin**, mai negli argomenti (`/proc/*/cmdline` è leggibile da
  tutti).
  Alternativa più pulita ma più pesante: un servizio D-Bus di sistema con polkit
  per metodo. Si può passare lì in un secondo momento senza cambiare la GUI, perché
  l'interfaccia dell'helper è già a "azioni".
- **Idempotenza e backup come oggi:**
  - ogni file toccato riceve un `.bak-<data>`;
  - si riscrivono solo le righe con i segreti;
  - rilanciare Applica non rompe niente.
- **La logica di rete resta negli script shell** (`proxy-detect`, `proxy-mode`,
  dispatcher). Funzionano e sono testati. Ne esce una versione generica: legge il nome
  della VPN e i proxy di riserva da `/etc/bnw/proxy-detect.conf` (righe `CHIAVE=valore`
  generate dal profilo e lette senza `source`: leggere TOML da bash sarebbe fragile)
  invece di averli scritti nel codice. L'app li installa e li comanda, non li
  reimplementa.
- **Protocollo dell'helper** (`bnw_core::action`): un'azione JSON su stdin
  (`{"action":"apply-proxy",…}`), un rapporto JSON su stdout con un esito per passo
  (`changed` / `unchanged` / `skipped` / `failed`). Con `--root DIR` l'helper scrive in
  una cartella qualsiasi e i comandi di sistema li annota senza eseguirli (tranne
  `cntlm -H`, che è locale).
- **Stato della macchina**: `/etc/bnw/profile.toml`, la copia del profilo applicato, senza
  segreti. È la "fonte di verità" da cui l'helper rigenera `upstream.conf`, le unit CIFS
  eccetera, e da cui l'app esporta.

---

## 4. Le schermate

### 4.1 Wizard (prima configurazione)

1. **Benvenuto e controlli**
   - NetworkManager attivo;
   - pacchetti presenti (`tinyproxy`, `cntlm`, `cifs-utils`, `openvpn`,
     `networkmanager-openvpn`);
   - agente polkit in esecuzione.

   Se manca qualcosa, spiega cosa e perché (vedi §6, l'uovo e la gallina).
2. **Profilo aziendale**: importa un `.bnw` (con la passphrase), oppure "compila a mano".
3. **Credenziali di dominio**: utente, password e conferma. La password resta solo in
   memoria fino al passo 8.
4. **Proxy**: indirizzi del proxy aziendale, eccezioni (lista modificabile con
   aggiungi e rimuovi, e il promemoria su `.dominio` contro `dominio`), browser da
   configurare.
5. **VPN**: file `.ovpn` (già nel profilo o da scegliere), nome, anteprima di cosa verrà
   corretto.
6. **WiFi aziendale**:
   - SSID, EAP e fase 2;
   - CA, **con controllo del fingerprint** e avviso se è la CA OpenVPN: è la trappola
     classica;
   - `domain-suffix-match` e autoconnect.
7. **Dischi di rete**: tabella di server, share e cartella; aggiungi e rimuovi.
7b. **Stampanti**: tabella di nome, URI e posizione; fronte-retro sì/no (predefinito: no).
8. **Riepilogo e applica**. Una pagina che mostra ogni passo con il suo esito (✓ / ✗ /
   saltato), come i nove passi di `install.sh`. Si può riprendere solo ciò che è fallito.
9. **Verifica**:
   - rileva la rete;
   - test NTLM verso l'esterno;
   - se trova un **407**, ferma subito cntlm e lo dice, per evitare il blocco
     dell'account.

### 4.2 Gestione (l'app aperta dopo il wizard)

- **Stato**:
  - modalità `direct` o `upstream` e **perché**;
  - forzatura attiva;
  - tinyproxy e cntlm;
  - VPN e WiFi aziendale;
  - share montate.

  Dopo ogni azione si aggiorna leggendo `nmcli monitor` e il journal, senza controlli
  periodici.
- **Proxy**: AUTO/ON/OFF (`proxy-mode`), editor delle eccezioni con il pulsante
  **"prova un URL"** (diretto contro proxy, per diagnosticare i 504), porta locale.
- **VPN / WiFi**: connetti e disconnetti, reimporta `.ovpn`, sostituisci la CA,
  autoconnect.
- **Dischi**: aggiungi e rimuovi share, stato del mount, "smonta ora", "apri cartella".
- **Stampanti**: aggiungi e rimuovi, stato della coda (`lpstat`), pagina di prova.
  Facoltativo: "cerca in AD" (`kinit` + `net ads search`), se `krb5`/`samba` ci sono.
- **Password di dominio**:
  - "Aggiorna password", che segue la procedura del §5;
  - lo **stato dei quattro posti** con le date, come `pass-dominio --stato`: se le date
    non sono vicine, un aggiornamento precedente è rimasto a metà e l'app lo segnala.
- **Diagnosi**: log filtrati, "esporta diagnosi" in un file di testo senza segreti,
  pulsante `reset-failed` per cntlm.
- **Esporta profilo**: crea il `.bnw` cifrato per un'altra macchina (chiede la passphrase
  due volte).

---

## 5. Aggiornare la password di dominio (la procedura)

È la parte più delicata: sbagliarla significa **account di dominio bloccato**. L'ordine
che segue è quello di `cambia-password-dominio.sh`, già collaudato, con tre aggiunte
(il WiFi, la prova preventiva, l'annullamento sicuro):

1. **Ferma cntlm prima di chiedere la password**, così non ritenta con gli hash vecchi
   mentre l'utente scrive.
2. Chiede la password nuova due volte, in un campo solo.
3. In un'unica chiamata all'helper, con la password su stdin:
   1. calcola gli hash NTLMv2 (`cntlm -H`, password su stdin);
   2. **la prova prima di scriverla**, se il proxy aziendale è raggiungibile: un cntlm
      temporaneo con gli hash nuovi su una porta libera, una richiesta verso l'esterno,
      poi lo chiude. Con un **407 non scrive niente**: la password sbagliata non finisce
      nei quattro posti e il dominio vede un solo tentativo fallito; l'app la richiede.
      Senza risposta, o fuori dalla rete aziendale, si va avanti e la prova si fa dopo;
   3. riscrive **solo** le righe `PassNTLMv2`/`PassNT`/`PassLM` di `/etc/cntlm.conf`;
   4. salva il secret VPN e il secret WiFi nei keyfile di NetworkManager
      (`password-flags=0`, corretto se serve) e fa `nmcli connection reload`;
   5. riscrive `/etc/samba/credentials/<azienda>` (600 root, cartella 700);
   6. smonta le share CIFS montate, che tengono in RAM la password vecchia;
   7. fa un `.bak-<data>` di ogni file.
4. Se la rete attuale vuole il proxy, riavvia cntlm e tinyproxy, aspetta che ascoltino
   e **prova l'NTLM verso l'esterno**:
   - se è OK, conferma;
   - se ottiene un **407**, ferma cntlm e mostra un messaggio chiaro.
5. Ricorda che la VPN già connessa resta sulla sessione vecchia e offre "Riconnetti VPN".

Se l'utente **annulla** dopo il punto 1, cntlm **resta fermo**: se la password sul
dominio è già cambiata, riaccenderlo con gli hash vecchi produrrebbe 407 a ripetizione.
Si riaccende solo con una scelta esplicita ("la password non è cambiata").

Se uno dei quattro posti fallisce, l'app dice **quale**, mentre gli altri restano
aggiornati. Lo stato (`password-status`) **confronta i quattro segreti** dentro
l'helper (per cntlm calcolando l'hash della password degli altri posti) e dice se sono
allineati; le date dei file sono solo informative, perché cambiano anche per modifiche
che non toccano la password.

Solo in un secondo momento: una notifica quando la VPN o il WiFi falliscono
l'autenticazione, o quando cntlm vede un 407 ("forse la password è scaduta: aggiornala"),
lanciata dall'hook del dispatcher.

---

## 6. Installazione e il problema dell'uovo e della gallina

L'app è un pacchetto AUR (`business-network-wizard`) con dipendenze `tinyproxy`,
`cifs-utils`, `openvpn`, `networkmanager-openvpn`, `cups`, `gtk4`, `libadwaita` e
**`cntlm` (solo AUR)**; in compilazione `rust`/`cargo`.

Per installarla serve internet **non aziendale**: sulla rete dell'ufficio pacman
vorrebbe il proxy, che ancora non esiste. È lo stesso vincolo che ha oggi il kit. Quindi:

- **via normale**: hotspot del telefono, installa, poi passa al WiFi aziendale;
- **via offline**: un bundle con i pacchetti (`bnw-offline-<data>.tar`), come l'attuale
  `files/pkg/`. L'app, dalla macchina già configurata, può generarlo ("Esporta per
  installazione offline"). Vale l'avviso sui pacchetti CachyOS `x86_64_v3`.

La GUI non può aggirare questo problema, ma può **spiegarlo**: il controllo al passo 1
del wizard rileva che manca `cntlm`, con quale rete si è connessi, e indica la strada
giusta.

---

## 7. Sicurezza

- Il `.bnw` contiene la chiave privata VPN ed è **sempre cifrato** (age, passphrase). Il
  contenuto decifrato vive solo in memoria o in una cartella `0700` rimossa a fine import.
- Segreti sulla macchina: esattamente come oggi.
  - hash NTLMv2 in `/etc/cntlm.conf`;
  - secret in NetworkManager;
  - password in chiaro solo in `/etc/samba/credentials/*`, perché CIFS non accetta hash.

  Tutti `600 root`.
- Nessun segreto in log, argomenti, file di diagnosi o `profile.toml`.
- L'helper accetta solo le proprie azioni, con parametri validati (nomi host, percorsi
  sotto `/mnt`, porte). Nessuna stringa passa a una shell.
- La VPN resta **full-tunnel** (`never-default=no`), come oggi: è una scelta deliberata.

---

## 8. E la shell desktop?

Niente di obbligatorio:
- **VPN**: la shell desktop elenca e attiva già il profilo creato dall'app.
- **WiFi 802.1X**: da **verificare** che la shell desktop attivi un profilo enterprise già salvato
  senza chiedere nulla. Passa da NetworkManager e la password è salvata, quindi dovrebbe
  funzionare. Se non funziona, è una correzione generica nella shell desktop.
- **Proxy**: non creare profili proxy della shell desktop su queste macchine. Il riepilogo del
  wizard lo ricorda. In seguito, se vuoi un indicatore nella barra, basta un hook
  generico ("comando di stato") nella shell desktop e `bnw status --json`, che esiste già dalla fase 3.
- Un lanciatore `.desktop` rende l'app raggiungibile dal launcher della shell desktop.

---

## 9. Adottare una configurazione fatta a mano

Una macchina configurata con il kit ha la versione "a mano": `/usr/local/bin/proxy-*`, `/etc/NetworkManager/dispatcher.d/90-proxy-vpn`,
`/etc/systemd/system/proxy-detect.service`, le funzioni fish in `~/.config/fish/`. Installando l'app ci sarebbero
due hook e due servizi. Per questo l'app ha un'azione **"Adotta configurazione esistente"**:
- legge i file attuali;
- crea `/etc/bnw/profile.toml`;
- mette i file manuali in `.bak`, **funzioni fish comprese** (si abbandonano);
- lascia al loro posto quelli del pacchetto.

Il risultato è identico e verificabile con la schermata Stato. Farla sulla macchina di
riferimento è anche il test migliore.

---

## 10. Struttura del repository

```
Business Network Wizard/
  Cargo.toml              # workspace
  crates/
    bnw-core/             # profilo (serde + toml), validazione, cifratura age,
      src/render/         #   generatori puri: upstream.conf, direct.conf, cntlm.conf,
                          #   unit CIFS, policies.json, environment
      src/action.rs       # l'enum delle azioni dell'helper, condiviso
    bnw-gui/              # gtk4-rs + libadwaita-rs: wizard e pagine di gestione
    bnw-helper/           # root: esegue le azioni, `--root` per i test
    bnw-client/           # lato utente condiviso da GUI e CLI: stato, pkexec, prove
    bnw-cli/              # `bnw status|proxy|vpn …` (libreria: il binario `bnw` è in bnw-gui)
  data/
    proxy-detect  proxy-mode  90-bnw-proxy  bnw-proxy-detect.service
    tinyproxy-bnw.conf  cntlm-bnw.conf   # drop-in, in /usr/lib/systemd/system/*.service.d/bnw.conf
    it.akusen.bnw.policy
    it.akusen.BusinessNetworkWizard.desktop
  tests/fixtures/esempio/ # i file reali di questa macchina, senza segreti
  packaging/aur/PKGBUILD
  PIANO.md
```

I generatori sono **funzioni pure** (profilo → testo), testate con `cargo test` contro i file
reali di questa macchina: il primo test è "il profilo esportato dalla macchina di riferimento rigenera
esattamente l'`upstream.conf` e le unit di oggi". L'helper prende una `--root` alternativa
per i test, quindi niente tocca `/etc` durante lo sviluppo.

---

## 11. Fasi

| # | Consegna | Si considera fatto quando |
|---|---|---|
| 1 | Modello del profilo + generatori + test | il profilo della macchina di riferimento rigenera i file di oggi, byte per byte o con differenze motivate |
| 2 | Helper + polkit + script generici (`proxy-detect`, `proxy-mode`, dispatcher) | l'helper applica il proxy su una root finta e poi su una VM |
| 3 | GUI Gestione: Stato + Proxy | AUTO/ON/OFF ed eccezioni funzionano sulla macchina di riferimento dopo l'"Adotta" |
| 4 | Password di dominio | aggiorna i quattro posti, rileva il 407, mostra le date |
| 5 | VPN + WiFi (NetworkManager via `zbus`) | import `.ovpn` con le correzioni, profilo 802.1X con controllo CA, segreti via D-Bus |
| 6 | Dischi di rete + stampanti | aggiungi e rimuovi share (automount, segnalibri) e code CUPS driverless |
| 7 | Wizard completo, «applica profilo» con sostituzione del precedente (v0.6.0) | una VM Arch/CachyOS vuota → configurata solo da GUI |
| 8 | PKGBUILD + bundle offline (v0.7.0; pubblicazione su AUR da fare) | installazione da AUR e offline |

La prova finale è una **VM pulita**: installa il pacchetto, importa `esempio.bnw`, scrivi
la password, Applica. VPN, proxy, WiFi (dove verificabile) e share funzionano come su
la macchina di riferimento, senza terminale.

---

## 12. Decisioni prese (2026-09-30)

1. **Linguaggio**: Rust (gtk4-rs + libadwaita-rs, `zbus` per NetworkManager e systemd).
2. **Helper**: pkexec con azione polkit per iniziare; l'interfaccia ad azioni permette di
   passare a un servizio D-Bus di sistema senza toccare la GUI.
3. **Profilo `.bnw`**: cifrato con passphrase, formato age.
4. **Nomi**: `it.akusen.BusinessNetworkWizard`, eseguibile `bnw`, pacchetto
   `business-network-wizard`.
5. **Stampanti**: dentro dalla v1. Lato di stampa predefinito: **solo fronte** (`duplex =
   false`), com'è oggi la `STAMPA_P1`. Il driver generato da CUPS chiama l'opzione `Duplex`,
   non `sides`: il generatore imposta **tutte e due** in modo coerente
   (`Duplex-default=None`, `sides-default=one-sided`; con `duplex = true`
   `DuplexNoTumble` / `two-sided-long-edge`, come faceva `install.sh`).
6. **Funzioni fish**: abbandonate; al loro posto l'app e `bnw` da riga di comando.

## 13. Da chiarire strada facendo

- Niente, per ora.
