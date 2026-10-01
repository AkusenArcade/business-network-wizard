# Business Network Wizard

Un'app GTK4 per Linux (Arch, CachyOS) che configura da zero, e poi mantiene, l'accesso
alla rete aziendale: proxy con autenticazione NTLM, VPN OpenVPN, WiFi 802.1X, dischi di
rete CIFS, stampanti CUPS e password di dominio. Tutto dalla GUI, senza terminale.

L'app è generica: i dati di un'azienda stanno in un **profilo aziendale** (`.bnw`), un
file cifrato che si prepara una volta su un PC già configurato e si importa sugli altri.

## Cosa fa

| Parte | Come |
|---|---|
| Proxy | `applicazioni → tinyproxy :8118 → cntlm :3128 → proxy aziendale`. Passa da solo al proxy aziendale quando la VPN è attiva o il proxy risponde (WiFi o rete dell'ufficio), altrimenti va diretto. Eccezioni, forzatura manuale, `/etc/environment`, policy di Firefox e Zen. |
| VPN | Import dell'`.ovpn` con le correzioni che l'importatore di NetworkManager sbaglia (nessun secret agent, `remote-cert-tls`, full-tunnel). Chiavi e certificati in `/etc/bnw/vpn` (700). |
| WiFi | Profilo 802.1X (PEAP/MSCHAPv2) costruito via D-Bus, CA del RADIUS controllata sul fingerprint. |
| Dischi di rete | Share CIFS in automount (montano al primo accesso, si smontano dopo 10 minuti), segnalibri del file manager. |
| Stampanti | Code CUPS driverless (IPP Everywhere), lato di stampa predefinito. |
| Password di dominio | Un campo, quattro posti (cntlm, VPN, WiFi, dischi). La password nuova si prova con un cntlm temporaneo **prima** di scriverla: con un 407 non si scrive niente. Lo stato confronta i quattro segreti senza mostrarli. |

## Installazione

Da AUR: `business-network-wizard` (dipende da `cntlm`, anch'esso su AUR).

Serve una connessione internet **non aziendale** (per esempio l'hotspot del telefono):
sulla rete dell'ufficio pacman vorrebbe il proxy, che ancora non c'è. In alternativa,
da un PC già configurato: menu ☰ → «Prepara installazione offline…» (o `bnw
offline-bundle FILE.tar`) produce un archivio con i pacchetti e uno script `installa.sh`.

## Prima configurazione

1. Su un PC già configurato: menu ☰ → «Esporta profilo aziendale…» (passphrase).
2. Sul PC nuovo: apri «Rete aziendale», premi «Configura…», scegli il `.bnw`, scrivi
   utenza e password di dominio.

Da terminale: `bnw setup azienda.bnw`.

Per preparare un profilo nuovo (per esempio quando l'azienda cambia dominio): menu ☰ →
«Modifica profilo aziendale…», poi «Salva come .bnw…» o «Applica a questa macchina…».

Una macchina configurata a mano con gli script del kit precedente si **adotta** senza
cambiarne il comportamento: banner «Adotta…» o `bnw adopt profile.toml`.

## Da terminale

```
bnw status [--json] [--detect]     stato (anche per un indicatore nella barra)
bnw proxy auto|on|off|test URL
bnw vpn up|down|check|import FILE.ovpn
bnw wifi up|down|check|ca FILE.pem|autoconnect on|off
bnw share add|remove|check|umount
bnw printer add|remove|check|test
bnw password [--stato]
bnw profile export|show|import FILE.bnw
```

## Sicurezza

- Le azioni con privilegi le esegue `bnw-helper` (via pkexec e polkit): accetta solo le
  proprie azioni, in JSON su stdin, con i parametri rivalidati. I segreti passano solo da
  stdin e da D-Bus, mai sulla riga di comando.
- Il profilo `.bnw` contiene la chiave privata della VPN ed è sempre cifrato
  ([age](https://age-encryption.org), passphrase). Non contiene password di dominio.
- Ogni file modificato ha un backup `.bak-<data>`; i keyfile di NetworkManager e le unit
  systemd hanno il backup in `/etc/bnw/backup/`.

## Sviluppo

Workspace Rust: `bnw-core` (profilo, generatori, cifratura), `bnw-helper` (root),
`bnw-client` (lato utente), `bnw-cli`, `bnw-gui` (binario `bnw`). Il piano è in
`PIANO.md`.

```
cargo test
BNW_ROOT=/tmp/radice BNW_HELPER=target/debug/bnw-helper target/debug/bnw
```

Con `BNW_ROOT` l'helper lavora in una cartella qualsiasi e non tocca il sistema.
`packaging/local/PKGBUILD` compila il pacchetto dal repository locale.

Licenza: GPL-3.0-or-later.
