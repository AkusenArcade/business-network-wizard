# Fixture di la macchina di esempio

Copie dei file in uso su la macchina di esempio al 2026-09-30, **senza segreti**. `profile.toml` è il
profilo aziendale che li descrive; `crates/bnw-core/tests/esempio.rs` verifica che i
generatori li rigenerino.

| File | Esito |
|---|---|
| `etc/tinyproxy/direct.conf`, `upstream.conf` | identici byte per byte |
| `etc/systemd/system/mnt-*.{mount,automount}` (4 share) | identici |
| `etc/environment` | identico, sia partendo dal file vuoto di Arch sia rilanciando |
| `etc/{firefox,zen}/policies/policies.json` | identici |
| `home/.config/gtk-3.0/bookmarks` | identico; i 3 segnalibri personali restano intatti |
| `etc/cntlm.conf.senza-hash` | le righe non segrete del file reale (niente `Pass*`): identiche tranne `NoProxy`, vedi sotto |
| `/etc/samba/credentials/esempio` | **non copiato** (password in chiaro): test con segnaposto |
| stampante `STAMPA_P1` | argomenti di `lpadmin`, vedi sotto |

## Differenze motivate

- **`cntlm.conf`, riga `NoProxy`**: `install.sh` la scriveva a mano
  (`localhost, 127.0.0.*, 10.*, 172.16.*, 192.168.*, *.corp.esempio`); l'app la deriva dalle
  eccezioni del profilo: `localhost, 127.*, 10.*, 172.16.*, 192.168.*, *.corp.esempio, *.esempioprod,
  esempio.it, *.esempio.it`. Il comportamento non cambia: le eccezioni le applica tinyproxy,
  che quelle richieste a cntlm non le manda.
- **Stampante**: oggi `STAMPA_P1` ha `Duplex=DuplexNoTumble` (fronte-retro, da `install.sh`)
  e `sides=one-sided`, due opzioni in disaccordo. L'app, per la decisione "solo fronte",
  imposta `Duplex-default=None` e `sides-default=one-sided`.
