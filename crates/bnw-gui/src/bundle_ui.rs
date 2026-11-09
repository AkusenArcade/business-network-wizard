//! Esporta e importa il profilo aziendale `.bnw` (menu della finestra).

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use adw::prelude::*;
use bnw_client::bundle as cb;
use bnw_core::action::{Action, NtlmCheck};
use bnw_core::bundle::{Bundle, MIN_PASSPHRASE};
use gtk::{gio, glib};

use crate::app::{self, App};

/// Le azioni `win.export-profile` e `win.import-profile` e il menu che le mostra.
pub fn install(app: &Rc<App>, header: &adw::HeaderBar) {
    let export = gio::SimpleAction::new("export-profile", None);
    let a = app.clone();
    export.connect_activate(move |_, _| {
        glib::spawn_future_local(export_profile(a.clone()));
    });
    let import = gio::SimpleAction::new("import-profile", None);
    let a = app.clone();
    import.connect_activate(move |_, _| {
        glib::spawn_future_local(import_profile(a.clone()));
    });
    let setup = gio::SimpleAction::new("setup", None);
    let a = app.clone();
    setup.connect_activate(move |_, _| crate::wizard::open(&a));
    app.window.add_action(&export);
    app.window.add_action(&import);
    app.window.add_action(&setup);
    let edit = gio::SimpleAction::new("edit-profile", None);
    let a = app.clone();
    edit.connect_activate(move |_, _| crate::profile_editor::open(&a));
    app.window.add_action(&edit);
    let offline = gio::SimpleAction::new("offline-bundle", None);
    let a = app.clone();
    offline.connect_activate(move |_, _| {
        glib::spawn_future_local(offline_bundle(a.clone()));
    });
    app.window.add_action(&offline);

    let menu = gio::Menu::new();
    menu.append(Some("Configura da un profilo…"), Some("win.setup"));
    menu.append(Some("Modifica profilo aziendale…"), Some("win.edit-profile"));
    menu.append(Some("Esporta profilo aziendale…"), Some("win.export-profile"));
    menu.append(Some("Importa profilo aziendale…"), Some("win.import-profile"));
    menu.append(Some("Prepara installazione offline…"), Some("win.offline-bundle"));
    let button = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .menu_model(&menu)
        .tooltip_text("Menu")
        .build();
    header.pack_end(&button);
}

fn bnw_filter() -> gio::ListStore {
    let f = gtk::FileFilter::new();
    f.set_name(Some("Profilo aziendale (.bnw)"));
    f.add_pattern("*.bnw");
    let list = gio::ListStore::new::<gtk::FileFilter>();
    list.append(&f);
    list
}

/// Una riga con un file scelto e il pulsante per cambiarlo.
fn file_row(
    app: &Rc<App>,
    title: &str,
    initial: Option<PathBuf>,
) -> (adw::ActionRow, Rc<RefCell<Option<PathBuf>>>) {
    let chosen = Rc::new(RefCell::new(initial));
    let row = adw::ActionRow::builder().title(title).build();
    let show = {
        let row = row.clone();
        move |p: &Option<PathBuf>| {
            row.set_subtitle(
                &p.as_ref()
                    .map_or("da scegliere".into(), |p| p.display().to_string()),
            );
        }
    };
    show(&chosen.borrow());
    let button = gtk::Button::builder()
        .label("Scegli…")
        .valign(gtk::Align::Center)
        .build();
    let (a, c) = (app.clone(), chosen.clone());
    button.connect_clicked(move |_| {
        let (a, c, show) = (a.clone(), c.clone(), show.clone());
        glib::spawn_future_local(async move {
            let d = gtk::FileDialog::builder().modal(true).build();
            if let Ok(f) = d.open_future(Some(&a.window)).await
                && let Some(p) = f.path()
            {
                show(&Some(p.clone()));
                c.replace(Some(p));
            }
        });
    });
    row.add_suffix(&button);
    (row, chosen)
}

async fn export_profile(app: Rc<App>) {
    let Some(profile) = app.profile.borrow().clone() else {
        return app::show_message(
            &app,
            "Nessun profilo",
            "Su questa macchina non c'è un profilo applicato da esportare.",
        )
        .await;
    };
    let p = profile.clone();
    let (ovpn, ca) = gio::spawn_blocking(move || (cb::detect_ovpn(&p, &glib::home_dir()), cb::detect_ca(&p)))
        .await
        .unwrap_or((None, None));

    let group = adw::PreferencesGroup::new();
    let (ovpn_row, ovpn) = file_row(&app, "VPN (.ovpn, con la chiave privata)", ovpn);
    let (ca_row, ca) = file_row(&app, "CA del WiFi aziendale", ca);
    if profile.vpn.is_some() {
        group.add(&ovpn_row);
    }
    if profile.wifi.is_some() {
        group.add(&ca_row);
    }
    let pass1 = adw::PasswordEntryRow::builder().title("Passphrase").build();
    let pass2 = adw::PasswordEntryRow::builder().title("Ripetila").build();
    group.add(&pass1);
    group.add(&pass2);

    let d = adw::AlertDialog::new(
        Some("Esporta il profilo aziendale"),
        Some(&format!(
            "Un file unico con proxy, VPN, WiFi, dischi di rete e stampanti, da importare su un \
             altro PC. Le password di dominio non ci sono; c'è però la chiave privata della VPN, \
             per questo il file è cifrato: serve una passphrase di almeno {MIN_PASSPHRASE} caratteri, \
             da conservare a parte."
        )),
    );
    d.set_extra_child(Some(&group));
    d.add_response("cancel", "Annulla");
    d.add_response("export", "Esporta…");
    d.set_response_appearance("export", adw::ResponseAppearance::Suggested);
    d.set_response_enabled("export", false);
    d.set_close_response("cancel");
    let check = {
        let (p1, p2, d) = (pass1.clone(), pass2.clone(), d.clone());
        move || {
            let ok = p1.text().chars().count() >= MIN_PASSPHRASE && p1.text() == p2.text();
            d.set_response_enabled("export", ok);
        }
    };
    let c = check.clone();
    pass1.connect_changed(move |_| c());
    pass2.connect_changed(move |_| check());

    if d.choose_future(Some(&app.window)).await != "export" {
        return;
    }
    let pass = pass1.text().to_string();
    pass1.set_text("");
    pass2.set_text("");

    let (ovpn, ca) = (ovpn.borrow().clone(), ca.borrow().clone());
    let built = gio::spawn_blocking(move || {
        let (bundle, warnings) =
            cb::build(&profile, ovpn.as_deref(), ca.as_deref()).map_err(|e| e.to_string())?;
        let data = bundle.encrypt(&pass).map_err(|e| e.to_string())?;
        Ok::<_, String>((data, warnings, bundle.profile.company.slug()))
    })
    .await;
    let (data, warnings, slug) = match built {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => return app::show_message(&app, "Esportazione non riuscita", &e).await,
        Err(_) => return,
    };

    let save = gtk::FileDialog::builder()
        .title("Salva il profilo aziendale")
        .initial_name(format!("{slug}.bnw"))
        .filters(&bnw_filter())
        .modal(true)
        .build();
    let Ok(file) = save.save_future(Some(&app.window)).await else {
        return;
    };
    let Some(path) = file.path() else { return };
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(&data));
    match written {
        Err(e) => {
            app::show_message(
                &app,
                "Esportazione non riuscita",
                &format!("{}: {e}", path.display()),
            )
            .await
        }
        Ok(()) if !warnings.is_empty() => {
            app::show_message(&app, "Profilo esportato, con avvisi", &warnings.join("\n")).await
        }
        Ok(()) => app::toast(&app, &format!("Profilo esportato in {}", path.display())),
    }
}

async fn ask_passphrase(app: &App, retry: bool) -> Option<String> {
    let row = adw::PasswordEntryRow::builder().title("Passphrase").build();
    let group = adw::PreferencesGroup::new();
    group.add(&row);
    let body = if retry {
        "Passphrase sbagliata, oppure il file non è un profilo .bnw. Riprova."
    } else {
        "Il profilo è cifrato: scrivi la passphrase scelta quando è stato esportato."
    };
    let d = adw::AlertDialog::new(Some("Apri il profilo aziendale"), Some(body));
    d.set_extra_child(Some(&group));
    d.add_response("cancel", "Annulla");
    d.add_response("open", "Apri");
    d.set_response_appearance("open", adw::ResponseAppearance::Suggested);
    d.set_default_response(Some("open"));
    d.set_close_response("cancel");
    let answer = d.choose_future(Some(&app.window)).await;
    let pass = row.text().to_string();
    row.set_text("");
    (answer == "open").then_some(pass)
}

async fn import_profile(app: Rc<App>) {
    // Solo per le schermate: niente file né passphrase, il profilo applicato fa da .bnw.
    if std::env::var_os("BNW_SCREENSHOT").is_some() {
        let env = app.env.clone();
        if let Ok(Some(b)) = gio::spawn_blocking(move || cb::from_installed(&env, &glib::home_dir())).await {
            let _ = ask_credentials(&app, &b, &cb::summary(&b)).await;
        }
        return;
    }
    let open = gtk::FileDialog::builder()
        .title("Importa un profilo aziendale")
        .filters(&bnw_filter())
        .modal(true)
        .build();
    let Ok(file) = open.open_future(Some(&app.window)).await else {
        return;
    };
    let Some(path) = file.path() else { return };
    let data = match std::fs::read(&path) {
        Ok(d) => Rc::new(d),
        Err(e) => return app::show_message(&app, "File illeggibile", &e.to_string()).await,
    };

    let mut retry = false;
    let bundle: Bundle = loop {
        let Some(pass) = ask_passphrase(&app, retry).await else {
            return;
        };
        let d = data.clone().as_ref().clone();
        match gio::spawn_blocking(move || Bundle::decrypt(&d, &pass)).await {
            Ok(Ok(b)) => break b,
            Ok(Err(bnw_core::bundle::BundleError::Decrypt)) => retry = true,
            Ok(Err(e)) => return app::show_message(&app, "Profilo non valido", &e.to_string()).await,
            Err(_) => return,
        }
    };

    let warnings = match bundle.check() {
        Ok(w) => w,
        Err(e) => return app::show_message(&app, "Profilo non valido", &e.to_string()).await,
    };
    let mut body = cb::summary(&bundle);
    for w in &warnings {
        body += &format!("\n⚠ {w}");
    }
    let Some((user, password)) = ask_credentials(&app, &bundle, &body).await else {
        return;
    };

    // una sola autorizzazione: polkit la tiene per qualche minuto
    let before = app
        .profile
        .borrow()
        .as_ref()
        .map(|p| p.shares.clone())
        .unwrap_or_default();
    let Some(applied) = app::run_helper(&app, &cb::apply_action(&bundle, Some(user.clone()))).await else {
        return;
    };
    if let Err(e) = bnw_client::user::sync_bookmarks(&glib::home_dir(), &before, &bundle.profile.shares) {
        app::toast(&app, &format!("Segnalibri non aggiornati: {e}"));
    }
    app::refresh(&app);

    // La password nei quattro posti. Se la prova preventiva la rifiuta (407) non è
    // stato scritto niente: la si richiede.
    let mut password = password;
    let pw = loop {
        let action = Action::SetPassword {
            password: bnw_core::Secret::new(password),
            only: Vec::new(),
            domain_user: Some(user.clone()),
        };
        let Some(r) = app::run_helper(&app, &action).await else {
            return;
        };
        if !r.rejected_before_writing() {
            break r;
        }
        match crate::password_page::ask_password(&app, true).await {
            Some(p) => password = p,
            None => {
                let mut text = app::report_text(&applied, true);
                text += "\n\nLa password non è stata salvata: aggiornala dalla pagina Password.";
                return app::show_message(&app, "Profilo applicato senza password", text.trim()).await;
            }
        }
    };
    app::refresh(&app);

    let heading = match (applied.failed() || pw.failed(), pw.ntlm) {
        (true, _) => "Configurazione incompleta: i passi con ✗ si possono ripetere",
        (false, Some(NtlmCheck::Ok { .. })) => "Fatto: il proxy aziendale accetta la password",
        (false, _) => "Profilo applicato",
    };
    let mut text = app::report_text(&applied, true);
    text += "\n";
    text += &app::report_text(&pw, true);
    if !matches!(pw.ntlm, Some(NtlmCheck::Ok { .. })) {
        text += "\n\nLa prova del proxy si farà sulla rete aziendale o in VPN.";
    }
    text += "\n\nApri una sessione nuova (o riavvia) perché le applicazioni vedano il proxy.";
    app::show_message(&app, heading, text.trim()).await;
}

/// Riepilogo del profilo, utenza di dominio e password (due volte). «Applica» si
/// abilita solo con un'utenza valida e due password uguali. Senza utenza la VPN non
/// si connette e il WiFi non si crea: per questo si chiede qui, come nel wizard.
async fn ask_credentials(app: &App, bundle: &Bundle, summary: &str) -> Option<(String, String)> {
    let hint = bundle
        .profile
        .company
        .user_hint
        .clone()
        .unwrap_or_else(|| "nome.cognome".into());
    let user_row = adw::EntryRow::builder()
        .title(format!("Utenza di dominio (es. {hint})"))
        .build();
    let p1 = adw::PasswordEntryRow::builder().title("Password di dominio").build();
    let p2 = adw::PasswordEntryRow::builder().title("Ripetila").build();
    let group = adw::PreferencesGroup::builder()
        .description(
            "La password va nel proxy, nella VPN, nel WiFi e nei dischi di rete. Prima di \
             salvarla l'app la prova con il proxy aziendale, se è raggiungibile.",
        )
        .build();
    group.add(&user_row);
    group.add(&p1);
    group.add(&p2);

    let d = adw::AlertDialog::new(
        Some(&format!("Profilo di {}", bundle.profile.company.name)),
        Some(summary),
    );
    d.set_extra_child(Some(&group));
    // il riepilogo è lungo: largo, i campi restano visibili senza scorrere
    d.set_prefer_wide_layout(true);
    d.add_response("close", "Annulla");
    d.add_response("apply", "Applica il profilo");
    d.set_response_appearance("apply", adw::ResponseAppearance::Suggested);
    d.set_response_enabled("apply", false);
    d.set_close_response("close");

    let check = {
        let (u, p1, p2, d) = (user_row.clone(), p1.clone(), p2.clone(), d.downgrade());
        move || {
            let Some(d) = d.upgrade() else { return };
            let user_ok = bnw_core::validate::target(&bnw_core::Target {
                domain_user: u.text().trim().to_string(),
                uid: 0,
                gid: 0,
            })
            .is_ok();
            let (a, b) = (p1.text(), p2.text());
            let pw_ok = !a.is_empty() && a == b && !a.contains(['\n', '\r']);
            d.set_response_enabled("apply", user_ok && pw_ok);
            if !b.is_empty() && a != b {
                p2.add_css_class("error");
            } else {
                p2.remove_css_class("error");
            }
        }
    };
    for e in [
        user_row.upcast_ref::<gtk::Editable>(),
        p1.upcast_ref(),
        p2.upcast_ref(),
    ] {
        let c = check.clone();
        e.connect_changed(move |_| c());
    }

    let answer = d.choose_future(Some(&app.window)).await;
    let user = user_row.text().trim().to_string();
    let password = p1.text().to_string();
    // i campi si svuotano subito: la password resta solo dove serve
    p1.set_text("");
    p2.set_text("");
    (answer == "apply").then_some((user, password))
}

/// Il bundle per installare l'app su un PC senza internet non aziendale.
async fn offline_bundle(app: Rc<App>) {
    let mut extra: Vec<std::path::PathBuf> = Vec::new();
    let plan = loop {
        let e = extra.clone();
        let Ok(plan) = gio::spawn_blocking(move || bnw_client::offline::plan(&e)).await else {
            return;
        };
        if plan.missing.is_empty() {
            break plan;
        }
        let names = plan
            .missing
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let d = adw::AlertDialog::new(
            Some("Mancano dei pacchetti"),
            Some(&format!(
                "Non trovati nella cache di pacman: {names}.\n\nSe li hai in un'altra cartella (per esempio \
                 dove hai compilato un pacchetto AUR), indicala."
            )),
        );
        d.add_response("cancel", "Annulla");
        d.add_response("without", "Prosegui senza");
        d.add_response("search", "Cerca in una cartella…");
        d.set_response_appearance("search", adw::ResponseAppearance::Suggested);
        match d.choose_future(Some(&app.window)).await.as_str() {
            "search" => {
                let fd = gtk::FileDialog::builder()
                    .title("Cartella con i pacchetti")
                    .modal(true)
                    .build();
                if let Ok(dir) = fd.select_folder_future(Some(&app.window)).await
                    && let Some(p) = dir.path()
                {
                    extra.push(p);
                }
            }
            "without" => break plan,
            _ => return,
        }
    };
    let save = gtk::FileDialog::builder()
        .title("Salva il bundle per l'installazione offline")
        .initial_name(format!(
            "bnw-offline-{}.tar",
            glib::DateTime::now_local()
                .ok()
                .and_then(|d| d.format("%Y%m%d").ok())
                .unwrap_or_default()
        ))
        .modal(true)
        .build();
    let Ok(file) = save.save_future(Some(&app.window)).await else {
        return;
    };
    let Some(path) = file.path() else { return };
    let v3 = plan.v3().len();
    let n = plan.found.len();
    let p = path.clone();
    match gio::spawn_blocking(move || bnw_client::offline::write(&plan, &p)).await {
        Ok(Ok(())) => {
            let mut body = format!(
                "{n} pacchetti in {}.\n\nSul PC nuovo: estrai il file (tar xf) e lancia «sh installa.sh», \
                 poi apri «Rete aziendale» e premi «Configura…».",
                path.display()
            );
            if v3 > 0 {
                body += &format!(
                    "\n\n{v3} pacchetti sono le versioni CachyOS ottimizzate (x86_64_v3): si installano solo \
                     su CPU recenti."
                );
            }
            app::show_message(&app, "Bundle pronto", &body).await;
        }
        Ok(Err(e)) => app::show_message(&app, "Bundle non scritto", &e.to_string()).await,
        Err(_) => {}
    }
}
