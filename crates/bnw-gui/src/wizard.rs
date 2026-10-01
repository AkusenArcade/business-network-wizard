//! Il wizard di prima configurazione: controlli, profilo `.bnw`, utenza e password,
//! applicazione con verifica. Su un PC nuovo è l'unica cosa da fare dopo aver
//! installato il pacchetto.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use bnw_client::{bundle as cb, checks, user};
use bnw_core::action::{Action, NtlmCheck};
use bnw_core::bundle::{Bundle, BundleError};
use gtk::{gio, glib};

use crate::app::{self, App};

#[derive(Default)]
struct State {
    bundle: Option<Bundle>,
}

/// Una pagina del wizard: titolo, contenuto, pulsante «Avanti» in fondo.
fn page(title: &str, content: &adw::PreferencesPage, next: &gtk::Button) -> adw::NavigationPage {
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(content));
    let bottom = gtk::Box::builder()
        .halign(gtk::Align::End)
        .margin_top(12)
        .margin_bottom(12)
        .margin_end(12)
        .build();
    bottom.append(next);
    toolbar.add_bottom_bar(&bottom);
    adw::NavigationPage::builder()
        .title(title)
        .child(&toolbar)
        .build()
}

fn next_button(label: &str) -> gtk::Button {
    gtk::Button::builder()
        .label(label)
        .css_classes(["suggested-action", "pill"])
        .build()
}

pub fn open(app: &Rc<App>) {
    let dialog = adw::Dialog::builder()
        .title("Configura la rete aziendale")
        .content_width(600)
        .content_height(680)
        .build();
    let nav = adw::NavigationView::new();
    dialog.set_child(Some(&nav));
    let state = Rc::new(RefCell::new(State::default()));
    nav.push(&welcome(app, &nav, &dialog, &state));
    dialog.present(Some(&app.window));
}

fn welcome(
    app: &Rc<App>,
    nav: &adw::NavigationView,
    dialog: &adw::Dialog,
    state: &Rc<RefCell<State>>,
) -> adw::NavigationPage {
    let content = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .title("Cosa serve")
        .description(
            "La configurazione usa un profilo aziendale (.bnw) preparato su un PC già configurato, \
             più la tua utenza e la tua password di dominio.",
        )
        .build();
    let results = checks::run();
    let blocked = results.iter().any(|c| c.required && !c.ok);
    for c in &results {
        let row = adw::ActionRow::builder().title(c.what).subtitle(c.why).build();
        let (icon, class) = match (c.ok, c.required) {
            (true, _) => ("object-select-symbolic", "success"),
            (false, true) => ("dialog-error-symbolic", "error"),
            (false, false) => ("dialog-warning-symbolic", "warning"),
        };
        let img = gtk::Image::from_icon_name(icon);
        img.add_css_class(class);
        row.add_prefix(&img);
        group.add(&row);
    }
    content.add(&group);
    if results.iter().any(|c| !c.ok) {
        let hint = adw::PreferencesGroup::builder()
            .description(checks::MISSING_HINT)
            .build();
        content.add(&hint);
    }
    let next = next_button("Avanti");
    next.set_sensitive(!blocked);
    let (a, n, d, s) = (app.clone(), nav.clone(), dialog.clone(), state.clone());
    next.connect_clicked(move |_| n.push(&choose_profile(&a, &n, &d, &s)));
    page("Benvenuto", &content, &next)
}

fn choose_profile(
    app: &Rc<App>,
    nav: &adw::NavigationView,
    dialog: &adw::Dialog,
    state: &Rc<RefCell<State>>,
) -> adw::NavigationPage {
    let content = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .title("Profilo aziendale")
        .description("Il file .bnw e la passphrase scelta quando è stato esportato.")
        .build();
    let file_row = adw::ActionRow::builder()
        .title("File")
        .subtitle("da scegliere")
        .build();
    let choose = gtk::Button::builder()
        .label("Scegli…")
        .valign(gtk::Align::Center)
        .build();
    file_row.add_suffix(&choose);
    let pass = adw::PasswordEntryRow::builder()
        .title("Passphrase")
        .show_apply_button(true)
        .build();
    group.add(&file_row);
    group.add(&pass);
    let summary = adw::PreferencesGroup::builder()
        .title("Contenuto")
        .visible(false)
        .build();
    let summary_label = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .selectable(true)
        .build();
    summary.add(&summary_label);
    content.add(&group);
    content.add(&summary);

    let next = next_button("Avanti");
    next.set_sensitive(false);
    let data: Rc<RefCell<Option<Vec<u8>>>> = Rc::default();

    let (a, fr, dt) = (app.clone(), file_row.clone(), data.clone());
    let dlg = dialog.clone();
    choose.connect_clicked(move |_| {
        let (a, fr, dt, dlg) = (a.clone(), fr.clone(), dt.clone(), dlg.clone());
        glib::spawn_future_local(async move {
            let f = gtk::FileFilter::new();
            f.set_name(Some("Profilo aziendale (.bnw)"));
            f.add_pattern("*.bnw");
            let filters = gio::ListStore::new::<gtk::FileFilter>();
            filters.append(&f);
            let fd = gtk::FileDialog::builder().filters(&filters).modal(true).build();
            let parent = dlg
                .root()
                .and_downcast::<gtk::Window>()
                .unwrap_or_else(|| a.window.clone().upcast());
            let Ok(file) = fd.open_future(Some(&parent)).await else {
                return;
            };
            match file.load_contents_future().await {
                Ok((bytes, _)) => {
                    fr.set_subtitle(&file.path().map(|p| p.display().to_string()).unwrap_or_default());
                    dt.replace(Some(bytes.to_vec()));
                }
                Err(e) => fr.set_subtitle(&format!("illeggibile: {e}")),
            }
        });
    });

    let (st, nx, sl, sg, dt) = (
        state.clone(),
        next.clone(),
        summary_label.clone(),
        summary.clone(),
        data.clone(),
    );
    pass.connect_apply(move |row| {
        let Some(bytes) = dt.borrow().clone() else {
            row.add_css_class("error");
            return;
        };
        let p = row.text().to_string();
        let (st, nx, sl, sg, row) = (st.clone(), nx.clone(), sl.clone(), sg.clone(), row.clone());
        row.set_sensitive(false);
        glib::spawn_future_local(async move {
            // scrypt: qualche secondo, fuori dal thread della GUI
            let result = gio::spawn_blocking(move || Bundle::decrypt(&bytes, &p)).await;
            row.set_sensitive(true);
            match result {
                Ok(Ok(b)) => {
                    let mut text = cb::summary(&b);
                    match b.check() {
                        Ok(w) => w.iter().for_each(|w| text += &format!("\n⚠ {w}")),
                        Err(e) => text += &format!("\n✗ {e}"),
                    }
                    sl.set_label(text.trim());
                    sg.set_visible(true);
                    nx.set_sensitive(b.check().is_ok());
                    row.remove_css_class("error");
                    row.set_text("");
                    st.borrow_mut().bundle = Some(b);
                }
                Ok(Err(BundleError::Decrypt)) => {
                    row.add_css_class("error");
                    row.set_title("Passphrase sbagliata, riprova");
                }
                Ok(Err(e)) => {
                    sl.set_label(&e.to_string());
                    sg.set_visible(true);
                }
                Err(_) => {}
            }
        });
    });

    let (a, n, d, s) = (app.clone(), nav.clone(), dialog.clone(), state.clone());
    next.connect_clicked(move |_| n.push(&credentials(&a, &n, &d, &s)));
    page("Profilo", &content, &next)
}

fn credentials(
    app: &Rc<App>,
    nav: &adw::NavigationView,
    dialog: &adw::Dialog,
    state: &Rc<RefCell<State>>,
) -> adw::NavigationPage {
    let (domain, hint) = state
        .borrow()
        .bundle
        .as_ref()
        .map(|b| {
            (
                b.profile.company.domain.clone(),
                b.profile
                    .company
                    .user_hint
                    .clone()
                    .unwrap_or_else(|| "nome.cognome".into()),
            )
        })
        .unwrap_or_default();
    let content = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .title("Credenziali di dominio")
        .description(format!(
            "Dominio {domain}. La password va nel proxy, nella VPN, nel WiFi e nei dischi di rete. \
             Prima di salvarla l'app la prova con il proxy aziendale, se è raggiungibile."
        ))
        .build();
    let user_row = adw::EntryRow::builder()
        .title(format!("Utenza (es. {hint})"))
        .build();
    let p1 = adw::PasswordEntryRow::builder().title("Password").build();
    let p2 = adw::PasswordEntryRow::builder().title("Ripetila").build();
    let error = adw::ActionRow::builder().visible(false).build();
    error.add_css_class("error");
    for r in [
        user_row.upcast_ref::<adw::PreferencesRow>(),
        p1.upcast_ref(),
        p2.upcast_ref(),
        error.upcast_ref(),
    ] {
        group.add(r);
    }
    content.add(&group);

    let next = next_button("Configura");
    next.set_sensitive(false);
    let check = {
        let (u, p1, p2, nx) = (user_row.clone(), p1.clone(), p2.clone(), next.clone());
        move || {
            let user_ok = bnw_core::validate::target(&bnw_core::Target {
                domain_user: u.text().trim().to_string(),
                uid: 0,
                gid: 0,
            })
            .is_ok();
            nx.set_sensitive(user_ok && !p1.text().is_empty() && p1.text() == p2.text());
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

    let (a, n, d, s) = (app.clone(), nav.clone(), dialog.clone(), state.clone());
    let (u, pw1, pw2, err) = (user_row.clone(), p1.clone(), p2.clone(), error.clone());
    next.connect_clicked(move |btn| {
        let user = u.text().trim().to_string();
        let password = pw1.text().to_string();
        pw1.set_text("");
        pw2.set_text("");
        btn.set_sensitive(false);
        let (a, n, d, s, err) = (a.clone(), n.clone(), d.clone(), s.clone(), err.clone());
        glib::spawn_future_local(async move {
            n.push(&applying(&a, &n, &d, &s, user, password, err).await);
        });
    });
    page("Credenziali", &content, &next)
}

/// Applica e mostra l'esito. Se la prova preventiva rifiuta la password non è stato
/// scritto niente: si torna alle credenziali con un messaggio.
async fn applying(
    app: &Rc<App>,
    nav: &adw::NavigationView,
    dialog: &adw::Dialog,
    state: &Rc<RefCell<State>>,
    user: String,
    password: String,
    error_row: adw::ActionRow,
) -> adw::NavigationPage {
    let content = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder().title("Configurazione").build();
    let spinner = adw::Spinner::new();
    let status = adw::ActionRow::builder().title("Applico il profilo…").build();
    status.add_prefix(&spinner);
    group.add(&status);
    let report = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .selectable(true)
        .visible(false)
        .build();
    group.add(&report);
    content.add(&group);
    let close = next_button("Chiudi");
    close.set_sensitive(false);
    let d = dialog.clone();
    close.connect_clicked(move |_| {
        d.close();
    });
    let result_page = page("Applicazione", &content, &close);

    let bundle = state.borrow().bundle.clone();
    let (a, n, rep, st, sp, cl) = (
        app.clone(),
        nav.clone(),
        report.clone(),
        status.clone(),
        spinner.clone(),
        close.clone(),
    );
    glib::spawn_future_local(async move {
        let Some(bundle) = bundle else { return };
        let before = a
            .profile
            .borrow()
            .as_ref()
            .map(|p| p.shares.clone())
            .unwrap_or_default();
        let Some(applied) = app::run_helper(&a, &cb::apply_action(&bundle, Some(user.clone()))).await else {
            n.pop();
            return;
        };
        let _ = user::sync_bookmarks(&glib::home_dir(), &before, &bundle.profile.shares);
        st.set_title("Scrivo la password nei quattro posti…");
        let action = Action::SetPassword {
            password: bnw_core::Secret::new(password),
            only: Vec::new(),
            domain_user: Some(user),
        };
        let Some(pw) = app::run_helper(&a, &action).await else {
            n.pop();
            return;
        };
        if pw.rejected_before_writing() {
            error_row.set_title(
                "Il proxy aziendale ha rifiutato la password (407): non è stato scritto niente. Riscrivila.",
            );
            error_row.set_visible(true);
            n.pop();
            return;
        }
        sp.set_visible(false);
        let failed = applied.failed() || pw.failed();
        st.set_title(match (failed, pw.ntlm) {
            (true, _) => "Configurazione incompleta: i passi con ✗ si possono ripetere",
            (false, Some(NtlmCheck::Ok { .. })) => "Fatto: il proxy aziendale accetta la password",
            (false, _) => "Fatto. La prova del proxy si farà sulla rete aziendale o in VPN",
        });
        let mut text = app::report_text(&applied, true);
        text += "\n";
        text += &app::report_text(&pw, true);
        text += "\n\nApri una sessione nuova (o riavvia) perché le applicazioni vedano il proxy.";
        rep.set_label(text.trim());
        rep.set_visible(true);
        cl.set_sensitive(true);
        app::refresh(&a);
    });
    result_page
}
