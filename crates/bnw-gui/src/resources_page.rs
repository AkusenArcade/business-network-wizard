//! Pagina Dischi e stampanti: le share CIFS (automount) e le code CUPS del profilo.
//! Le modifiche restano in bozza finché non si preme Applica, come le eccezioni del
//! proxy.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use bnw_client::user;
use bnw_core::action::Action;
use bnw_core::profile::{Printer, Share};
use bnw_core::status::Status;
use gtk::{gio, glib};

use crate::app::{self, App};

pub struct ResourcesPage {
    pub page: adw::PreferencesPage,
    shares: adw::PreferencesGroup,
    share_rows: RefCell<Vec<adw::ActionRow>>,
    share_add: adw::ButtonRow,
    share_apply: gtk::Button,
    share_revert: gtk::Button,
    unmount: gtk::Button,
    shares_draft: RefCell<Option<Vec<Share>>>,
    printers: adw::PreferencesGroup,
    printer_rows: RefCell<Vec<adw::ActionRow>>,
    printer_add: adw::ButtonRow,
    printer_apply: gtk::Button,
    printer_revert: gtk::Button,
    printers_draft: RefCell<Option<Vec<Printer>>>,
    /// L'ultimo stato letto, per ridisegnare le righe senza rileggerlo.
    status: RefCell<Status>,
}

fn apply_buttons() -> (gtk::Box, gtk::Button, gtk::Button) {
    let apply = gtk::Button::builder()
        .label("Applica")
        .css_classes(["suggested-action"])
        .visible(false)
        .build();
    let revert = gtk::Button::builder().label("Annulla").visible(false).build();
    let b = gtk::Box::builder().spacing(6).build();
    b.append(&revert);
    b.append(&apply);
    (b, apply, revert)
}

fn icon_button(icon: &str, tooltip: &str) -> gtk::Button {
    gtk::Button::builder()
        .icon_name(icon)
        .tooltip_text(tooltip)
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build()
}

impl ResourcesPage {
    pub fn new() -> Self {
        let page = adw::PreferencesPage::new();

        let shares = adw::PreferencesGroup::builder()
            .title("Dischi di rete")
            .description("Si montano al primo accesso alla cartella e si smontano dopo 10 minuti di inattività. Servono la VPN o la rete aziendale.")
            .build();
        let (buttons, share_apply, share_revert) = apply_buttons();
        let unmount = gtk::Button::builder()
            .label("Smonta tutto")
            .visible(false)
            .build();
        buttons.prepend(&unmount);
        shares.set_header_suffix(Some(&buttons));
        let share_add = adw::ButtonRow::builder()
            .title("Aggiungi un disco di rete…")
            .start_icon_name("list-add-symbolic")
            .build();
        shares.add(&share_add);

        let printers = adw::PreferencesGroup::builder()
            .title("Stampanti")
            .description("Code CUPS driverless (IPP Everywhere): niente driver. Per aggiungerne una serve la rete aziendale o la VPN.")
            .build();
        let (buttons, printer_apply, printer_revert) = apply_buttons();
        printers.set_header_suffix(Some(&buttons));
        let printer_add = adw::ButtonRow::builder()
            .title("Aggiungi una stampante…")
            .start_icon_name("list-add-symbolic")
            .build();
        printers.add(&printer_add);

        page.add(&shares);
        page.add(&printers);
        ResourcesPage {
            page,
            shares,
            share_rows: RefCell::default(),
            share_add,
            share_apply,
            share_revert,
            unmount,
            shares_draft: RefCell::default(),
            printers,
            printer_rows: RefCell::default(),
            printer_add,
            printer_apply,
            printer_revert,
            printers_draft: RefCell::default(),
            status: RefCell::default(),
        }
    }

    pub fn connect(&self, app: &Rc<App>) {
        let a = app.clone();
        self.share_add.connect_activated(move |_| {
            glib::spawn_future_local(add_share(a.clone()));
        });
        let a = app.clone();
        self.printer_add.connect_activated(move |_| {
            glib::spawn_future_local(add_printer(a.clone()));
        });
        let a = app.clone();
        self.share_revert.connect_clicked(move |_| {
            a.resources_page.shares_draft.replace(None);
            a.resources_page.render(&a);
        });
        let a = app.clone();
        self.printer_revert.connect_clicked(move |_| {
            a.resources_page.printers_draft.replace(None);
            a.resources_page.render(&a);
        });
        let a = app.clone();
        self.unmount.connect_clicked(move |_| {
            let a = a.clone();
            glib::spawn_future_local(async move {
                if let Some(r) = app::run_helper(&a, &Action::UnmountShares).await {
                    app::show_report(&a, "Dischi smontati", &r).await;
                }
                app::refresh(&a);
            });
        });
        let a = app.clone();
        self.share_apply.connect_clicked(move |_| {
            glib::spawn_future_local(apply_shares(a.clone()));
        });
        let a = app.clone();
        self.printer_apply.connect_clicked(move |_| {
            let a = a.clone();
            glib::spawn_future_local(async move {
                let Some(list) = a.resources_page.printers_draft.borrow().clone() else {
                    return;
                };
                let Some(mut p) = a.profile.borrow().clone() else {
                    return;
                };
                p.printers = list;
                if let Some(r) = app::run_helper(&a, &Action::ApplyPrinters { profile: p }).await {
                    if !r.failed() {
                        a.resources_page.printers_draft.replace(None);
                    }
                    app::show_report(&a, "Stampanti applicate", &r).await;
                }
                app::refresh(&a);
            });
        });
    }

    fn current_shares(&self, app: &App) -> Vec<Share> {
        self.shares_draft.borrow().clone().unwrap_or_else(|| {
            app.profile
                .borrow()
                .as_ref()
                .map(|p| p.shares.clone())
                .unwrap_or_default()
        })
    }

    fn current_printers(&self, app: &App) -> Vec<Printer> {
        self.printers_draft.borrow().clone().unwrap_or_else(|| {
            app.profile
                .borrow()
                .as_ref()
                .map(|p| p.printers.clone())
                .unwrap_or_default()
        })
    }

    pub fn update(&self, app: &Rc<App>, st: &Status) {
        self.page.set_sensitive(app.profile.borrow().is_some());
        self.status.replace(st.clone());
        self.render(app);
    }

    fn render(&self, app: &Rc<App>) {
        let st = self.status.borrow().clone();

        for r in self.share_rows.take() {
            self.shares.remove(&r);
        }
        let shares = self.current_shares(app);
        let dirty = self.shares_draft.borrow().is_some();
        self.share_apply.set_visible(dirty);
        self.share_revert.set_visible(dirty);
        self.unmount
            .set_visible(!dirty && st.shares.iter().any(|s| s.mounted));
        let mut rows = Vec::new();
        for (i, share) in shares.iter().enumerate() {
            let mounted = st.shares.iter().any(|s| s.mount == share.mount && s.mounted);
            let state = if dirty && !st.shares.iter().any(|s| s.mount == share.mount) {
                "da applicare"
            } else if mounted {
                "montato"
            } else {
                "non montato"
            };
            let row = adw::ActionRow::builder()
                .title(share.label())
                .subtitle(format!("{} → {}  ·  {state}", share.unc(), share.mount))
                .build();
            let open = icon_button("folder-open-symbolic", "Apri la cartella");
            let mount = share.mount.clone();
            let a = app.clone();
            open.connect_clicked(move |_| {
                let launcher = gtk::FileLauncher::new(Some(&gio::File::for_path(&mount)));
                let a = a.clone();
                glib::spawn_future_local(async move {
                    if let Err(e) = launcher.launch_future(Some(&a.window)).await {
                        app::show_message(
                            &a,
                            "Cartella non raggiungibile",
                            &format!("{e}\n\nServe la VPN o la rete aziendale."),
                        )
                        .await;
                    }
                });
            });
            let remove = icon_button("user-trash-symbolic", "Togli dal profilo");
            let a = app.clone();
            remove.connect_clicked(move |_| {
                let mut list = a.resources_page.current_shares(&a);
                list.remove(i);
                a.resources_page.shares_draft.replace(Some(list));
                a.resources_page.render(&a);
            });
            row.add_suffix(&open);
            row.add_suffix(&remove);
            self.shares.add(&row);
            rows.push(row);
        }
        self.shares.remove(&self.share_add);
        self.shares.add(&self.share_add);
        self.share_rows.replace(rows);

        for r in self.printer_rows.take() {
            self.printers.remove(&r);
        }
        let printers = self.current_printers(app);
        let dirty = self.printers_draft.borrow().is_some();
        self.printer_apply.set_visible(dirty);
        self.printer_revert.set_visible(dirty);
        let mut rows = Vec::new();
        for (i, pr) in printers.iter().enumerate() {
            let state = match st
                .printers
                .iter()
                .find(|p| p.name == pr.name)
                .and_then(|p| p.state.clone())
                .as_deref()
            {
                Some("idle") => "pronta",
                Some("printing") => "in stampa",
                Some("disabled") => "disattivata",
                Some(_) => "attiva",
                None => "da applicare",
            };
            let mut subtitle = vec![state.to_string(), pr.uri.clone()];
            if let Some(l) = &pr.location {
                subtitle.insert(0, l.clone());
            }
            let row = adw::ActionRow::builder()
                .title(&pr.name)
                .subtitle(subtitle.join("  ·  "))
                .build();
            let duplex = gtk::Switch::builder()
                .active(pr.duplex)
                .valign(gtk::Align::Center)
                .tooltip_text("Fronte-retro come predefinito")
                .build();
            let a = app.clone();
            duplex.connect_active_notify(move |sw| {
                let mut list = a.resources_page.current_printers(&a);
                if list[i].duplex != sw.is_active() {
                    list[i].duplex = sw.is_active();
                    a.resources_page.printers_draft.replace(Some(list));
                    a.resources_page.render(&a);
                }
            });
            let label = gtk::Label::builder()
                .label("Fronte-retro")
                .css_classes(["dim-label"])
                .build();
            let test = icon_button("document-print-symbolic", "Stampa una pagina di prova");
            let name = pr.name.clone();
            let a = app.clone();
            test.connect_clicked(move |_| {
                let argv = ["lp", "-d", name.as_str(), "/usr/share/cups/data/testprint"];
                let argv: Vec<&std::ffi::OsStr> = argv.iter().map(|s| s.as_ref()).collect();
                match gio::Subprocess::newv(
                    &argv,
                    gio::SubprocessFlags::STDOUT_SILENCE | gio::SubprocessFlags::STDERR_SILENCE,
                ) {
                    Ok(_) => app::toast(&a, "Pagina di prova inviata"),
                    Err(e) => app::toast(&a, &format!("lp: {e}")),
                }
            });
            let remove = icon_button("user-trash-symbolic", "Togli dal profilo");
            let a = app.clone();
            remove.connect_clicked(move |_| {
                let mut list = a.resources_page.current_printers(&a);
                list.remove(i);
                a.resources_page.printers_draft.replace(Some(list));
                a.resources_page.render(&a);
            });
            row.add_suffix(&label);
            row.add_suffix(&duplex);
            row.add_suffix(&test);
            row.add_suffix(&remove);
            self.printers.add(&row);
            rows.push(row);
        }
        self.printers.remove(&self.printer_add);
        self.printers.add(&self.printer_add);
        self.printer_rows.replace(rows);
    }
}

async fn apply_shares(app: Rc<App>) {
    let Some(list) = app.resources_page.shares_draft.borrow().clone() else {
        return;
    };
    let Some(mut p) = app.profile.borrow().clone() else {
        return;
    };
    let before = p.shares.clone();
    p.shares = list.clone();
    let action = Action::ApplyShares {
        profile: p,
        owner_uid: user::current_uid(),
    };
    if let Some(r) = app::run_helper(&app, &action).await {
        if !r.failed() {
            app.resources_page.shares_draft.replace(None);
            if let Err(e) = user::sync_bookmarks(&glib::home_dir(), &before, &list) {
                app::toast(&app, &format!("Segnalibri non aggiornati: {e}"));
            }
        }
        app::show_report(&app, "Dischi di rete applicati", &r).await;
    }
    app::refresh(&app);
}

/// Un dialogo con delle righe di testo; `None` se annullato.
async fn form(app: &App, heading: &str, body: &str, rows: &[&adw::PreferencesRow], ok: &str) -> bool {
    let group = adw::PreferencesGroup::new();
    for r in rows {
        group.add(*r);
    }
    let d = adw::AlertDialog::new(Some(heading), Some(body));
    d.set_extra_child(Some(&group));
    d.add_response("cancel", "Annulla");
    d.add_response("ok", ok);
    d.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    d.set_close_response("cancel");
    d.choose_future(Some(&app.window)).await == "ok"
}

async fn add_share(app: Rc<App>) {
    let unc = adw::EntryRow::builder()
        .title(r"Percorso: \\server\cartella o //server/cartella")
        .build();
    let mount = adw::EntryRow::builder()
        .title("Cartella locale (sotto /mnt)")
        .text("/mnt/")
        .build();
    let label = adw::EntryRow::builder()
        .title("Nome nei segnalibri (facoltativo)")
        .build();
    // la cartella locale si propone dal nome della share, finché l'utente non la tocca
    let m = mount.clone();
    unc.connect_changed(move |e| {
        if let Some((_, name)) = bnw_cli::parse_unc(&e.text()) {
            m.set_text(&format!("/mnt/{}", name.to_lowercase().replace(' ', "-")));
        }
    });
    let rows: [&adw::PreferencesRow; 3] = [unc.upcast_ref(), mount.upcast_ref(), label.upcast_ref()];
    if !form(
        &app,
        "Aggiungi un disco di rete",
        "Lo stesso percorso che si usa da Windows.",
        &rows,
        "Aggiungi",
    )
    .await
    {
        return;
    }
    let Some((server, name)) = bnw_cli::parse_unc(&unc.text()) else {
        return app::show_message(
            &app,
            "Percorso non valido",
            r"Serve \\server\cartella o //server/cartella.",
        )
        .await;
    };
    let share = Share {
        server,
        name,
        mount: mount.text().trim().to_string(),
        label: Some(label.text().trim().to_string()).filter(|l| !l.is_empty()),
    };
    let mut list = app.resources_page.current_shares(&app);
    if list.iter().any(|s| s.mount == share.mount) {
        return app::show_message(
            &app,
            "Cartella già usata",
            &format!("{} è già di un altro disco.", share.mount),
        )
        .await;
    }
    list.push(share);
    // la copia prima: un prestito del RefCell non deve attraversare un .await
    let current = app.profile.borrow().clone();
    if let Some(mut p) = current {
        p.shares = list.clone();
        if let Err(e) = bnw_core::validate::profile(&p) {
            let msg = e.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n");
            return app::show_message(&app, "Disco non valido", &msg).await;
        }
    }
    app.resources_page.shares_draft.replace(Some(list));
    app.resources_page.render(&app);
}

async fn add_printer(app: Rc<App>) {
    let name = adw::EntryRow::builder()
        .title("Nome della coda (es. STAMPA_P3)")
        .build();
    let addr = adw::EntryRow::builder()
        .title("Indirizzo: nome host o ipp://host/ipp")
        .build();
    let location = adw::EntryRow::builder().title("Posizione (facoltativa)").build();
    let duplex = adw::SwitchRow::builder()
        .title("Fronte-retro come predefinito")
        .build();
    let rows: [&adw::PreferencesRow; 4] = [
        name.upcast_ref(),
        addr.upcast_ref(),
        location.upcast_ref(),
        duplex.upcast_ref(),
    ];
    if !form(
        &app,
        "Aggiungi una stampante",
        "Driverless: la stampante deve supportare IPP (quasi tutte quelle di rete).",
        &rows,
        "Aggiungi",
    )
    .await
    {
        return;
    }
    let a = addr.text().trim().to_string();
    let uri = if a.contains("://") {
        a
    } else {
        format!("ipp://{a}/ipp")
    };
    let pr = Printer {
        name: name.text().trim().to_string(),
        uri,
        description: None,
        location: Some(location.text().trim().to_string()).filter(|l| !l.is_empty()),
        duplex: duplex.is_active(),
    };
    let mut list = app.resources_page.current_printers(&app);
    if list.iter().any(|p| p.name == pr.name) {
        return app::show_message(&app, "Nome già usato", &format!("La coda {} c'è già.", pr.name)).await;
    }
    list.push(pr);
    // la copia prima: un prestito del RefCell non deve attraversare un .await
    let current = app.profile.borrow().clone();
    if let Some(mut p) = current {
        p.printers = list.clone();
        if let Err(e) = bnw_core::validate::profile(&p) {
            let msg = e.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n");
            return app::show_message(&app, "Stampante non valida", &msg).await;
        }
    }
    app.resources_page.printers_draft.replace(Some(list));
    app.resources_page.render(&app);
}
