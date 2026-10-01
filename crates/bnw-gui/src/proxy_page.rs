//! Pagina Proxy: modalità (automatica / forzata), eccezioni, prova di un URL.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use bnw_client::nettest;
use bnw_core::action::{Action, ProxyMode};
use bnw_core::profile::DirectRule;
use bnw_core::status::Status;
use bnw_core::validate;
use gtk::{gio, glib};

use crate::app::{self, App};

pub struct ProxyPage {
    pub page: adw::PreferencesPage,
    mode: adw::ToggleGroup,
    /// Mentre si aggiorna la modalità dallo stato, il cambio non va rimandato all'helper.
    syncing: Cell<bool>,
    exceptions: adw::PreferencesGroup,
    add_row: adw::EntryRow,
    apply: gtk::Button,
    revert: gtk::Button,
    /// Le eccezioni in modifica; `None` finché non si tocca niente.
    draft: RefCell<Option<Vec<DirectRule>>>,
    /// Le righe mostrate, da togliere quando si ridisegna.
    rows: RefCell<Vec<adw::ActionRow>>,
    url: adw::EntryRow,
    direct_row: adw::ActionRow,
    proxy_row: adw::ActionRow,
    suggest: gtk::Button,
}

impl ProxyPage {
    pub fn new() -> Self {
        let page = adw::PreferencesPage::new();

        let mode_group = adw::PreferencesGroup::builder()
            .title("Modalità")
            .description(
                "In automatico il traffico passa dal proxy aziendale quando la VPN è attiva o il proxy \
                 risponde (WiFi o rete dell'ufficio). La forzatura vale fino al riavvio.",
            )
            .build();
        let mode = adw::ToggleGroup::builder().homogeneous(true).build();
        for (name, label) in [
            ("auto", "Automatica"),
            ("on", "Sempre proxy"),
            ("off", "Sempre diretto"),
        ] {
            mode.add(adw::Toggle::builder().name(name).label(label).build());
        }
        mode.add_css_class("round");
        mode_group.add(&mode);

        let exceptions = adw::PreferencesGroup::builder()
            .title("Eccezioni")
            .description(
                "Destinazioni raggiunte senza il proxy aziendale. «.esempio.it» vale per tutti i \
                 sottodomini ma non per «esempio.it»: se serve anche quello, vanno messi tutti e due.",
            )
            .build();
        let apply = gtk::Button::builder()
            .label("Applica")
            .css_classes(["suggested-action"])
            .build();
        let revert = gtk::Button::builder().label("Annulla").build();
        let buttons = gtk::Box::builder().spacing(6).build();
        buttons.append(&revert);
        buttons.append(&apply);
        exceptions.set_header_suffix(Some(&buttons));
        let add_row = adw::EntryRow::builder()
            .title("Aggiungi: host, .dominio o rete (10.0.0.0/8)")
            .show_apply_button(true)
            .build();
        exceptions.add(&add_row);

        let test = adw::PreferencesGroup::builder()
            .title("Prova un URL")
            .description("La stessa richiesta diretta e attraverso il proxy: un sito interno che dà 504 via proxy va tra le eccezioni")
            .build();
        let url = adw::EntryRow::builder()
            .title("https://…")
            .show_apply_button(true)
            .build();
        url.set_input_purpose(gtk::InputPurpose::Url);
        let direct_row = adw::ActionRow::builder().title("Diretto").visible(false).build();
        let proxy_row = adw::ActionRow::builder()
            .title("Via proxy")
            .visible(false)
            .build();
        let suggest = gtk::Button::builder()
            .label("Aggiungi alle eccezioni")
            .valign(gtk::Align::Center)
            .visible(false)
            .build();
        proxy_row.add_suffix(&suggest);
        test.add(&url);
        test.add(&direct_row);
        test.add(&proxy_row);

        page.add(&mode_group);
        page.add(&exceptions);
        page.add(&test);

        ProxyPage {
            page,
            mode,
            syncing: Cell::new(false),
            exceptions,
            add_row,
            apply,
            revert,
            draft: RefCell::new(None),
            rows: RefCell::new(Vec::new()),
            url,
            direct_row,
            proxy_row,
            suggest,
        }
    }

    pub fn connect(&self, app: &Rc<App>) {
        let a = app.clone();
        self.mode.connect_active_name_notify(move |g| {
            if a.proxy_page.syncing.get() {
                return;
            }
            let mode = match g.active_name().as_deref() {
                Some("on") => ProxyMode::On,
                Some("off") => ProxyMode::Off,
                _ => ProxyMode::Auto,
            };
            let a = a.clone();
            glib::spawn_future_local(async move {
                if let Some(r) = app::run_helper(&a, &Action::SetMode { mode }).await {
                    let text = match mode {
                        ProxyMode::Auto => "Modalità automatica",
                        ProxyMode::On => "Forzato: sempre proxy aziendale",
                        ProxyMode::Off => "Forzato: sempre diretto",
                    };
                    app::show_report(&a, text, &r).await;
                }
                app::refresh(&a);
            });
        });

        let a = app.clone();
        self.add_row.connect_apply(move |row| {
            let host = row.text().trim().to_string();
            if !validate::is_direct_rule(&host) {
                app::toast(&a, &format!("«{host}» non è un host, un .dominio o una rete"));
                return;
            }
            let mut rules = a.proxy_page.current(&a);
            if rules.iter().any(|r| r.host() == host) {
                app::toast(&a, "È già tra le eccezioni");
                return;
            }
            rules.push(DirectRule::Host(host));
            a.proxy_page.draft.replace(Some(rules));
            row.set_text("");
            a.proxy_page.render(&a);
        });

        let a = app.clone();
        self.revert.connect_clicked(move |_| {
            a.proxy_page.draft.replace(None);
            a.proxy_page.render(&a);
        });

        let a = app.clone();
        self.apply.connect_clicked(move |_| {
            let Some(rules) = a.proxy_page.draft.borrow().clone() else {
                return;
            };
            let Some(mut profile) = a.profile.borrow().clone() else {
                return;
            };
            profile.proxy.direct = rules;
            let a = a.clone();
            glib::spawn_future_local(async move {
                if let Some(r) = app::run_helper(&a, &Action::ApplyProxy { profile }).await {
                    if !r.failed() {
                        a.proxy_page.draft.replace(None);
                    }
                    app::show_report(&a, "Eccezioni applicate", &r).await;
                }
                app::refresh(&a);
            });
        });

        let a = app.clone();
        self.url.connect_apply(move |row| {
            let url = row.text().trim().to_string();
            if !nettest::valid_url(&url) {
                app::toast(&a, "Serve un indirizzo che inizia con http:// o https://");
                return;
            }
            let port = a.profile.borrow().as_ref().map_or(8118, |p| p.proxy.local_port);
            let page = &a.proxy_page;
            for r in [&page.direct_row, &page.proxy_row] {
                r.set_visible(true);
                r.set_subtitle("in corso…");
            }
            page.suggest.set_visible(false);
            let a = a.clone();
            glib::spawn_future_local(async move {
                let u = url.clone();
                let Ok(t) = gio::spawn_blocking(move || nettest::test_url(&u, port)).await else {
                    return;
                };
                let page = &a.proxy_page;
                page.direct_row.set_subtitle(&describe(&t.direct));
                page.proxy_row.set_subtitle(&describe(&t.proxy));
                let only_direct = t.direct.code.is_some() && matches!(t.proxy.code, Some(502..=504) | None);
                page.suggest
                    .set_visible(only_direct && a.profile.borrow().is_some());
                page.suggest.set_tooltip_text(host_of(&url).as_deref());
            });
        });

        let a = app.clone();
        self.suggest.connect_clicked(move |b| {
            let Some(host) = b.tooltip_text() else { return };
            a.proxy_page.add_row.set_text(&host);
            a.proxy_page.add_row.emit_by_name::<()>("apply", &[]);
            b.set_visible(false);
        });
    }

    /// Le eccezioni mostrate: la bozza se c'è, altrimenti quelle del profilo.
    fn current(&self, app: &App) -> Vec<DirectRule> {
        if let Some(d) = self.draft.borrow().as_ref() {
            return d.clone();
        }
        app.profile
            .borrow()
            .as_ref()
            .map(|p| p.proxy.direct.clone())
            .unwrap_or_default()
    }

    pub fn update(&self, app: &Rc<App>, st: &Status) {
        self.syncing.set(true);
        self.mode
            .set_active_name(Some(st.forced.map_or("auto", ProxyMode::as_str)));
        self.syncing.set(false);
        let configured = app.profile.borrow().is_some();
        self.mode.set_sensitive(configured || st.legacy);
        self.exceptions.set_sensitive(configured);
        self.render(app);
    }

    fn render(&self, app: &Rc<App>) {
        for r in self.rows.take() {
            self.exceptions.remove(&r);
        }
        let rules = self.current(app);
        let dirty = self.draft.borrow().is_some();
        self.apply.set_visible(dirty);
        self.revert.set_visible(dirty);
        let mut rows = Vec::new();
        for (i, rule) in rules.iter().enumerate() {
            let row = adw::ActionRow::builder().title(rule.host()).build();
            if let Some(note) = rule.note() {
                row.set_subtitle(&note.split_whitespace().collect::<Vec<_>>().join(" "));
                row.set_subtitle_lines(2);
            }
            let remove = gtk::Button::builder()
                .icon_name("user-trash-symbolic")
                .tooltip_text("Togli")
                .valign(gtk::Align::Center)
                .css_classes(["flat"])
                .build();
            let a = app.clone();
            remove.connect_clicked(move |_| {
                let mut rules = a.proxy_page.current(&a);
                rules.remove(i);
                a.proxy_page.draft.replace(Some(rules));
                a.proxy_page.render(&a);
            });
            row.add_suffix(&remove);
            // le righe vanno prima di quella per aggiungere
            self.exceptions.add(&row);
            rows.push(row);
        }
        self.exceptions.remove(&self.add_row);
        self.exceptions.add(&self.add_row);
        self.rows.replace(rows);
    }
}

fn describe(p: &nettest::Probe) -> String {
    match (p.code, &p.error) {
        (Some(c), _) => format!("HTTP {c} in {:.2} s", p.seconds),
        (None, Some(e)) => format!("nessuna risposta: {e}"),
        (None, None) => "nessuna risposta".into(),
    }
}

/// L'host di un URL http(s), per proporlo come eccezione.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn host_dall_url() {
        assert_eq!(
            host_of("https://www.Esempio.it:8443/a?b").as_deref(),
            Some("www.esempio.it")
        );
        assert_eq!(
            host_of("http://u@intranet.corp.esempio").as_deref(),
            Some("intranet.corp.esempio")
        );
        assert_eq!(host_of("nonunurl"), None);
    }
}
