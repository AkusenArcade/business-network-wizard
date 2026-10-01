//! Pagina Stato: dove va il traffico e perché, servizi, connessioni aziendali.

use std::rc::Rc;

use adw::prelude::*;
use bnw_client::status;
use bnw_core::action::ProxyMode;
use bnw_core::status::{Connection, Route, Status, service_label};
use gtk::{gio, glib};

use crate::app::App;

pub struct StatusPage {
    pub page: adw::PreferencesPage,
    route: adw::ActionRow,
    mode: adw::ActionRow,
    decision: adw::ActionRow,
    detect: adw::ActionRow,
    detect_button: gtk::Button,
    tinyproxy: adw::ActionRow,
    cntlm: adw::ActionRow,
    vpn: adw::ActionRow,
    wifi: adw::ActionRow,
    connections: adw::PreferencesGroup,
}

fn row(title: &str) -> adw::ActionRow {
    let r = adw::ActionRow::builder()
        .title(title)
        .subtitle_selectable(true)
        .build();
    r.add_css_class("property");
    r
}

impl StatusPage {
    pub fn new() -> Self {
        let page = adw::PreferencesPage::new();

        let proxy = adw::PreferencesGroup::builder().title("Proxy").build();
        let route = row("Traffico web");
        let mode = row("Modalità");
        let decision = row("Ultima rilevazione");
        let detect = adw::ActionRow::builder()
            .title("Rileva la rete adesso")
            .subtitle("Controlla VPN e proxy aziendale senza cambiare niente")
            .build();
        let detect_button = gtk::Button::builder()
            .label("Rileva")
            .valign(gtk::Align::Center)
            .build();
        detect.add_suffix(&detect_button);
        for r in [&route, &mode, &decision, &detect] {
            proxy.add(r);
        }

        let services = adw::PreferencesGroup::builder()
            .title("Servizi")
            .description("tinyproxy è sempre acceso; cntlm si accende solo sulla rete aziendale")
            .build();
        let tinyproxy = row("tinyproxy (proxy locale)");
        let cntlm = row("cntlm (autenticazione NTLM)");
        services.add(&tinyproxy);
        services.add(&cntlm);

        let connections = adw::PreferencesGroup::builder()
            .title("Connessioni aziendali")
            .build();
        let vpn = row("VPN");
        let wifi = row("WiFi");
        connections.add(&vpn);
        connections.add(&wifi);

        page.add(&proxy);
        page.add(&services);
        page.add(&connections);

        StatusPage {
            page,
            route,
            mode,
            decision,
            detect,
            detect_button,
            tinyproxy,
            cntlm,
            vpn,
            wifi,
            connections,
        }
    }

    pub fn connect(&self, app: &Rc<App>) {
        let app = app.clone();
        self.detect_button.connect_clicked(move |b| {
            b.set_sensitive(false);
            app.status_page.detect.set_subtitle("Rilevazione in corso…");
            let app = app.clone();
            let b = b.clone();
            glib::spawn_future_local(async move {
                let env = app.env.clone();
                let result = gio::spawn_blocking(move || status::detect_now(&env)).await;
                let text = match result {
                    Ok(Ok(t)) => t,
                    Ok(Err(e)) => format!("non riuscita: {e}"),
                    Err(_) => "non riuscita".into(),
                };
                app.status_page.detect.set_subtitle(&text);
                b.set_sensitive(true);
            });
        });
    }

    pub fn update(&self, st: &Status) {
        self.route.set_subtitle(match st.route {
            Some(Route::Upstream) => "Attraverso il proxy aziendale",
            Some(Route::Direct) => "Diretto",
            None => "Sconosciuto (tinyproxy non configurato?)",
        });
        self.mode.set_subtitle(match st.forced {
            None => "Automatica: proxy aziendale se la VPN è attiva o se il proxy risponde",
            Some(ProxyMode::On) => "Forzata: sempre proxy aziendale, fino a «Automatica» o al riavvio",
            Some(ProxyMode::Off) => "Forzata: sempre diretto, fino a «Automatica» o al riavvio",
            Some(ProxyMode::Auto) => "Automatica",
        });
        self.decision
            .set_subtitle(st.last_decision.as_deref().unwrap_or("nessuna nel journal"));
        set_service(&self.tinyproxy, st.tinyproxy.as_deref(), true);
        set_service(
            &self.cntlm,
            st.cntlm.as_deref(),
            st.route == Some(Route::Upstream),
        );
        set_connection(&self.vpn, st.vpn.as_ref());
        set_connection(&self.wifi, st.wifi.as_ref());
        self.connections
            .set_visible(st.vpn.is_some() || st.wifi.is_some());
    }
}

/// Stato di un servizio, con un segno di errore se non è come dovrebbe.
fn set_service(row: &adw::ActionRow, state: Option<&str>, should_run: bool) {
    row.set_subtitle(service_label(state));
    let wrong = state == Some("failed") || (should_run && state != Some("active"));
    if wrong {
        row.add_css_class("error");
    } else {
        row.remove_css_class("error");
    }
}

fn set_connection(row: &adw::ActionRow, c: Option<&Connection>) {
    row.set_visible(c.is_some());
    if let Some(c) = c {
        row.set_subtitle(&format!(
            "{}: {}",
            c.name,
            if c.active { "connessa" } else { "non connessa" }
        ));
    }
}
