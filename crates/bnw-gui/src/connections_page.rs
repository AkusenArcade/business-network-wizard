//! Pagina Connessioni: la VPN e il WiFi aziendale del profilo.

use std::cell::Cell;
use std::rc::Rc;

use adw::prelude::*;
use bnw_core::Blob;
use bnw_core::action::Action;
use bnw_core::status::Status;
use gtk::{gio, glib};

use crate::app::{self, App};

pub struct ConnectionsPage {
    pub page: adw::PreferencesPage,
    vpn: adw::PreferencesGroup,
    vpn_switch: gtk::Switch,
    vpn_row: adw::ActionRow,
    vpn_import: gtk::Button,
    vpn_check: gtk::Button,
    wifi: adw::PreferencesGroup,
    wifi_switch: gtk::Switch,
    wifi_row: adw::ActionRow,
    wifi_auto: adw::SwitchRow,
    wifi_ca_row: adw::ActionRow,
    wifi_ca: gtk::Button,
    wifi_check: gtk::Button,
    /// Mentre si aggiornano gli interruttori dallo stato, i cambi non sono dell'utente.
    syncing: Cell<bool>,
}

fn button(label: &str) -> gtk::Button {
    gtk::Button::builder()
        .label(label)
        .valign(gtk::Align::Center)
        .build()
}

fn row_with(title: &str, subtitle: &str, b: &gtk::Button) -> adw::ActionRow {
    let r = adw::ActionRow::builder().title(title).subtitle(subtitle).build();
    r.add_suffix(b);
    r
}

impl ConnectionsPage {
    pub fn new() -> Self {
        let page = adw::PreferencesPage::new();

        let vpn = adw::PreferencesGroup::builder().title("VPN").build();
        let vpn_switch = gtk::Switch::builder().valign(gtk::Align::Center).build();
        let vpn_row = adw::ActionRow::builder().title("Connessione").build();
        vpn_row.add_suffix(&vpn_switch);
        vpn_row.set_activatable_widget(Some(&vpn_switch));
        let vpn_import = button("Scegli…");
        let vpn_check = button("Ricontrolla");
        vpn.add(&vpn_row);
        vpn.add(&row_with(
            "Reimporta da un file .ovpn",
            "Per un certificato nuovo: la password salvata resta",
            &vpn_import,
        ));
        vpn.add(&row_with(
            "Impostazioni",
            "Corregge quello che l'importatore sbaglia (secret agent, ns-cert-type, full-tunnel)",
            &vpn_check,
        ));

        let wifi = adw::PreferencesGroup::builder().title("WiFi aziendale").build();
        let wifi_switch = gtk::Switch::builder().valign(gtk::Align::Center).build();
        let wifi_row = adw::ActionRow::builder().title("Connessione").build();
        wifi_row.add_suffix(&wifi_switch);
        wifi_row.set_activatable_widget(Some(&wifi_switch));
        let wifi_auto = adw::SwitchRow::builder()
            .title("Connessione automatica")
            .subtitle("Si collega da solo quando la rete è in vista")
            .build();
        let wifi_ca = button("Sostituisci…");
        let wifi_ca_row = row_with("CA del RADIUS", "", &wifi_ca);
        wifi_ca_row.add_css_class("property");
        let wifi_check = button("Ricontrolla");
        wifi.add(&wifi_row);
        wifi.add(&wifi_auto);
        wifi.add(&wifi_ca_row);
        wifi.add(&row_with(
            "Impostazioni",
            "PEAP/MSCHAPv2, CA e domain-suffix-match del profilo",
            &wifi_check,
        ));

        page.add(&vpn);
        page.add(&wifi);
        ConnectionsPage {
            page,
            vpn,
            vpn_switch,
            vpn_row,
            vpn_import,
            vpn_check,
            wifi,
            wifi_switch,
            wifi_row,
            wifi_auto,
            wifi_ca_row,
            wifi_ca,
            wifi_check,
            syncing: Cell::new(false),
        }
    }

    pub fn connect(&self, app: &Rc<App>) {
        for vpn in [true, false] {
            let sw = if vpn { &self.vpn_switch } else { &self.wifi_switch };
            let a = app.clone();
            sw.connect_active_notify(move |sw| {
                if a.connections_page.syncing.get() {
                    return;
                }
                let up = sw.is_active();
                sw.set_sensitive(false);
                glib::spawn_future_local(toggle(a.clone(), vpn, up, sw.clone()));
            });
        }

        let a = app.clone();
        self.vpn_check.connect_clicked(move |_| {
            let a = a.clone();
            glib::spawn_future_local(async move {
                let Some(p) = a.profile.borrow().clone() else {
                    return;
                };
                let action = Action::ApplyVpn {
                    profile: p,
                    ovpn: None,
                    reimport: false,
                    domain_user: None,
                    password: None,
                };
                run(&a, &action, "VPN ricontrollata").await;
            });
        });
        let a = app.clone();
        self.vpn_import.connect_clicked(move |_| {
            let a = a.clone();
            glib::spawn_future_local(async move {
                let Some(data) =
                    choose_file(&a, "Scegli il file .ovpn", "*.ovpn", "Profilo OpenVPN (.ovpn)").await
                else {
                    return;
                };
                let Some(p) = a.profile.borrow().clone() else {
                    return;
                };
                let action = Action::ApplyVpn {
                    profile: p,
                    ovpn: Some(Blob(data)),
                    reimport: true,
                    domain_user: None,
                    password: None,
                };
                run(&a, &action, "VPN reimportata").await;
            });
        });

        let a = app.clone();
        self.wifi_check.connect_clicked(move |_| {
            let a = a.clone();
            glib::spawn_future_local(async move {
                let Some(p) = a.profile.borrow().clone() else {
                    return;
                };
                run(
                    &a,
                    &Action::ApplyWifi {
                        profile: p,
                        ca: None,
                        domain_user: None,
                        password: None,
                    },
                    "WiFi ricontrollato",
                )
                .await;
            });
        });
        let a = app.clone();
        self.wifi_ca.connect_clicked(move |_| {
            let a = a.clone();
            glib::spawn_future_local(async move {
                let Some(data) = choose_file(&a, "Scegli la CA del RADIUS", "*.pem", "Certificato PEM").await
                else {
                    return;
                };
                let Some(p) = a.profile.borrow().clone() else {
                    return;
                };
                let action = Action::ApplyWifi {
                    profile: p,
                    ca: Some(Blob(data)),
                    domain_user: None,
                    password: None,
                };
                run(&a, &action, "CA del WiFi sostituita").await;
            });
        });
        let a = app.clone();
        self.wifi_auto.connect_active_notify(move |row| {
            if a.connections_page.syncing.get() {
                return;
            }
            let on = row.is_active();
            let a = a.clone();
            glib::spawn_future_local(async move {
                let Some(mut p) = a.profile.borrow().clone() else {
                    return;
                };
                if let Some(w) = p.wifi.as_mut() {
                    w.autoconnect = on;
                }
                let text = if on {
                    "Connessione automatica attiva"
                } else {
                    "Connessione automatica disattivata"
                };
                run(
                    &a,
                    &Action::ApplyWifi {
                        profile: p,
                        ca: None,
                        domain_user: None,
                        password: None,
                    },
                    text,
                )
                .await;
            });
        });
    }

    pub fn update(&self, app: &App, st: &Status) {
        let profile = app.profile.borrow();
        self.page.set_sensitive(profile.is_some());
        self.syncing.set(true);
        let vpn = profile.as_ref().and_then(|p| p.vpn.as_ref());
        self.vpn.set_visible(vpn.is_some());
        if let Some(v) = vpn {
            self.vpn.set_title(&format!("VPN «{}»", v.name));
            let on = st.vpn.as_ref().is_some_and(|c| c.active);
            self.vpn_switch.set_active(on);
            self.vpn_row
                .set_subtitle(if on { "connessa" } else { "non connessa" });
        }
        let wifi = profile.as_ref().and_then(|p| p.wifi.as_ref());
        self.wifi.set_visible(wifi.is_some());
        if let Some(w) = wifi {
            self.wifi.set_title(&format!("WiFi aziendale «{}»", w.ssid));
            let on = st.wifi.as_ref().is_some_and(|c| c.active);
            self.wifi_switch.set_active(on);
            self.wifi_row
                .set_subtitle(if on { "connesso" } else { "non connesso" });
            self.wifi_auto.set_active(w.autoconnect);
            self.wifi_ca_row.set_subtitle(&format!(
                "fingerprint SHA-1 {}",
                w.ca_sha1.as_deref().unwrap_or("non indicato nel profilo")
            ));
        }
        self.syncing.set(false);
    }
}

async fn run(app: &Rc<App>, action: &Action, ok: &str) {
    if let Some(r) = app::run_helper(app, action).await {
        app::show_report(app, ok, &r).await;
    }
    app::refresh(app);
}

async fn choose_file(app: &App, title: &str, pattern: &str, label: &str) -> Option<Vec<u8>> {
    let f = gtk::FileFilter::new();
    f.set_name(Some(label));
    f.add_pattern(pattern);
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&f);
    let d = gtk::FileDialog::builder()
        .title(title)
        .filters(&filters)
        .modal(true)
        .build();
    let file = d.open_future(Some(&app.window)).await.ok()?;
    match file.load_contents_future().await {
        Ok((bytes, _)) => Some(bytes.to_vec()),
        Err(e) => {
            app::show_message(app, "File illeggibile", &e.to_string()).await;
            None
        }
    }
}

/// Connette o disconnette come utente (nmcli): NetworkManager usa i segreti salvati.
async fn toggle(app: Rc<App>, vpn: bool, up: bool, sw: gtk::Switch) {
    let name = app.profile.borrow().as_ref().and_then(|p| {
        if vpn {
            p.vpn.as_ref().map(|v| v.name.clone())
        } else {
            p.wifi.as_ref().map(|w| w.name.clone())
        }
    });
    if let Some(name) = name {
        let verb = if up { "up" } else { "down" };
        let argv = ["nmcli", "connection", verb, "id", name.as_str()];
        let argv: Vec<&std::ffi::OsStr> = argv.iter().map(|s| s.as_ref()).collect();
        if let Ok(proc) = gio::Subprocess::newv(
            &argv,
            gio::SubprocessFlags::STDOUT_SILENCE | gio::SubprocessFlags::STDERR_PIPE,
        ) {
            let result = proc.communicate_utf8_future(None).await;
            if !proc.is_successful() {
                let err = result
                    .ok()
                    .and_then(|(_, e)| e)
                    .map(|e| e.to_string())
                    .unwrap_or_default();
                let what = if vpn { "La VPN" } else { "Il WiFi" };
                let heading = if up {
                    format!("{what} non si connette")
                } else {
                    format!("{what} non si disconnette")
                };
                app::show_message(&app, &heading, err.trim()).await;
            }
        }
    }
    sw.set_sensitive(true);
    app::refresh(&app);
}
