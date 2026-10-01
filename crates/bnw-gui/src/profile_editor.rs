//! «Modifica profilo aziendale»: un editor completo del profilo `.bnw`, per prepararne
//! uno nuovo (per esempio quando l'azienda cambia dominio) senza scrivere TOML a mano.
//! Si parte dal profilo applicato, da un `.bnw` o da zero; si salva come `.bnw` cifrato
//! o si applica a questa macchina. Gli errori si vedono mentre si scrive, con la stessa
//! validazione che usa l'helper.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use bnw_client::{bundle as cb, user};
use bnw_core::bundle::{Bundle, MIN_PASSPHRASE, ovpn_inline, pem_sha1};
use bnw_core::profile::{Browser, DirectRule, Eap, Printer, Share, Vpn, Wifi};
use bnw_core::validate;
use gtk::{gio, glib};

use crate::app::{self, App};

/// Il profilo in modifica e i pezzi dell'interfaccia che dipendono da lui.
struct Ed {
    app: Rc<App>,
    dialog: adw::Dialog,
    model: RefCell<Bundle>,
    errors: adw::PreferencesGroup,
    errors_label: gtk::Label,
    save: gtk::Button,
    apply: gtk::Button,
    direct: adw::PreferencesGroup,
    direct_rows: RefCell<Vec<gtk::Widget>>,
    direct_add: adw::EntryRow,
    shares: adw::PreferencesGroup,
    share_rows: RefCell<Vec<gtk::Widget>>,
    share_add: adw::EntryRow,
    printers: adw::PreferencesGroup,
    printer_rows: RefCell<Vec<gtk::Widget>>,
    printer_add: adw::EntryRow,
    vpn_fields: RefCell<Vec<gtk::Widget>>,
    wifi_fields: RefCell<Vec<gtk::Widget>>,
    ovpn_row: adw::ActionRow,
    ca_row: adw::ActionRow,
    /// Mentre si costruisce l'interfaccia i "changed" non sono dell'utente.
    building: Cell<bool>,
}

pub fn open(app: &Rc<App>) {
    let app = app.clone();
    glib::spawn_future_local(async move {
        // solo per le schermate di sviluppo: si parte dal profilo applicato
        let bundle = if std::env::var_os("BNW_SCREENSHOT").is_some() {
            let env = app.env.clone();
            gio::spawn_blocking(move || cb::from_installed(&env, &glib::home_dir()))
                .await
                .ok()
                .flatten()
        } else {
            choose_source(&app).await
        };
        let Some(bundle) = bundle else { return };
        show(&app, bundle);
    });
}

async fn choose_source(app: &Rc<App>) -> Option<Bundle> {
    let d = adw::AlertDialog::new(
        Some("Modifica profilo aziendale"),
        Some(
            "Da dove partire? Si può salvare come file .bnw senza toccare questa macchina, oppure applicarlo.",
        ),
    );
    d.add_response("cancel", "Annulla");
    d.add_response("empty", "Vuoto");
    d.add_response("file", "Da un .bnw…");
    d.add_response("installed", "Profilo applicato");
    d.set_response_appearance("installed", adw::ResponseAppearance::Suggested);
    d.set_close_response("cancel");
    d.set_response_enabled("installed", app.profile.borrow().is_some());
    match d.choose_future(Some(&app.window)).await.as_str() {
        "installed" => {
            let env = app.env.clone();
            gio::spawn_blocking(move || cb::from_installed(&env, &glib::home_dir()))
                .await
                .ok()
                .flatten()
        }
        "file" => open_bnw(app).await,
        "empty" => Some(cb::empty()),
        _ => None,
    }
}

/// Un `.bnw` esistente, con la sua passphrase.
async fn open_bnw(app: &Rc<App>) -> Option<Bundle> {
    let f = gtk::FileFilter::new();
    f.set_name(Some("Profilo aziendale (.bnw)"));
    f.add_pattern("*.bnw");
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&f);
    let fd = gtk::FileDialog::builder().filters(&filters).modal(true).build();
    let file = fd.open_future(Some(&app.window)).await.ok()?;
    let (bytes, _) = file.load_contents_future().await.ok()?;
    let data = bytes.to_vec();
    let mut retry = false;
    loop {
        let row = adw::PasswordEntryRow::builder().title("Passphrase").build();
        let group = adw::PreferencesGroup::new();
        group.add(&row);
        let body = if retry {
            "Passphrase sbagliata, riprova."
        } else {
            "La passphrase del file."
        };
        let d = adw::AlertDialog::new(Some("Apri il profilo"), Some(body));
        d.set_extra_child(Some(&group));
        d.add_response("cancel", "Annulla");
        d.add_response("open", "Apri");
        d.set_response_appearance("open", adw::ResponseAppearance::Suggested);
        d.set_default_response(Some("open"));
        d.set_close_response("cancel");
        if d.choose_future(Some(&app.window)).await != "open" {
            return None;
        }
        let (pass, d2) = (row.text().to_string(), data.clone());
        row.set_text("");
        match gio::spawn_blocking(move || Bundle::decrypt(&d2, &pass)).await {
            Ok(Ok(b)) => return Some(b),
            Ok(Err(bnw_core::bundle::BundleError::Decrypt)) => retry = true,
            Ok(Err(e)) => {
                app::show_message(app, "Profilo non valido", &e.to_string()).await;
                return None;
            }
            Err(_) => return None,
        }
    }
}

fn group(title: &str, description: &str) -> adw::PreferencesGroup {
    adw::PreferencesGroup::builder()
        .title(title)
        .description(description)
        .build()
}

fn show(app: &Rc<App>, bundle: Bundle) {
    let page = adw::PreferencesPage::new();

    let errors = adw::PreferencesGroup::new();
    let errors_label = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["error"])
        .build();
    errors.add(&errors_label);
    page.add(&errors);

    let save = gtk::Button::builder()
        .label("Salva come .bnw…")
        .css_classes(["suggested-action"])
        .build();
    let apply = gtk::Button::builder().label("Applica a questa macchina…").build();

    // --- azienda -------------------------------------------------------------------
    let company = group(
        "Azienda",
        "Il dominio è quello NTLM (NetBIOS) usato dal proxy e dai dischi di rete.",
    );
    page.add(&company);
    // --- proxy ---------------------------------------------------------------------
    let proxy = group(
        "Proxy",
        "Il proxy aziendale a cui cntlm inoltra le richieste, autenticandole.",
    );
    page.add(&proxy);
    let direct = group(
        "Eccezioni",
        "Destinazioni raggiunte senza il proxy aziendale: host, «.dominio» (tutti i sottodomini) o reti come 10.0.0.0/8.",
    );
    let direct_add = adw::EntryRow::builder()
        .title("Aggiungi un'eccezione")
        .show_apply_button(true)
        .build();
    page.add(&direct);
    // --- VPN e WiFi ----------------------------------------------------------------
    let vpn = group(
        "VPN",
        "Il file .ovpn deve contenere la chiave privata (&lt;key&gt;): il profilo è cifrato per questo.",
    );
    page.add(&vpn);
    let wifi = group(
        "WiFi aziendale",
        "802.1X con la CA del RADIUS: il fingerprint si calcola dal file scelto.",
    );
    page.add(&wifi);
    // --- dischi e stampanti --------------------------------------------------------
    let shares = group(
        "Dischi di rete",
        r"Scrivi \\server\cartella (o //server/cartella): si monterà in /mnt/&lt;cartella&gt;.",
    );
    let share_add = adw::EntryRow::builder()
        .title(r"Aggiungi: \\server\cartella")
        .show_apply_button(true)
        .build();
    page.add(&shares);
    let printers = group(
        "Stampanti",
        "Scrivi «NOME indirizzo», per esempio «STAMPA_P1 stampante.corp.esempio»: driverless IPP.",
    );
    let printer_add = adw::EntryRow::builder()
        .title("Aggiungi: NOME indirizzo")
        .show_apply_button(true)
        .build();
    page.add(&printers);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&page));
    let bottom = gtk::Box::builder()
        .spacing(12)
        .halign(gtk::Align::End)
        .margin_top(12)
        .margin_bottom(12)
        .margin_end(12)
        .build();
    bottom.append(&apply);
    bottom.append(&save);
    toolbar.add_bottom_bar(&bottom);
    let dialog = adw::Dialog::builder()
        .title("Profilo aziendale")
        .content_width(760)
        .content_height(860)
        .child(&toolbar)
        .build();

    let ovpn_row = adw::ActionRow::builder().title("File .ovpn").build();
    let ca_row = adw::ActionRow::builder().title("CA del RADIUS").build();
    ca_row.add_css_class("property");

    let ed = Rc::new(Ed {
        app: app.clone(),
        dialog: dialog.clone(),
        model: RefCell::new(bundle),
        errors,
        errors_label,
        save: save.clone(),
        apply: apply.clone(),
        direct,
        direct_rows: RefCell::default(),
        direct_add,
        shares,
        share_rows: RefCell::default(),
        share_add,
        printers,
        printer_rows: RefCell::default(),
        printer_add,
        vpn_fields: RefCell::default(),
        wifi_fields: RefCell::default(),
        ovpn_row,
        ca_row,
        building: Cell::new(true),
    });
    build_fields(&ed, &company, &proxy, &vpn, &wifi);

    let e = ed.clone();
    save.connect_clicked(move |_| {
        glib::spawn_future_local(save_bnw(e.clone()));
    });
    let e = ed.clone();
    apply.connect_clicked(move |_| {
        glib::spawn_future_local(apply_here(e.clone()));
    });
    ed.building.set(false);
    ed.render_lists();
    ed.revalidate();
    dialog.present(Some(&app.window));
}

/// Una riga di testo legata a un campo del profilo.
fn entry(
    ed: &Rc<Ed>,
    title: &str,
    value: &str,
    set: impl Fn(&mut Bundle, String) + 'static,
) -> adw::EntryRow {
    let row = adw::EntryRow::builder().title(title).text(value).build();
    let e = Rc::downgrade(ed);
    row.connect_changed(move |r| {
        if let Some(ed) = e.upgrade()
            && !ed.building.get()
        {
            set(&mut ed.model.borrow_mut(), r.text().trim().to_string());
            ed.revalidate();
        }
    });
    row
}

fn switch(
    ed: &Rc<Ed>,
    title: &str,
    subtitle: &str,
    value: bool,
    set: impl Fn(&Rc<Ed>, bool) + 'static,
) -> adw::SwitchRow {
    let row = adw::SwitchRow::builder()
        .title(title)
        .subtitle(subtitle)
        .active(value)
        .build();
    let e = Rc::downgrade(ed);
    row.connect_active_notify(move |r| {
        if let Some(ed) = e.upgrade()
            && !ed.building.get()
        {
            set(&ed, r.is_active());
            ed.revalidate();
        }
    });
    row
}

fn port(ed: &Rc<Ed>, title: &str, value: u16, set: impl Fn(&mut Bundle, u16) + 'static) -> adw::SpinRow {
    let row = adw::SpinRow::with_range(1.0, 65535.0, 1.0);
    row.set_title(title);
    row.set_value(value as f64);
    let e = Rc::downgrade(ed);
    row.connect_value_notify(move |r| {
        if let Some(ed) = e.upgrade()
            && !ed.building.get()
        {
            set(&mut ed.model.borrow_mut(), r.value() as u16);
            ed.revalidate();
        }
    });
    row
}

/// Testo facoltativo: vuoto = assente.
fn opt(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

fn build_fields(
    ed: &Rc<Ed>,
    company: &adw::PreferencesGroup,
    proxy: &adw::PreferencesGroup,
    vpn_group: &adw::PreferencesGroup,
    wifi_group: &adw::PreferencesGroup,
) {
    let p = ed.model.borrow().profile.clone();

    company.add(&entry(ed, "Nome", &p.company.name, |b, v| {
        b.profile.company.name = v
    }));
    company.add(&entry(ed, "Dominio (es. CORP)", &p.company.domain, |b, v| {
        b.profile.company.domain = v
    }));
    company.add(&entry(
        ed,
        "Esempio di utenza (facoltativo)",
        p.company.user_hint.as_deref().unwrap_or(""),
        |b, v| b.profile.company.user_hint = opt(v),
    ));

    proxy.add(&entry(
        ed,
        "Proxy aziendali (host:porta, separati da virgola)",
        &p.proxy.upstream.join(", "),
        |b, v| {
            b.profile.proxy.upstream = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        },
    ));
    proxy.add(&port(
        ed,
        "Porta locale (tinyproxy)",
        p.proxy.local_port,
        |b, v| b.profile.proxy.local_port = v,
    ));
    proxy.add(&port(ed, "Porta di cntlm", p.proxy.cntlm_port, |b, v| {
        b.profile.proxy.cntlm_port = v
    }));
    for (browser, label) in [(Browser::Firefox, "Firefox"), (Browser::Zen, "Zen")] {
        let on = p.proxy.browsers.contains(&browser);
        proxy.add(&switch(
            ed,
            &format!("Proxy per {label}"),
            "con le policy di sistema",
            on,
            move |ed, v| {
                let list = &mut ed.model.borrow_mut().profile.proxy.browsers;
                list.retain(|b| *b != browser);
                if v {
                    list.push(browser);
                }
            },
        ));
    }
    proxy.add(&entry(
        ed,
        "URL del PAC (solo documentazione, facoltativo)",
        p.proxy.pac.as_deref().unwrap_or(""),
        |b, v| b.profile.proxy.pac = opt(v),
    ));
    proxy.add(&entry(
        ed,
        "URL per provare il proxy (facoltativo)",
        p.proxy.check_url.as_deref().unwrap_or(""),
        |b, v| b.profile.proxy.check_url = opt(v),
    ));

    // --- VPN -----------------------------------------------------------------------
    let v = p.vpn.clone().unwrap_or(Vpn {
        name: String::new(),
        file: String::new(),
        full_tunnel: true,
    });
    let vpn_name = entry(ed, "Nome della connessione", &v.name, |b, val| {
        if let Some(v) = b.profile.vpn.as_mut() {
            v.name = val;
        }
    });
    let full = switch(
        ed,
        "Tutto il traffico in VPN",
        "full-tunnel",
        v.full_tunnel,
        |ed, val| {
            if let Some(v) = ed.model.borrow_mut().profile.vpn.as_mut() {
                v.full_tunnel = val;
            }
        },
    );
    let choose_ovpn = gtk::Button::builder()
        .label("Scegli…")
        .valign(gtk::Align::Center)
        .build();
    ed.ovpn_row.add_suffix(&choose_ovpn);
    let name_for_toggle = vpn_name.clone();
    let enable = switch(
        ed,
        "VPN",
        "il profilo ha una VPN OpenVPN",
        p.vpn.is_some(),
        move |ed, on| {
            ed.model.borrow_mut().profile.vpn = on.then(|| Vpn {
                name: name_for_toggle.text().trim().to_string(),
                file: String::new(),
                full_tunnel: true,
            });
            ed.toggle(true, on);
        },
    );
    vpn_group.add(&enable);
    vpn_group.add(&vpn_name);
    vpn_group.add(&full);
    vpn_group.add(&ed.ovpn_row);
    let e = Rc::downgrade(ed);
    choose_ovpn.connect_clicked(move |_| {
        if let Some(ed) = e.upgrade() {
            glib::spawn_future_local(pick_file(ed, true));
        }
    });

    // --- WiFi ----------------------------------------------------------------------
    let w = p.wifi.clone().unwrap_or(Wifi {
        name: String::new(),
        ssid: String::new(),
        eap: Eap::Peap,
        phase2: Default::default(),
        ca: String::new(),
        ca_sha1: None,
        domain_suffix_match: String::new(),
        autoconnect: false,
    });
    let wifi_name = entry(ed, "Nome della connessione", &w.name, |b, v| {
        if let Some(w) = b.profile.wifi.as_mut() {
            w.name = v;
        }
    });
    let ssid = entry(ed, "SSID", &w.ssid, |b, v| {
        if let Some(w) = b.profile.wifi.as_mut() {
            w.ssid = v;
        }
    });
    let dsm = entry(
        ed,
        "Nome del server RADIUS (domain-suffix-match)",
        &w.domain_suffix_match,
        |b, v| {
            if let Some(w) = b.profile.wifi.as_mut() {
                w.domain_suffix_match = v;
            }
        },
    );
    let eap = adw::ComboRow::builder()
        .title("Metodo")
        .model(&gtk::StringList::new(&["PEAP / MSCHAPv2", "TTLS / MSCHAPv2"]))
        .selected(if w.eap == Eap::Ttls { 1 } else { 0 })
        .build();
    let e = Rc::downgrade(ed);
    eap.connect_selected_notify(move |c| {
        if let Some(ed) = e.upgrade()
            && !ed.building.get()
        {
            if let Some(w) = ed.model.borrow_mut().profile.wifi.as_mut() {
                w.eap = if c.selected() == 1 { Eap::Ttls } else { Eap::Peap };
            }
            ed.revalidate();
        }
    });
    let auto = switch(ed, "Connessione automatica", "", w.autoconnect, |ed, val| {
        if let Some(w) = ed.model.borrow_mut().profile.wifi.as_mut() {
            w.autoconnect = val;
        }
    });
    let choose_ca = gtk::Button::builder()
        .label("Scegli…")
        .valign(gtk::Align::Center)
        .build();
    ed.ca_row.add_suffix(&choose_ca);
    let (wn, ws, wd) = (wifi_name.clone(), ssid.clone(), dsm.clone());
    let enable = switch(
        ed,
        "WiFi aziendale",
        "il profilo ha un WiFi 802.1X",
        p.wifi.is_some(),
        move |ed, on| {
            ed.model.borrow_mut().profile.wifi = on.then(|| Wifi {
                name: wn.text().trim().to_string(),
                ssid: ws.text().trim().to_string(),
                eap: Eap::Peap,
                phase2: Default::default(),
                ca: String::new(),
                ca_sha1: None,
                domain_suffix_match: wd.text().trim().to_string(),
                autoconnect: false,
            });
            ed.toggle(false, on);
        },
    );
    wifi_group.add(&enable);
    for r in [
        wifi_name.upcast_ref::<gtk::Widget>(),
        ssid.upcast_ref(),
        eap.upcast_ref(),
        dsm.upcast_ref(),
        ed.ca_row.upcast_ref(),
        auto.upcast_ref(),
    ] {
        wifi_group.add(r);
    }
    let e = Rc::downgrade(ed);
    choose_ca.connect_clicked(move |_| {
        if let Some(ed) = e.upgrade() {
            glib::spawn_future_local(pick_file(ed, false));
        }
    });

    // i campi da accendere e spegnere con l'interruttore della sezione
    ed.vpn_fields.replace(vec![
        vpn_name.upcast(),
        full.upcast(),
        ed.ovpn_row.clone().upcast(),
    ]);
    ed.wifi_fields.replace(vec![
        wifi_name.upcast(),
        ssid.upcast(),
        eap.upcast(),
        dsm.upcast(),
        ed.ca_row.clone().upcast(),
        auto.upcast(),
    ]);
    ed.toggle(true, p.vpn.is_some());
    ed.toggle(false, p.wifi.is_some());
    connect_lists(ed);
}

impl Ed {
    fn toggle(&self, vpn: bool, on: bool) {
        let fields = if vpn {
            self.vpn_fields.borrow()
        } else {
            self.wifi_fields.borrow()
        };
        for f in fields.iter() {
            f.set_sensitive(on);
        }
    }

    /// Il profilo com'è adesso, con i file allineati.
    fn current(&self) -> Bundle {
        cb::normalize(self.model.borrow().clone())
    }

    fn revalidate(&self) {
        let b = self.current();
        let mut msgs: Vec<String> = match validate::profile(&b.profile) {
            Ok(()) => Vec::new(),
            Err(e) => e.iter().map(|e| e.to_string()).collect(),
        };
        let mut warnings = Vec::new();
        if msgs.is_empty() {
            match b.check() {
                Ok(w) => warnings = w,
                Err(e) => msgs.push(e.to_string()),
            }
        }
        let ok = msgs.is_empty();
        self.save.set_sensitive(ok);
        self.apply.set_sensitive(ok);
        let mut text = msgs.join("\n");
        for w in warnings {
            text += &format!("\n⚠ {w}");
        }
        self.errors_label.set_label(text.trim());
        self.errors.set_visible(!text.trim().is_empty());

        // i file: cosa c'è dentro, in breve
        let v = b.profile.vpn.as_ref().and_then(|v| b.files.get(&v.file));
        self.ovpn_row.set_subtitle(&match v {
            Some(d) if ovpn_inline(d, "key").is_some() => {
                format!("scelto ({} byte), con la chiave privata", d.len())
            }
            Some(d) => format!("scelto ({} byte), SENZA chiave privata", d.len()),
            None => "da scegliere".into(),
        });
        let ca = b.profile.wifi.as_ref().and_then(|w| w.ca_sha1.clone());
        self.ca_row.set_subtitle(
            &ca.map(|fp| format!("fingerprint {fp}"))
                .unwrap_or_else(|| "da scegliere".into()),
        );
    }

    fn render_lists(self: &Rc<Self>) {
        let b = self.model.borrow().clone();
        rerender(
            &self.direct,
            &self.direct_rows,
            &self.direct_add,
            b.profile.proxy.direct.iter().enumerate().map(|(i, r)| {
                let row = adw::ActionRow::builder().title(r.host()).build();
                if let Some(n) = r.note() {
                    row.set_subtitle(&n.split_whitespace().collect::<Vec<_>>().join(" "));
                    row.set_subtitle_lines(2);
                }
                (
                    row,
                    Box::new(move |b: &mut Bundle| drop(b.profile.proxy.direct.remove(i)))
                        as Box<dyn Fn(&mut Bundle)>,
                )
            }),
            self,
        );
        rerender(
            &self.shares,
            &self.share_rows,
            &self.share_add,
            b.profile.shares.iter().enumerate().map(|(i, s)| {
                let row = adw::ActionRow::builder()
                    .title(s.label())
                    .subtitle(format!("{} → {}", s.unc(), s.mount))
                    .build();
                (
                    row,
                    Box::new(move |b: &mut Bundle| drop(b.profile.shares.remove(i)))
                        as Box<dyn Fn(&mut Bundle)>,
                )
            }),
            self,
        );
        rerender(
            &self.printers,
            &self.printer_rows,
            &self.printer_add,
            b.profile.printers.iter().enumerate().map(|(i, p)| {
                let side = if p.duplex { "fronte-retro" } else { "solo fronte" };
                let row = adw::ActionRow::builder()
                    .title(&p.name)
                    .subtitle(format!("{}  ·  {side}", p.uri))
                    .build();
                (
                    row,
                    Box::new(move |b: &mut Bundle| drop(b.profile.printers.remove(i)))
                        as Box<dyn Fn(&mut Bundle)>,
                )
            }),
            self,
        );
    }
}

type Remove = Box<dyn Fn(&mut Bundle)>;

/// Ridisegna una lista: una riga per elemento con il cestino, poi la riga per aggiungere.
fn rerender(
    group: &adw::PreferencesGroup,
    rows: &RefCell<Vec<gtk::Widget>>,
    add: &adw::EntryRow,
    items: impl Iterator<Item = (adw::ActionRow, Remove)>,
    ed: &Rc<Ed>,
) {
    for r in rows.take() {
        group.remove(&r);
    }
    let mut out = Vec::new();
    for (row, remove) in items {
        let trash = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .tooltip_text("Togli")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        let e = Rc::downgrade(ed);
        trash.connect_clicked(move |_| {
            if let Some(ed) = e.upgrade() {
                remove(&mut ed.model.borrow_mut());
                ed.render_lists();
                ed.revalidate();
            }
        });
        row.add_suffix(&trash);
        group.add(&row);
        out.push(row.upcast());
    }
    // la riga per aggiungere va in fondo (la prima volta non c'è ancora)
    if add.is_ancestor(group) {
        group.remove(add);
    }
    group.add(add);
    rows.replace(out);
}

fn connect_lists(ed: &Rc<Ed>) {
    let e = Rc::downgrade(ed);
    ed.direct_add.connect_apply(move |row| {
        let Some(ed) = e.upgrade() else { return };
        let host = row.text().trim().to_string();
        if !validate::is_direct_rule(&host) {
            return row.add_css_class("error");
        }
        row.remove_css_class("error");
        ed.model
            .borrow_mut()
            .profile
            .proxy
            .direct
            .push(DirectRule::Host(host));
        row.set_text("");
        ed.render_lists();
        ed.revalidate();
    });
    let e = Rc::downgrade(ed);
    ed.share_add.connect_apply(move |row| {
        let Some(ed) = e.upgrade() else { return };
        let Some((server, name)) = bnw_cli::parse_unc(row.text().trim()) else {
            return row.add_css_class("error");
        };
        row.remove_css_class("error");
        let mount = format!("/mnt/{}", name.to_lowercase().replace(' ', "-"));
        ed.model.borrow_mut().profile.shares.push(Share {
            server,
            name,
            mount,
            label: None,
        });
        row.set_text("");
        ed.render_lists();
        ed.revalidate();
    });
    let e = Rc::downgrade(ed);
    ed.printer_add.connect_apply(move |row| {
        let Some(ed) = e.upgrade() else { return };
        let text = row.text().trim().to_string();
        let Some((name, addr)) = text.split_once(char::is_whitespace) else {
            return row.add_css_class("error");
        };
        row.remove_css_class("error");
        let addr = addr.trim();
        let uri = if addr.contains("://") {
            addr.to_string()
        } else {
            format!("ipp://{addr}/ipp")
        };
        ed.model.borrow_mut().profile.printers.push(Printer {
            name: name.to_string(),
            uri,
            description: None,
            location: None,
            duplex: false,
        });
        row.set_text("");
        ed.render_lists();
        ed.revalidate();
    });
}

/// Sceglie l'`.ovpn` (`vpn`) o la CA del WiFi.
async fn pick_file(ed: Rc<Ed>, vpn: bool) {
    let f = gtk::FileFilter::new();
    if vpn {
        f.set_name(Some("Profilo OpenVPN (.ovpn)"));
        f.add_pattern("*.ovpn");
    } else {
        f.set_name(Some("Certificato (PEM)"));
        f.add_pattern("*.pem");
        f.add_pattern("*.crt");
    }
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&f);
    let fd = gtk::FileDialog::builder().filters(&filters).modal(true).build();
    let parent = ed.dialog.root().and_downcast::<gtk::Window>();
    let Ok(file) = fd.open_future(parent.as_ref()).await else {
        return;
    };
    let Ok((bytes, _)) = file.load_contents_future().await else {
        return;
    };
    let data = bytes.to_vec();
    if !vpn && pem_sha1(&data).is_none() {
        return app::show_message(
            &ed.app,
            "Certificato non valido",
            "Serve una CA in formato PEM (-----BEGIN CERTIFICATE-----).",
        )
        .await;
    }
    {
        let mut m = ed.model.borrow_mut();
        let key = if vpn { "vpn/scelto.ovpn" } else { "wifi/scelto.pem" };
        // via il file precedente: normalize prende il primo che trova
        let old: Vec<String> = m
            .files
            .keys()
            .filter(|k| k.ends_with(if vpn { ".ovpn" } else { ".pem" }))
            .cloned()
            .collect();
        for k in old {
            m.files.remove(&k);
        }
        if let Some(v) = m.profile.vpn.as_mut().filter(|_| vpn) {
            v.file = key.into();
        }
        if let Some(w) = m.profile.wifi.as_mut().filter(|_| !vpn) {
            w.ca = key.into();
            w.ca_sha1 = None;
        }
        m.files.insert(key.into(), data);
    }
    let normalized = ed.current();
    ed.model.replace(normalized);
    ed.revalidate();
}

async fn save_bnw(ed: Rc<Ed>) {
    let b = ed.current();
    let p1 = adw::PasswordEntryRow::builder().title("Passphrase").build();
    let p2 = adw::PasswordEntryRow::builder().title("Ripetila").build();
    let group = adw::PreferencesGroup::new();
    group.add(&p1);
    group.add(&p2);
    let d = adw::AlertDialog::new(
        Some("Salva il profilo"),
        Some(&format!(
            "Il file è cifrato con questa passphrase (almeno {MIN_PASSPHRASE} caratteri): conservala a parte."
        )),
    );
    d.set_extra_child(Some(&group));
    d.add_response("cancel", "Annulla");
    d.add_response("save", "Salva…");
    d.set_response_appearance("save", adw::ResponseAppearance::Suggested);
    d.set_response_enabled("save", false);
    d.set_close_response("cancel");
    let check = {
        let (p1, p2, d) = (p1.clone(), p2.clone(), d.clone());
        move || {
            d.set_response_enabled(
                "save",
                p1.text().chars().count() >= MIN_PASSPHRASE && p1.text() == p2.text(),
            )
        }
    };
    let c = check.clone();
    p1.connect_changed(move |_| c());
    p2.connect_changed(move |_| check());
    if d.choose_future(Some(&ed.dialog)).await != "save" {
        return;
    }
    let pass = p1.text().to_string();
    p1.set_text("");
    p2.set_text("");
    let slug = b.profile.company.slug();
    let data = match gio::spawn_blocking(move || b.encrypt(&pass)).await {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => return app::show_message(&ed.app, "Profilo non salvato", &e.to_string()).await,
        Err(_) => return,
    };
    let fd = gtk::FileDialog::builder()
        .initial_name(format!("{slug}.bnw"))
        .modal(true)
        .build();
    let parent = ed.dialog.root().and_downcast::<gtk::Window>();
    let Ok(file) = fd.save_future(parent.as_ref()).await else {
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
        Ok(()) => app::toast(&ed.app, &format!("Profilo salvato in {}", path.display())),
        Err(e) => app::show_message(&ed.app, "Profilo non salvato", &e.to_string()).await,
    }
}

async fn apply_here(ed: Rc<Ed>) {
    let b = ed.current();
    let old = ed.app.profile.borrow().clone();
    let domain_changed = old
        .as_ref()
        .is_some_and(|o| o.company.domain != b.profile.company.domain);
    let mut body = format!(
        "Il profilo «{}» prende il posto di quello attuale: VPN, WiFi, dischi e stampanti che non ci sono più \
         vengono tolti (con backup).",
        b.profile.company.name
    );
    if domain_changed {
        body += "\n\nIl dominio cambia: dopo, aggiorna la password dalla pagina Password.";
    }
    let d = adw::AlertDialog::new(Some("Applicare a questa macchina?"), Some(&body));
    d.add_response("cancel", "Annulla");
    d.add_response("apply", "Applica");
    d.set_response_appearance("apply", adw::ResponseAppearance::Suggested);
    d.set_close_response("cancel");
    if d.choose_future(Some(&ed.dialog)).await != "apply" {
        return;
    }
    let before = old.map(|p| p.shares).unwrap_or_default();
    let Some(r) = app::run_helper(&ed.app, &cb::apply_action(&b, None)).await else {
        return;
    };
    if !r.failed() {
        let _ = user::sync_bookmarks(&glib::home_dir(), &before, &b.profile.shares);
        ed.dialog.close();
    }
    app::show_report(&ed.app, "Profilo applicato", &r).await;
    app::refresh(&ed.app);
}
