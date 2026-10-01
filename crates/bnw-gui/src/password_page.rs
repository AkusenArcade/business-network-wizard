//! Pagina Password: dove sta la password di dominio, quando è stata scritta, e la
//! procedura per aggiornarla quando è stata cambiata altrove (Windows, portale).

use std::rc::Rc;

use adw::prelude::*;
use bnw_core::action::{Action, NtlmCheck, Outcome, Place, Report, SPREAD_WARNING_SECS};
use bnw_core::status::Status;
use gtk::glib;

use crate::app::{self, App};

pub struct PasswordPage {
    pub page: adw::PreferencesPage,
    places: adw::PreferencesGroup,
    check: gtk::Button,
    rows: Vec<(Place, adw::ActionRow)>,
    warning: adw::ActionRow,
    update: gtk::Button,
}

impl PasswordPage {
    pub fn new() -> Self {
        let page = adw::PreferencesPage::new();

        let places = adw::PreferencesGroup::builder()
            .title("Dove sta la password di dominio")
            .description(
                "La stessa password è salvata in quattro posti. «Controlla» li confronta senza \
                 mostrarla; serve la password di amministratore.",
            )
            .build();
        let check = gtk::Button::builder()
            .label("Controlla")
            .valign(gtk::Align::Center)
            .build();
        places.set_header_suffix(Some(&check));
        let mut rows = Vec::new();
        for place in Place::ALL {
            let row = adw::ActionRow::builder()
                .title(place.label())
                .subtitle("—")
                .build();
            row.add_css_class("property");
            places.add(&row);
            rows.push((place, row));
        }
        let warning = adw::ActionRow::builder()
            .title("Le date non sono vicine")
            .subtitle(
                "Un cambio password precedente può essere rimasto a metà: aggiorna la password qui sotto",
            )
            .visible(false)
            .build();
        warning.add_css_class("warning");
        warning.add_prefix(&gtk::Image::from_icon_name("dialog-warning-symbolic"));
        places.add(&warning);

        let action = adw::PreferencesGroup::builder()
            .title("Password cambiata")
            .description(
                "Quando la password di dominio scade e la cambi (da Windows o dal portale), qui la \
                 aggiorni in tutti e quattro i posti con un'unica procedura. Il cambio sul dominio \
                 non lo fa l'app.",
            )
            .build();
        let update = gtk::Button::builder()
            .label("Aggiorna la password di dominio…")
            .halign(gtk::Align::Center)
            .css_classes(["pill", "suggested-action"])
            .build();
        action.add(&update);

        page.add(&places);
        page.add(&action);
        PasswordPage {
            page,
            places,
            check,
            rows,
            warning,
            update,
        }
    }

    pub fn connect(&self, app: &Rc<App>) {
        let a = app.clone();
        self.check.connect_clicked(move |_| {
            glib::spawn_future_local(load_status(a.clone()));
        });
        let a = app.clone();
        self.update.connect_clicked(move |_| {
            glib::spawn_future_local(change_password(a.clone()));
        });
    }

    pub fn update(&self, app: &App, _st: &Status) {
        let configured = app.profile.borrow().is_some();
        self.page.set_sensitive(configured);
    }

    fn show(&self, r: &Report) {
        for (place, row) in &self.rows {
            match r.steps.iter().find(|s| s.place == Some(*place)) {
                None => {
                    row.set_subtitle("non previsto dal profilo");
                    row.remove_css_class("error");
                }
                Some(s) => {
                    let when = s.mtime.map(local_time).unwrap_or_default();
                    let text = match (&s.detail, s.outcome) {
                        (Some(d), _) => format!("{when}  {d}").trim().to_string(),
                        (None, _) => format!("{when}  {}", s.what),
                    };
                    row.set_subtitle(&text);
                    if s.outcome == Outcome::Failed {
                        row.add_css_class("error");
                    } else {
                        row.remove_css_class("error");
                    }
                }
            }
        }
        match r.password_aligned {
            Some(false) => {
                self.warning.set_title("La password non è la stessa ovunque");
                self.warning.set_subtitle(
                    "Un cambio password è rimasto a metà (posti in rosso): aggiornala qui sotto",
                );
                self.warning.set_visible(true);
            }
            None if r.mtime_spread().is_some_and(|d| d > SPREAD_WARNING_SECS) => {
                self.warning.set_title("Le date non sono vicine");
                self.warning.set_subtitle(
                    "Non è stato possibile confrontare le password: un aggiornamento può essere rimasto a metà",
                );
                self.warning.set_visible(true);
            }
            _ => self.warning.set_visible(false),
        }
        if r.password_aligned == Some(true) {
            self.places.set_description(Some(
                "La password è la stessa in tutti i posti che ne hanno una (confrontata senza mostrarla).",
            ));
        }
    }
}

fn local_time(secs: i64) -> String {
    glib::DateTime::from_unix_local(secs)
        .and_then(|t| t.format("%d/%m/%Y %H:%M"))
        .map(|s| s.to_string())
        .unwrap_or_default()
}

async fn load_status(app: Rc<App>) {
    if let Some(r) = app::run_helper(&app, &Action::PasswordStatus).await {
        app.password_page.show(&r);
    }
}

/// La procedura del §5 del piano: avviso, cntlm fermo, password due volte, scrittura,
/// verifica NTLM, riconnessione della VPN.
async fn change_password(app: Rc<App>) {
    let intro = adw::AlertDialog::new(
        Some("Aggiornare la password di dominio?"),
        Some(
            "Prima di chiederti la password l'app ferma cntlm: con la password vecchia ritenterebbe \
             a ogni richiesta e il dominio bloccherebbe l'account. Fino alla fine della procedura \
             la navigazione attraverso il proxy aziendale si interrompe.\n\n\
             La password nuova va nella VPN, nel WiFi aziendale, nel proxy e nei dischi di rete.",
        ),
    );
    intro.add_response("cancel", "Annulla");
    intro.add_response("go", "Continua");
    intro.set_response_appearance("go", adw::ResponseAppearance::Suggested);
    intro.set_default_response(Some("go"));
    if intro.choose_future(Some(&app.window)).await != "go" {
        return;
    }

    let Some(r) = app::run_helper(&app, &Action::StopCntlm).await else {
        return;
    };
    if r.failed() {
        return app::show_message(&app, "Non riesco a fermare cntlm", &app::report_text(&r, true)).await;
    }

    // Si chiede la password finché la prova preventiva la rifiuta: in quel caso non è
    // stato scritto niente e cntlm è ancora fermo.
    let mut retry = false;
    let r = loop {
        let Some(password) = ask_password(&app, retry).await else {
            cancelled(&app).await;
            app::refresh(&app);
            return;
        };
        let action = Action::SetPassword {
            password: bnw_core::Secret::new(password),
            only: Vec::new(),
            domain_user: None,
        };
        let Some(r) = app::run_helper(&app, &action).await else {
            cancelled(&app).await;
            app::refresh(&app);
            return;
        };
        if !r.rejected_before_writing() {
            break r;
        }
        retry = true;
    };
    app::refresh(&app);

    let (heading, mut body) = match r.ntlm {
        Some(NtlmCheck::Rejected) => (
            "Password rifiutata dal proxy (407)",
            "La password è stata scritta, ma la prova finale del proxy aziendale la rifiuta. cntlm è \
             stato fermato subito per non bloccare l'account: controlla la password e ripeti la \
             procedura.\n\n"
                .to_string(),
        ),
        _ if r.failed() => (
            "Aggiornamento incompleto",
            "Alcuni posti non sono stati aggiornati: sono segnati con ✗. Gli altri hanno già la \
             password nuova.\n\n"
                .to_string(),
        ),
        Some(NtlmCheck::Ok { .. }) => (
            "Password aggiornata",
            "Il proxy aziendale accetta la password nuova.\n\n".to_string(),
        ),
        Some(NtlmCheck::NotRun) => (
            "Password aggiornata",
            "La prova del proxy si potrà fare sulla rete aziendale o in VPN («Prova un URL» nella \
             pagina Proxy).\n\n"
                .to_string(),
        ),
        Some(NtlmCheck::Inconclusive { .. }) | None => ("Password aggiornata", String::new()),
    };
    body += &app::report_text(&r, true);

    let vpn = app
        .profile
        .borrow()
        .as_ref()
        .and_then(|p| p.vpn.as_ref().map(|v| v.name.clone()));
    let done = adw::AlertDialog::new(Some(heading), Some(&body));
    done.add_response("close", "Chiudi");
    if let Some(name) = &vpn {
        body_note(&done, name);
        done.add_response("reconnect", "Riconnetti la VPN");
        done.set_response_appearance("reconnect", adw::ResponseAppearance::Suggested);
    }
    if done.choose_future(Some(&app.window)).await == "reconnect"
        && let Some(name) = vpn
    {
        reconnect_vpn(&app, &name).await;
    }
    load_status(app).await;
}

fn body_note(d: &adw::AlertDialog, vpn: &str) {
    let note = gtk::Label::builder()
        .label(format!(
            "La VPN «{vpn}», se è connessa, resta sulla sessione vecchia: riconnettila per usare la password nuova."
        ))
        .wrap(true)
        .css_classes(["dim-label"])
        .build();
    d.set_extra_child(Some(&note));
}

/// Annullato a metà: cntlm è fermo. Riaccenderlo con gli hash vecchi, se la password
/// sul dominio è già cambiata, vorrebbe dire 407 a ripetizione: di base resta fermo.
async fn cancelled(app: &Rc<App>) {
    let d = adw::AlertDialog::new(
        Some("cntlm è fermo"),
        Some(
            "Non è stato modificato niente. cntlm resta fermo: se la password sul dominio è già \
             cambiata, con quella vecchia bloccherebbe l'account. Finché non aggiorni la password, \
             la navigazione attraverso il proxy aziendale non funziona.\n\n\
             Se invece la password non è cambiata, puoi riaccenderlo.",
        ),
    );
    d.add_response("keep", "Lascialo fermo");
    d.add_response("start", "Riaccendilo");
    d.set_default_response(Some("keep"));
    d.set_close_response("keep");
    if d.choose_future(Some(&app.window)).await == "start"
        && let Some(r) = app::run_helper(app, &Action::StartCntlm).await
    {
        app::show_report(app, "cntlm riacceso", &r).await;
    }
}

/// Due campi password; «Aggiorna» si abilita solo quando coincidono. `retry`: la
/// password precedente è stata rifiutata dalla prova.
async fn ask_password(app: &App, retry: bool) -> Option<String> {
    let first = adw::PasswordEntryRow::builder().title("Password nuova").build();
    let second = adw::PasswordEntryRow::builder().title("Ripetila").build();
    let group = adw::PreferencesGroup::new();
    group.add(&first);
    group.add(&second);

    let (heading, body) = if retry {
        (
            "Password rifiutata",
            "Il proxy aziendale ha rifiutato la password (407). Non è stato modificato niente: \
             riscrivila con attenzione. Ogni prova sbagliata conta come un tentativo verso il dominio.",
        )
    } else {
        (
            "Password di dominio nuova",
            "Scrivi la password che hai già impostato sul dominio. Prima di salvarla l'app la prova \
             con il proxy aziendale, se è raggiungibile.",
        )
    };
    let d = adw::AlertDialog::new(Some(heading), Some(body));
    d.set_extra_child(Some(&group));
    d.add_response("cancel", "Annulla");
    d.add_response("ok", "Aggiorna");
    d.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    d.set_response_enabled("ok", false);
    d.set_default_response(Some("ok"));
    d.set_close_response("cancel");

    let check = {
        let (first, second, d) = (first.clone(), second.clone(), d.clone());
        move || {
            let (a, b) = (first.text(), second.text());
            let ok = !a.is_empty() && a == b && !a.contains(['\n', '\r']);
            d.set_response_enabled("ok", ok);
            if !b.is_empty() && a != b {
                second.add_css_class("error");
            } else {
                second.remove_css_class("error");
            }
        }
    };
    let c = check.clone();
    first.connect_changed(move |_| c());
    second.connect_changed(move |_| check());
    first.grab_focus();

    let answer = d.choose_future(Some(&app.window)).await;
    let password = first.text().to_string();
    // i campi si svuotano subito: la password resta solo dove serve
    first.set_text("");
    second.set_text("");
    (answer == "ok").then_some(password)
}

async fn reconnect_vpn(app: &App, name: &str) {
    for verb in ["down", "up"] {
        let proc = gtk::gio::Subprocess::newv(
            &[
                "nmcli".as_ref(),
                "connection".as_ref(),
                verb.as_ref(),
                "id".as_ref(),
                name.as_ref(),
            ],
            gtk::gio::SubprocessFlags::STDOUT_SILENCE | gtk::gio::SubprocessFlags::STDERR_PIPE,
        );
        let Ok(proc) = proc else { return };
        let result = proc.communicate_utf8_future(None).await;
        // «down» fallisce se la VPN non era connessa: non è un errore
        if verb == "up" && !proc.is_successful() {
            let err = result
                .ok()
                .and_then(|(_, e)| e)
                .map(|e| e.to_string())
                .unwrap_or_default();
            app::show_message(app, "La VPN non si connette", err.trim()).await;
            return;
        }
    }
    app::toast(app, "VPN riconnessa con la password nuova");
}
