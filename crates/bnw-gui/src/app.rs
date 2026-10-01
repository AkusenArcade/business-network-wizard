//! La finestra, lo stato condiviso e le operazioni comuni alle pagine: aggiornare lo
//! stato, lanciare l'helper, mostrare l'esito.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use bnw_client::{Env, helper, status, user};
use bnw_core::Profile;
use bnw_core::action::{Action, Outcome, Report};
use bnw_core::status::Status;
use gtk::{gio, glib};

use crate::{
    connections_page::ConnectionsPage, password_page::PasswordPage, proxy_page::ProxyPage,
    resources_page::ResourcesPage, status_page::StatusPage, watch,
};

pub struct App {
    pub env: Env,
    pub window: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    banner: adw::Banner,
    pub status_page: StatusPage,
    pub proxy_page: ProxyPage,
    pub connections_page: ConnectionsPage,
    pub resources_page: ResourcesPage,
    pub password_page: PasswordPage,
    /// Il profilo applicato, riletto a ogni aggiornamento.
    pub profile: RefCell<Option<Profile>>,
    /// Un'azione dell'helper è in corso: niente doppi clic.
    pub busy: Cell<bool>,
    /// Il pulsante del banner adotta (macchina fatta a mano) invece di configurare.
    banner_adopt: Cell<bool>,
    refresh_pending: Cell<Option<glib::SourceId>>,
    /// I monitor dei file vivono quanto l'app.
    pub monitors: RefCell<Vec<gio::FileMonitor>>,
}

pub fn activate(application: &adw::Application) {
    if let Some(w) = application.active_window() {
        w.present();
        return;
    }
    let env = Env::from_env();

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Rete aziendale")
        .default_width(940)
        .default_height(760)
        .build();

    let stack = adw::ViewStack::new();
    let status_page = StatusPage::new();
    let proxy_page = ProxyPage::new();
    let connections_page = ConnectionsPage::new();
    let resources_page = ResourcesPage::new();
    let password_page = PasswordPage::new();
    // Le sezioni: nome nello stack, titolo, icona, pagina.
    let sections: [(&str, &str, &str, &adw::PreferencesPage); 5] = [
        ("stato", "Stato", "network-workgroup-symbolic", &status_page.page),
        (
            "proxy",
            "Proxy",
            "preferences-system-network-proxy-symbolic",
            &proxy_page.page,
        ),
        (
            "connessioni",
            "VPN e WiFi",
            "network-vpn-symbolic",
            &connections_page.page,
        ),
        (
            "dischi",
            "Dischi e stampanti",
            "folder-remote-symbolic",
            &resources_page.page,
        ),
        (
            "password",
            "Password",
            "dialog-password-symbolic",
            &password_page.page,
        ),
    ];
    let sidebar_list = gtk::ListBox::builder()
        .css_classes(["navigation-sidebar"])
        .build();
    for (name, title, icon, page) in sections {
        stack.add_titled_with_icon(page, Some(name), title, icon);
        let row_box = gtk::Box::builder()
            .spacing(12)
            .margin_top(6)
            .margin_bottom(6)
            .build();
        row_box.append(&gtk::Image::from_icon_name(icon));
        row_box.append(&gtk::Label::builder().label(title).xalign(0.0).build());
        let row = gtk::ListBoxRow::builder().child(&row_box).name(name).build();
        sidebar_list.append(&row);
    }

    // Barra laterale con le sezioni, contenuto a destra; su una finestra stretta (niri
    // la affianca spesso) diventa una navigazione a pagine.
    let sidebar_header = adw::HeaderBar::new();
    let sidebar_toolbar = adw::ToolbarView::new();
    sidebar_toolbar.add_top_bar(&sidebar_header);
    sidebar_toolbar.set_content(Some(&gtk::ScrolledWindow::builder().child(&sidebar_list).build()));
    let sidebar = adw::NavigationPage::builder()
        .title("Rete aziendale")
        .child(&sidebar_toolbar)
        .build();

    let header = adw::HeaderBar::new();
    let banner = adw::Banner::new("");
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.add_top_bar(&banner);
    toolbar.set_content(Some(&stack));
    let content = adw::NavigationPage::builder()
        .title("Stato")
        .child(&toolbar)
        .build();

    let split = adw::NavigationSplitView::builder()
        .sidebar(&sidebar)
        .content(&content)
        .build();
    {
        let (stack, content, split) = (stack.clone(), content.clone(), split.clone());
        sidebar_list.connect_row_selected(move |_, row| {
            let Some(row) = row else { return };
            let name = row.widget_name();
            stack.set_visible_child_name(&name);
            if let Some(title) = stack.page(&stack.visible_child().unwrap()).title() {
                content.set_title(&title);
            }
            split.set_show_content(true);
        });
    }
    // anche chi cambia sezione da codice (le schermate) tiene allineata la barra
    {
        let list = sidebar_list.clone();
        stack.connect_visible_child_name_notify(move |st| {
            let Some(name) = st.visible_child_name() else {
                return;
            };
            let mut i = 0;
            while let Some(row) = list.row_at_index(i) {
                if row.widget_name() == name && !row.is_selected() {
                    list.select_row(Some(&row));
                }
                i += 1;
            }
        });
    }
    sidebar_list.select_row(sidebar_list.row_at_index(0).as_ref());
    let narrow = adw::Breakpoint::new(adw::BreakpointCondition::new_length(
        adw::BreakpointConditionLengthType::MaxWidth,
        600.0,
        adw::LengthUnit::Sp,
    ));
    narrow.add_setter(&split, "collapsed", Some(&true.to_value()));

    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&split));
    window.set_content(Some(&toasts));
    window.add_breakpoint(narrow);

    let app = Rc::new(App {
        env,
        window,
        toasts,
        banner,
        status_page,
        proxy_page,
        connections_page,
        resources_page,
        password_page,
        profile: RefCell::new(None),
        busy: Cell::new(false),
        banner_adopt: Cell::new(false),
        refresh_pending: Cell::new(None),
        monitors: RefCell::new(Vec::new()),
    });

    app.banner.connect_button_clicked({
        let app = app.clone();
        move |_| {
            // lo stesso banner: «Adotta…» su una macchina fatta a mano, «Configura…» su una
            // vuota
            if app.banner_adopt.get() {
                glib::spawn_future_local(adopt(app.clone()));
            } else {
                crate::wizard::open(&app);
            }
        }
    });
    app.status_page.connect(&app);
    app.proxy_page.connect(&app);
    app.connections_page.connect(&app);
    app.resources_page.connect(&app);
    app.password_page.connect(&app);
    crate::bundle_ui::install(&app, &sidebar_header);
    watch::start(&app);

    app.window.present();
    refresh(&app);
    if let Ok(prefix) = std::env::var("BNW_SCREENSHOT") {
        screenshots(app.clone(), stack, prefix);
    }
}

/// Solo per lo sviluppo (`BNW_SCREENSHOT=/percorso/prefisso`, di solito con
/// `GDK_BACKEND=broadway`): salva un PNG per pagina e chiude l'app. Con
/// `BNW_SCREENSHOT_ACTION=<azione>` (es. `export-profile`) apre anche quell'azione del
/// menu e fotografa il dialogo.
fn screenshots(app: Rc<App>, stack: adw::ViewStack, prefix: String) {
    fn shoot(w: &gtk::Widget, path: &str) {
        let (width, height) = (w.width() as f32, w.height() as f32);
        let paintable = gtk::WidgetPaintable::new(Some(w));
        let snapshot = gtk::Snapshot::new();
        paintable.snapshot(&snapshot, width as f64, height as f64);
        let (Some(node), Some(renderer)) = (snapshot.to_node(), w.native().and_then(|n| n.renderer())) else {
            return;
        };
        let rect = gtk::graphene::Rect::new(0.0, 0.0, width, height);
        if let Err(e) = renderer.render_texture(&node, Some(&rect)).save_to_png(path) {
            eprintln!("bnw: {path}: {e}");
        }
    }
    glib::spawn_future_local(async move {
        for name in ["stato", "proxy", "connessioni", "dischi", "password"] {
            stack.set_visible_child_name(name);
            glib::timeout_future(std::time::Duration::from_millis(2500)).await;
            shoot(app.window.upcast_ref(), &format!("{prefix}-{name}.png"));
        }
        if let Ok(action) = std::env::var("BNW_SCREENSHOT_ACTION") {
            let _ = WidgetExt::activate_action(&app.window, &format!("win.{action}"), None);
            // il dialogo si apre con un'animazione: prima di allora ha dimensione zero
            glib::timeout_future(std::time::Duration::from_millis(5000)).await;
            shoot(app.window.upcast_ref(), &format!("{prefix}-{action}.png"));
            if let Some(d) = app.window.visible_dialog() {
                shoot(d.upcast_ref(), &format!("{prefix}-{action}-dialogo.png"));
            } else {
                eprintln!("bnw: nessun dialogo visibile");
            }
        }
        app.window.close();
    });
}

/// Rilegge lo stato in un thread e aggiorna le pagine.
pub fn refresh(app: &Rc<App>) {
    let app = app.clone();
    glib::spawn_future_local(async move {
        let env = app.env.clone();
        let Ok((st, profile)) =
            gio::spawn_blocking(move || (status::read(&env), status::installed_profile(&env))).await
        else {
            return;
        };
        app.profile.replace(profile);
        update_banner(&app, &st);
        app.status_page.update(&st);
        app.proxy_page.update(&app, &st);
        app.connections_page.update(&app, &st);
        app.resources_page.update(&app, &st);
        app.password_page.update(&app, &st);
    });
}

/// Aggiornamento raggruppato: molti eventi ravvicinati (un cambio di rete ne genera
/// parecchi) producono una sola lettura.
pub fn refresh_soon(app: &Rc<App>) {
    if let Some(id) = app.refresh_pending.take() {
        id.remove();
    }
    let weak = Rc::downgrade(app);
    let id = glib::timeout_add_local_once(std::time::Duration::from_millis(400), move || {
        if let Some(app) = weak.upgrade() {
            app.refresh_pending.set(None);
            refresh(&app);
        }
    });
    app.refresh_pending.set(Some(id));
}

fn update_banner(app: &App, st: &Status) {
    let home = glib::home_dir();
    let fish = !user::legacy_fish(&home).is_empty();
    if st.legacy || (st.company.is_none() && fish) {
        app.banner.set_title(
            "Questa macchina è configurata a mano: adottala per gestirla da qui, senza cambiarne il comportamento",
        );
        app.banner.set_button_label(Some("Adotta…"));
        app.banner_adopt.set(true);
        app.banner.set_revealed(true);
    } else if st.company.is_none() {
        app.banner
            .set_title("Questa macchina non è ancora configurata per la rete aziendale");
        app.banner.set_button_label(Some("Configura…"));
        app.banner_adopt.set(false);
        app.banner.set_revealed(true);
    } else {
        app.banner.set_revealed(false);
    }
}

pub fn toast(app: &App, text: &str) {
    app.toasts.add_toast(adw::Toast::new(text));
}

/// Lancia l'helper (con pkexec) e aspetta il rapporto. Gli errori li mostra qui;
/// `None` se non c'è rapporto.
pub async fn run_helper(app: &Rc<App>, action: &Action) -> Option<Report> {
    if app.busy.replace(true) {
        return None;
    }
    let result = spawn_helper(&app.env, action).await;
    app.busy.set(false);
    match result {
        Ok(r) => Some(r),
        Err(helper::HelperError::NotAuthorized) => {
            toast(app, "Autorizzazione annullata: non è cambiato niente");
            None
        }
        Err(e) => {
            show_message(app, "Operazione non riuscita", &e.to_string()).await;
            None
        }
    }
}

async fn spawn_helper(env: &Env, action: &Action) -> Result<Report, helper::HelperError> {
    let argv: Vec<std::ffi::OsString> = helper::argv(env).into_iter().map(Into::into).collect();
    let argv: Vec<&std::ffi::OsStr> = argv.iter().map(|s| s.as_os_str()).collect();
    let proc = gio::Subprocess::newv(
        &argv,
        gio::SubprocessFlags::STDIN_PIPE
            | gio::SubprocessFlags::STDOUT_PIPE
            | gio::SubprocessFlags::STDERR_PIPE,
    )
    .map_err(|e| helper::HelperError::Spawn(std::io::Error::other(e.to_string())))?;
    // la password, se c'è, passa solo di qui
    let (out, err) = proc
        .communicate_utf8_future(Some(helper::request(action)))
        .await
        .map_err(|e| helper::HelperError::Spawn(std::io::Error::other(e.to_string())))?;
    let code = if proc.has_exited() { proc.exit_status() } else { -1 };
    helper::parse_reply(code, out.as_deref().unwrap_or(""), err.as_deref().unwrap_or(""))
}

/// Il rapporto come elenco leggibile, un passo per riga.
pub fn report_text(r: &Report, only_relevant: bool) -> String {
    r.steps
        .iter()
        .filter(|s| !only_relevant || s.outcome != Outcome::Unchanged)
        .map(|s| {
            let mark = match s.outcome {
                Outcome::Changed => "✓",
                Outcome::Unchanged => "=",
                Outcome::Skipped => "–",
                Outcome::Failed => "✗",
            };
            match &s.detail {
                Some(d) => format!("{mark} {}: {d}", s.what),
                None => format!("{mark} {}", s.what),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub async fn show_message(app: &App, heading: &str, body: &str) {
    let d = adw::AlertDialog::new(Some(heading), Some(body));
    d.add_response("ok", "Chiudi");
    d.choose_future(Some(&app.window)).await;
}

/// Esito di un'azione: un toast se è andata bene, il dettaglio se qualcosa è fallito.
pub async fn show_report(app: &App, ok_text: &str, r: &Report) {
    if r.failed() {
        show_message(app, "Qualcosa non è andato", &report_text(r, true)).await;
    } else {
        toast(app, ok_text);
    }
}

async fn adopt(app: Rc<App>) {
    let filter = gtk::FileFilter::new();
    filter.set_name(Some("Profilo aziendale (profile.toml)"));
    filter.add_pattern("*.toml");
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&filter);
    let chooser = gtk::FileDialog::builder()
        .title("Scegli il profilo aziendale di questa macchina")
        .filters(&filters)
        .modal(true)
        .build();
    let Ok(file) = chooser.open_future(Some(&app.window)).await else {
        return;
    };
    let Some(path) = file.path() else { return };
    let profile = match std::fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|t| {
            let p = Profile::from_toml(&t).map_err(|e| e.to_string())?;
            bnw_core::validate::profile(&p)
                .map_err(|e| e.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"))?;
            Ok(p)
        }) {
        Ok(p) => p,
        Err(e) => return show_message(&app, "Profilo non valido", &e).await,
    };

    let confirm = adw::AlertDialog::new(
        Some(&format!(
            "Adottare la configurazione di {}?",
            profile.company.name
        )),
        Some(
            "L'app scrive il profilo in /etc/bnw e rigenera i file del proxy (identici a quelli di oggi), \
             poi mette in .bak gli script manuali (/usr/local/bin/proxy-*, il dispatcher 90-proxy-vpn, \
             gli override di systemd) e le funzioni fish vpn-up, vpn-down, vpn-pass e pass-dominio.\n\n\
             Da quel momento il proxy lo gestiscono gli script del pacchetto. Gli hash di cntlm restano \
             quelli di oggi.",
        ),
    );
    confirm.add_response("cancel", "Annulla");
    confirm.add_response("adopt", "Adotta");
    confirm.set_response_appearance("adopt", adw::ResponseAppearance::Suggested);
    confirm.set_default_response(Some("cancel"));
    if confirm.choose_future(Some(&app.window)).await != "adopt" {
        return;
    }

    let Some(report) = run_helper(&app, &Action::Adopt { profile }).await else {
        return;
    };
    if report.failed() {
        show_message(&app, "Adozione non riuscita", &report_text(&report, true)).await;
        refresh(&app);
        return;
    }
    let mut text = report_text(&report, true);
    match user::retire_fish(&glib::home_dir()) {
        Ok(done) => {
            for p in done {
                text += &format!("\n✓ {}: funzione fish messa da parte", p.display());
            }
        }
        Err(e) => text += &format!("\n✗ funzioni fish: {e}"),
    }
    show_message(&app, "Configurazione adottata", &text).await;
    refresh(&app);
}
