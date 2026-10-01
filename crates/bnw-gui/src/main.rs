//! `bnw`: senza argomenti apre l'app, con un comando fa da riga di comando (e allora
//! GTK non viene nemmeno inizializzato).

mod app;
mod bundle_ui;
mod connections_page;
mod password_page;
mod proxy_page;
mod resources_page;
mod status_page;
mod watch;
mod wizard;

use std::process::ExitCode;

use adw::prelude::*;

pub const APP_ID: &str = "it.akusen.BusinessNetworkWizard";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        return bnw_cli::run(&args);
    }
    let application = adw::Application::builder().application_id(APP_ID).build();
    application.connect_activate(app::activate);
    let code = application.run_with_args::<&str>(&[]);
    ExitCode::from(code.get())
}
