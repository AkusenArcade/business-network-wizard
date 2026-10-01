//! Aggiornare lo stato quando qualcosa cambia, senza controlli periodici: segnali
//! D-Bus di NetworkManager e systemd, e modifiche ai file del proxy.

use std::rc::Rc;

use futures_util::StreamExt;
use gtk::prelude::*;
use gtk::{gio, glib};
use zbus::{Connection, MatchRule, MessageStream};

use crate::app::{self, App};

pub fn start(app: &Rc<App>) {
    // Il symlink active.conf si sposta dentro /etc/tinyproxy; la forzatura è un file
    // in /run che compare e sparisce.
    let files = [
        bnw_core::paths::ACTIVE_CONF,
        bnw_core::paths::MANUAL,
        bnw_core::paths::PROFILE,
    ];
    let mut monitors = Vec::new();
    for abs in files {
        let file = gio::File::for_path(app.env.path(abs));
        let Ok(m) = file.monitor_file(gio::FileMonitorFlags::WATCH_MOVES, gio::Cancellable::NONE) else {
            continue;
        };
        let weak = Rc::downgrade(app);
        m.connect_changed(move |_, _, _, _| {
            if let Some(app) = weak.upgrade() {
                app::refresh_soon(&app);
            }
        });
        monitors.push(m);
    }
    app.monitors.replace(monitors);

    let weak = Rc::downgrade(app);
    glib::spawn_future_local(async move {
        if let Err(e) = watch_dbus(weak).await {
            eprintln!("bnw: segnali D-Bus non disponibili ({e}): lo stato si aggiorna solo dopo le azioni");
        }
    });
}

async fn watch_dbus(weak: std::rc::Weak<App>) -> zbus::Result<()> {
    let bus = Connection::system().await?;
    // systemd manda PropertiesChanged delle unit solo a chi si è abbonato
    let _ = bus
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "Subscribe",
            &(),
        )
        .await;

    let props = |sender: &'static str, path: &'static str| -> zbus::Result<MatchRule<'static>> {
        Ok(MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(sender)?
            .interface("org.freedesktop.DBus.Properties")?
            .member("PropertiesChanged")?
            .path(path)?
            .build())
    };
    let rules = [
        props(
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
        )?,
        props(
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/tinyproxy_2eservice",
        )?,
        props(
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/cntlm_2eservice",
        )?,
    ];
    let mut streams = Vec::new();
    for rule in rules {
        streams.push(MessageStream::for_match_rule(rule, &bus, Some(16)).await?);
    }
    let mut all = futures_util::stream::select_all(streams);
    while all.next().await.is_some() {
        let Some(app) = weak.upgrade() else { break };
        app::refresh_soon(&app);
    }
    Ok(())
}
