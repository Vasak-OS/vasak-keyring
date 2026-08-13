#![allow(dead_code)]
mod crypto;
mod dbus_api;
mod session_crypto;

use std::sync::Arc;
use tokio::sync::Mutex;
use dbus_api::{ServiceInterface, PamUnlockInterface, KeyringState};
use std::error::Error;
use zbus::fdo::{RequestNameFlags, RequestNameReply};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let conn = zbus::connection::Builder::session()?.build().await?;

    let state = Arc::new(Mutex::new(KeyringState::new()));

    let service = ServiceInterface::new(conn.clone(), state.clone());
    // Register the default "login" collection (and its "default"/"login"
    // aliases) up front so libsecret can resolve ReadAlias("default") before the
    // PAM unlock populates it.
    service.register_default_collection().await?;
    conn.object_server()
        .at("/org/freedesktop/secrets", service)
        .await
        .map(|_| ())?;

    let unlock = PamUnlockInterface::new(state, conn.clone());
    conn.object_server()
        .at("/org/vasak/keyring", unlock)
        .await
        .map(|_| ())?;

    // The name is claimed only once every object is being served, so there is
    // no window where a client resolves the name and finds no paths behind it.
    //
    // Without DoNotQueue (and with zbus' default AllowReplacement) a second
    // process took the name away from the running daemon, and when that second
    // process died the name was left with no owner at all: every client got
    // "the name is not activatable" while systemd still reported the unit as
    // active, with nothing in the logs. Refusing to start is far easier to
    // diagnose than a service that is running but unreachable.
    //
    // Secret Service well-known name is lowercase per the freedesktop spec;
    // libsecret/gnome-keyring clients look this exact name up.
    // A name that is already taken comes back as Err(NameTaken), not as a
    // non-primary reply, so both have to be handled to get a legible message
    // instead of a bare "Error: NameTaken".
    let claimed = conn
        .request_name_with_flags(
            "org.freedesktop.secrets",
            RequestNameFlags::DoNotQueue.into(),
        )
        .await;

    match claimed {
        Ok(RequestNameReply::PrimaryOwner) => {}
        Ok(_) | Err(zbus::Error::NameTaken) => {
            eprintln!(
                "vasak-keyring: org.freedesktop.secrets ya tiene dueño; \
                 el demonio ya está corriendo. Se sale sin tocarlo."
            );
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    }

    println!("vasak-keyring: D-Bus services ready");

    std::future::pending::<()>().await;
    Ok(())
}
