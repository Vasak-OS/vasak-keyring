#![allow(dead_code)]
mod crypto;
mod dbus_api;

use std::sync::Arc;
use tokio::sync::Mutex;
use dbus_api::{ServiceInterface, PamUnlockInterface, KeyringState};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Secret Service well-known name is lowercase per the freedesktop spec;
    // libsecret/gnome-keyring clients look this exact name up.
    let conn = zbus::connection::Builder::session()?
        .name("org.freedesktop.secrets")?
        .build()
        .await?;

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

    println!("vasak-keyring: D-Bus services ready");

    std::future::pending::<()>().await;
    Ok(())
}
