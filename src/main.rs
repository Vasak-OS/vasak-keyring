#![allow(dead_code)]
mod crypto;
mod dbus_api;

use dbus_api::ServiceInterface;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let conn = zbus::connection::Builder::session()?
        .name("org.freedesktop.Secrets")?
        .build()
        .await?;

    let service = ServiceInterface::new(conn.clone());
    conn.object_server()
        .at("/org/freedesktop/secrets", service)
        .await
        .map(|_| ())?;

    println!("vasak-keyring: D-Bus service 'org.freedesktop.Secrets' ready");

    std::future::pending::<()>().await;
    Ok(())
}
