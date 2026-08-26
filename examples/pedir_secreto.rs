//! Cliente de prueba del portal Secret: pide el secreto de una app y lo imprime.
use std::io::Read;
use std::os::fd::{IntoRawFd, FromRawFd, OwnedFd};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_id = std::env::args().nth(1).unwrap_or_else(|| "ar.net.vasak.prueba".into());
    let conn = zbus::Connection::session().await?;

    let (lector, escritor) = std::os::unix::net::UnixStream::pair()?;
    let fd = zbus::zvariant::OwnedFd::from(unsafe { OwnedFd::from_raw_fd(escritor.into_raw_fd()) });

    let respuesta = conn.call_method(
        Some("org.freedesktop.impl.portal.desktop.vasak-keyring"),
        "/org/freedesktop/portal/desktop",
        Some("org.freedesktop.impl.portal.Secret"),
        "RetrieveSecret",
        &(
            zbus::zvariant::ObjectPath::try_from("/org/freedesktop/portal/desktop/req/1")?,
            app_id.as_str(),
            fd,
            std::collections::HashMap::<String, zbus::zvariant::Value>::new(),
        ),
    ).await?;

    let (codigo, _): (u32, std::collections::HashMap<String, zbus::zvariant::OwnedValue>) =
        respuesta.body().deserialize()?;

    let mut bytes = Vec::new();
    let mut lector = lector;
    lector.read_to_end(&mut bytes)?;

    println!("codigo={codigo} largo={} sha={:x}", bytes.len(), {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new(); h.update(&bytes); h.finalize()
    });
    Ok(())
}
