#![allow(dead_code)]
mod crypto;
mod dbus_api;
mod session_crypto;
mod portal_secret;
mod unlock_socket;

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

    let unlock = PamUnlockInterface::new(state.clone(), conn.clone());
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

    // El socket por donde llega la contraseña al iniciar sesión. Va después de
    // reclamar el nombre porque recién ahí se sabe que este proceso es el único
    // demonio, y por lo tanto que puede borrar un socket viejo sin robarle las
    // entregas a otro. Ver `unlock_socket.rs` para por qué no alcanza D-Bus.
    let state_portal = state.clone();
    if let Err(e) = unlock_socket::escuchar(state, conn.clone()).await {
        // No es fatal: el llavero sigue sirviendo a quien ya esté desbloqueado y
        // el diálogo gráfico sigue funcionando por el bus. Pero el desbloqueo
        // automático no va a andar, y eso tiene que quedar dicho.
        eprintln!(
            "vasak-keyring: no se pudo abrir el socket de desbloqueo ({e}); \
             el llavero va a pedir la contraseña a mano."
        );
    }

    // El backend del portal para el secreto maestro por aplicación. Nombre
    // aparte del de Secret Service: son dos contratos distintos, y el portal
    // busca este exacto —el mismo que declara `packaging/vasak-keyring.portal`—.
    //
    // Si no se puede tomar, el llavero sigue sirviendo todo lo demás: lo único
    // que se pierde es que las aplicaciones en sandbox tengan clave propia, y es
    // preferible eso a no arrancar.
    let backend = portal_secret::SecretBackend::new(state_portal, conn.clone());
    match conn
        .object_server()
        .at(portal_secret::RUTA_BACKEND, backend)
        .await
    {
        Ok(_) => match conn
            .request_name_with_flags(
                portal_secret::NOMBRE_BACKEND,
                RequestNameFlags::DoNotQueue.into(),
            )
            .await
        {
            Ok(RequestNameReply::PrimaryOwner) => {}
            otro => eprintln!(
                "vasak-keyring: no se pudo tomar {}: {otro:?}; \
                 las aplicaciones en sandbox no van a tener secreto propio",
                portal_secret::NOMBRE_BACKEND
            ),
        },
        Err(e) => eprintln!(
            "vasak-keyring: no se pudo publicar el backend del portal ({e}); \
             las aplicaciones en sandbox no van a tener secreto propio"
        ),
    }

    println!("vasak-keyring: D-Bus services ready");

    std::future::pending::<()>().await;
    Ok(())
}
