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

    // El backend del portal para el secreto maestro por aplicación.
    //
    // En una **conexión propia**, no en la que sirve el Secret Service. Con las
    // dos en la misma, un permiso de sandbox concedido sobre
    // `org.freedesktop.secrets` alcanzaría para hablar con este backend y pedir el
    // secreto de cualquier aplicación: el proxy de D-Bus filtra por nombre, y
    // todos los nombres de una conexión comparten el mismo nombre único.
    //
    // Si algo de esto falla, el llavero sigue sirviendo todo lo demás: lo único
    // que se pierde es que las aplicaciones en sandbox tengan clave propia, y es
    // preferible eso a no arrancar.
    match zbus::connection::Builder::session() {
        Ok(constructor) => {
            let backend_conn = constructor
                .name(portal_secret::NOMBRE_BACKEND)
                .and_then(|c| {
                    c.serve_at(
                        portal_secret::RUTA_BACKEND,
                        portal_secret::SecretBackend::new(state_portal, conn.clone()),
                    )
                });

            match backend_conn {
                Ok(constructor) => match constructor.build().await {
                    // Se deja viva a propósito: al soltarla, la conexión se cierra
                    // y el nombre se pierde.
                    Ok(viva) => {
                        std::mem::forget(viva);
                    }
                    Err(e) => eprintln!(
                        "vasak-keyring: no se pudo abrir la conexión del backend del portal \
                         ({e}); las aplicaciones en sandbox no van a tener secreto propio"
                    ),
                },
                Err(e) => eprintln!(
                    "vasak-keyring: no se pudo publicar el backend del portal ({e}); \
                     las aplicaciones en sandbox no van a tener secreto propio"
                ),
            }
        }
        Err(e) => eprintln!(
            "vasak-keyring: no se pudo preparar la conexión del backend del portal ({e})"
        ),
    }

    println!("vasak-keyring: D-Bus services ready");

    std::future::pending::<()>().await;
    Ok(())
}
