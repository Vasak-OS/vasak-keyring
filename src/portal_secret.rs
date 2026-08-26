//! El backend del portal para `org.freedesktop.impl.portal.Secret`.
//!
//! Le da a una aplicación un secreto maestro propio, con el que cifrar lo suyo
//! sin tener que pedirle nada a la persona.
//!
//! # Por qué lo sirve el llavero y no el agente de permisos
//!
//! El único backend que había instalado con esta interfaz era el de KWallet, así
//! que los secretos de las aplicaciones iban a **una cartera de KDE que nada más
//! del sistema lee**, mientras vasak-keyring —el llavero del escritorio— quedaba
//! de lado. Estaba ruteado a `none` para que al menos no se guardaran en el lugar
//! equivocado en silencio; esto es lo que lo reemplaza.
//!
//! Lo sirve el llavero, que es quien tiene los secretos, y no el agente de
//! permisos: pasarlo por otro servicio agregaría un salto por el bus con la clave
//! adentro, sin ganar nada.
//!
//! # El descriptor
//!
//! La especificación no devuelve el secreto en la respuesta: el cliente manda un
//! descriptor y el backend escribe ahí. Eso mantiene la clave fuera de los
//! mensajes de D-Bus, que pasan por el broker y aparecen en cualquier traza del
//! bus.

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use tokio::sync::Mutex;
use zbus::interface;
use zbus::zvariant::{ObjectPath, OwnedValue};

use crate::dbus_api::{secreto_maestro_de_app, KeyringState};

/// El nombre con el que el portal encuentra este backend. Tiene que coincidir
/// con el `.portal` que se instala al lado, o el portal no mira acá.
pub const NOMBRE_BACKEND: &str = "org.freedesktop.impl.portal.desktop.vasak-keyring";
pub const RUTA_BACKEND: &str = "/org/freedesktop/portal/desktop";

/// Códigos de respuesta de la especificación del portal.
const RESPUESTA_OK: u32 = 0;
/// Cualquier fallo que no sea una cancelación de la persona.
const RESPUESTA_FALLO: u32 = 2;

pub struct SecretBackend {
    state: Arc<Mutex<KeyringState>>,
    conn: zbus::Connection,
}

impl SecretBackend {
    pub fn new(state: Arc<Mutex<KeyringState>>, conn: zbus::Connection) -> Self {
        Self { state, conn }
    }
}

#[interface(name = "org.freedesktop.impl.portal.Secret")]
impl SecretBackend {
    /// Escribe en `fd` el secreto maestro de `app_id`.
    ///
    /// No pregunta nada a la persona, y es correcto que no lo haga: no está
    /// entregando **sus** secretos, está dándole a la aplicación una clave propia
    /// que el escritorio guarda por ella. Un diálogo acá no tendría qué decir.
    async fn retrieve_secret(
        &self,
        handle: ObjectPath<'_>,
        app_id: String,
        fd: zbus::zvariant::OwnedFd,
        options: HashMap<String, OwnedValue>,
    ) -> (u32, HashMap<String, OwnedValue>) {
        // Nombrados sin guion bajo porque los nombres viajan: aparecen en la
        // introspección que lee el portal y cualquiera que lo esté depurando.
        //
        // `handle` serviría para que el portal cancele el pedido; esto contesta
        // enseguida y no hay nada que cancelar. En `options` no hay nada que la
        // especificación defina para esta llamada.
        let _ = (handle, options);

        let secreto = match secreto_maestro_de_app(&self.state, &self.conn, &app_id).await {
            Ok(secreto) => secreto,
            Err(e) => {
                eprintln!("vasak-keyring: no se pudo dar el secreto de «{app_id}»: {e}");
                return (RESPUESTA_FALLO, HashMap::new());
            }
        };

        match escribir_en_descriptor(fd, &secreto) {
            Ok(()) => (RESPUESTA_OK, HashMap::new()),
            Err(e) => {
                eprintln!("vasak-keyring: no se pudo escribir el secreto de «{app_id}»: {e}");
                (RESPUESTA_FALLO, HashMap::new())
            }
        }
    }

    /// El portal lee esto antes de usar un backend.
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        1
    }
}

/// Escribe el secreto y cierra.
///
/// El cierre es lo que le dice al cliente que terminó: del otro lado se lee hasta
/// el fin del flujo. Dejando el descriptor abierto, la aplicación se queda
/// esperando para siempre —el mismo error que la terminal tuvo con el PTY—.
///
/// `into_raw_fd` no sirve acá: hay que tomar la propiedad para que el `File` lo
/// cierre al salir del alcance, y no duplicarlo.
fn escribir_en_descriptor(
    fd: zbus::zvariant::OwnedFd,
    secreto: &[u8],
) -> Result<(), std::io::Error> {
    let crudo = fd.as_raw_fd();
    // Se olvida el `OwnedFd` de zvariant para que no lo cierre dos veces: desde
    // acá lo maneja el `File`.
    std::mem::forget(fd);
    let propio = unsafe { OwnedFd::from_raw_fd(crudo) };
    let mut archivo = std::fs::File::from(propio);

    archivo.write_all(secreto)?;
    archivo.flush()
    // El `File` se cierra al salir, y ese cierre es la señal de fin.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_nombre_del_backend_coincide_con_el_portal_instalado() {
        // El portal busca este nombre exacto en el archivo .portal que se
        // instala al lado. Si dejaran de coincidir, el backend no se usaría y no
        // habría ningún error: los secretos irían al backend que quedara.
        let portal = include_str!("../packaging/vasak-keyring.portal");
        assert!(
            portal.contains(&format!("DBusName={NOMBRE_BACKEND}")),
            "el .portal no nombra a {NOMBRE_BACKEND}"
        );
        assert!(
            portal.contains("Interfaces=org.freedesktop.impl.portal.Secret;"),
            "el .portal no declara la interfaz Secret"
        );
    }

    #[test]
    fn el_portal_se_declara_para_el_escritorio_correcto() {
        // Decía «VasakOS» en el otro .portal del sistema y no coincidía con
        // nada, así que el backend nunca se elegía.
        let portal = include_str!("../packaging/vasak-keyring.portal");
        assert!(portal.contains("UseIn=Vasak;"), "UseIn tiene que ser Vasak");
    }

    /// Que lo escrito sea exactamente el secreto, y que el descriptor quede
    /// cerrado — que es lo que le dice al cliente que terminó.
    #[test]
    fn se_escribe_el_secreto_y_se_cierra() {
        use std::io::Read;
        use std::os::fd::IntoRawFd;

        let (lector, escritor) = std::os::unix::net::UnixStream::pair().expect("par de sockets");
        let crudo = escritor.into_raw_fd();
        let como_zvariant =
            zbus::zvariant::OwnedFd::from(unsafe { OwnedFd::from_raw_fd(crudo) });

        let secreto = b"un secreto de prueba con acentos: \xc3\xb1";
        escribir_en_descriptor(como_zvariant, secreto).expect("escribir");

        let mut recibido = Vec::new();
        // Termina porque el otro lado se cerró. Si no se cerrara, esto no vuelve.
        let mut lector = lector;
        lector.read_to_end(&mut recibido).expect("leer");
        assert_eq!(recibido, secreto);
    }
}
