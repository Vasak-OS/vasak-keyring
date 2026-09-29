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
//!
//! # Quién puede llamar
//!
//! El `app_id` lo dice quien llama, y el backend no tiene forma de verificarlo:
//! así está diseñado el portal, porque el que sí puede verificarlo es
//! xdg-desktop-portal —lo deriva del sandbox del proceso que le pidió—. La
//! consecuencia es que **cualquiera que pueda llamar acá directamente puede pedir
//! el secreto de cualquier aplicación**, pasando su `app_id`. Con un diálogo de
//! permiso eso sería una molestia; con una clave, es entregar los datos de otro.
//!
//! Por eso dos cosas:
//!
//! 1. Se comprueba que quien llama **sea** el portal. Se lo pregunta el bus, que
//!    es la única fuente de verdad: la conexión del pedido tiene que ser la que
//!    tiene tomado `org.freedesktop.portal.Desktop`. Antes se preguntaba por el
//!    ejecutable del pid, y eso dejó de poder contestarse —ver
//!    [`deja_pasar`]—, que es lo que dejó al backend sin darle secreto a nadie.
//! 2. Va en una **conexión propia** al bus, aparte de la que sirve el Secret
//!    Service. Con las dos en la misma conexión, un permiso de sandbox concedido
//!    sobre `org.freedesktop.secrets` alcanzaría para hablar con este backend: el
//!    proxy de D-Bus filtra por nombre, y todos los nombres de una conexión
//!    comparten el mismo nombre único.

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

/// El nombre que xdg-desktop-portal toma en el bus de la sesión.
///
/// La fuente de verdad de «¿es el portal?». Mientras el portal esté andando lo
/// tiene tomado, y un `RequestName` de cualquiera que no sea él vuelve con
/// `org.freedesktop.DBus.Error.NameExists`: eso es lo que hace la prueba
/// imposible de suplantar desde la sesión. Lo que sí puede es tomar el nombre
/// **después** de que el portal muera, y para entonces no queda a quién
/// engañar: sin portal no hay pedidos que darle la vuelta.
const NOMBRE_DEL_PORTAL: &str = "org.freedesktop.portal.Desktop";

/// El ejecutable que refuerza que quien llama es el portal.
///
/// Antes era la única condición, y sola no podía ser: `/proc/<pid>/exe` de un
/// proceso de la sesión da `EACCES` desde adentro del namespace de usuario en que
/// corre la unidad —lo crea cualquiera de `PrivateTmp`, `ProtectSystem`,
/// `PrivateDevices`, `ProtectHostname` o `ProtectClock`, y no se elige cuál—,
/// y la lectura se tragaba el error con `.ok()`. El backend rechazaba entonces al
/// portal de verdad y sin dejar rastro.
///
/// La ruta está en `/usr/lib`, donde escribir requiere root, así que ningún
/// programa del usuario puede hacerse pasar por él.
const EJECUTABLE_DEL_PORTAL: &str = "/usr/lib/xdg-desktop-portal";

/// Si el ejecutable es el del portal.
///
/// `None` es «no se pudo saber», no «sí». Por eso la decisión de dejar pasar
/// no es la de acá sino la de [`deja_pasar`], que sabe qué hacer con ese `None`.
pub fn es_el_portal(ejecutable: Option<&str>) -> bool {
    ejecutable == Some(EJECUTABLE_DEL_PORTAL)
}

/// Si la conexión que llama es la del portal.
///
/// `duenia` es `None` cuando en el bus nadie tiene el nombre del portal, que no
/// es un fallo de la pregunta: es la respuesta, y significa que no hay nadie a
/// quien el pedido pueda haberle dado la vuelta.
pub fn es_del_portal(emisor: &str, duenia: Option<&str>) -> bool {
    duenia == Some(emisor)
}

/// La puerta, entera y sin bus.
///
/// Son dos condiciones, y la segunda depende de si el ejecutable se pudo leer:
///
/// 1. La conexión que llama tiene que ser la del portal. La contesta el bus, que
///    sí responde desde adentro del namespace de usuario de la unidad.
/// 2. Si el ejecutable de su pid se pudo leer, tiene que ser el del portal. Un
///    `None` acá no es un no: con la unidad aislada es lo de todos los pedidos, no
///    la excepción, y en ese caso decide la primera.
///
/// Que la segunda no baste por sí sola es justamente lo que la distingue de la
/// puerta anterior, que era la única y por eso no dejaba pasar a nadie.
pub fn deja_pasar(emisor: &str, duenia: Option<&str>, ejecutable: Option<&str>) -> bool {
    es_del_portal(emisor, duenia) && ejecutable.is_none_or(|ruta| es_el_portal(Some(ruta)))
}

/// Quién tiene un nombre en el bus, o `None` si nadie lo tiene.
///
/// `GetNameOwner` contesta con un error cuando el nombre no lo tiene nadie, y
/// eso no es una pregunta que salió mal: es la respuesta.
pub(crate) async fn dueno_de(conn: &zbus::Connection, nombre: &str) -> Result<Option<String>, zbus::Error> {
    const SIN_DUENO: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";

    match conn
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetNameOwner",
            &(nombre,),
        )
        .await
    {
        Ok(respuesta) => Ok(Some(respuesta.body().deserialize()?)),
        Err(zbus::Error::MethodError(del_error, _, _)) if del_error == SIN_DUENO => Ok(None),
        Err(e) => Err(e),
    }
}

/// El ejecutable del pid que el bus asocia a una conexión.
///
/// Va aparte de la puerta porque casi siempre **no se puede saber**, y cuando no
/// se puede hay que decirlo: el `Err` es el motivo, y suele ser `EACCES` del
/// namespace de usuario de la unidad. Tragar el error con `.ok()` es lo que
/// dejó al portal afuera sin que se viera.
async fn ejecutable_de(conn: &zbus::Connection, emisor: &str) -> Result<String, String> {
    let pid: u32 = conn
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetConnectionUnixProcessID",
            &(emisor,),
        )
        .await
        .and_then(|r| r.body().deserialize())
        .map_err(|e| format!("el bus no dio el pid de {emisor}: {e}"))?;

    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|r| r.to_string_lossy().into_owned())
        .map_err(|e| format!("no se pudo leer /proc/{pid}/exe: {e}"))
}

pub struct SecretBackend {
    state: Arc<Mutex<KeyringState>>,
    conn: zbus::Connection,
}

impl SecretBackend {
    pub fn new(state: Arc<Mutex<KeyringState>>, conn: zbus::Connection) -> Self {
        Self { state, conn }
    }
}

impl SecretBackend {
    /// Si el mensaje viene de la conexión del portal.
    ///
    /// La pregunta se la hace al bus, que contesta desde adentro del namespace de
    /// usuario de la unidad. El ejecutable del pid se mira después, y sólo de
    /// refuerzo: se deja constancia cuando no se puede leer, porque es lo que pasa
    /// siempre y antes era la única condición, con el error tragado y sin rastro.
    ///
    /// Cada negativa dice su motivo. Antes todas decían lo mismo —«no viene del
    /// portal»—, que era cierto y no servía para nada: no distinguía un impostor
    /// de un `/proc` que no se deja leer, que es el caso real.
    async fn llama_el_portal(&self, cabecera: &zbus::message::Header<'_>) -> bool {
        let emisor = match cabecera.sender() {
            Some(emisor) => emisor.as_str().to_owned(),
            None => {
                eprintln!(
                    "vasak-keyring: se rechaza un pedido de secreto que vino sin emisor en la \
                     cabecera"
                );
                return false;
            }
        };

        let duenia = match dueno_de(&self.conn, NOMBRE_DEL_PORTAL).await {
            Ok(duenia) => duenia,
            Err(e) => {
                eprintln!(
                    "vasak-keyring: se rechaza un pedido de secreto de {emisor}: no se pudo \
                     preguntar al bus quién tiene {NOMBRE_DEL_PORTAL}: {e}"
                );
                return false;
            }
        };

        let ejecutable = match ejecutable_de(&self.conn, &emisor).await {
            Ok(ejecutable) => Some(ejecutable),
            Err(motivo) => {
                // No es un no. Queda anotado igual, porque es el caso de todos los
                // pedidos con la unidad aislada y es lo primero que hay que ver si
                // la puerta vuelve a rechazar a alguien.
                eprintln!(
                    "vasak-keyring: de {emisor} no se pudo saber el ejecutable: {motivo}. La \
                     puerta queda con la comparación del nombre solamente, que es lo que \
                     corresponde: con la unidad aislada, /proc/<pid>/exe de la sesión no se deja leer"
                );
                None
            }
        };

        if deja_pasar(&emisor, duenia.as_deref(), ejecutable.as_deref()) {
            return true;
        }

        if !es_del_portal(&emisor, duenia.as_deref()) {
            match duenia.as_deref() {
                Some(duenia) => eprintln!(
                    "vasak-keyring: se rechaza un pedido de secreto de {emisor}: no es el \
                     portal, y {NOMBRE_DEL_PORTAL} lo tiene {duenia}"
                ),
                None => eprintln!(
                    "vasak-keyring: se rechaza un pedido de secreto de {emisor}: en el bus nadie \
                     tiene {NOMBRE_DEL_PORTAL}, así que no hay portal al que se lo hayan pedido"
                ),
            }
        } else {
            eprintln!(
                "vasak-keyring: se rechaza un pedido de secreto de {emisor}: tiene el nombre del \
                 portal pero su ejecutable es {} y no {EJECUTABLE_DEL_PORTAL}",
                ejecutable.unwrap_or_default()
            );
        }
        false
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
        #[zbus(header)] cabecera: zbus::message::Header<'_>,
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

        // Sólo el portal. Cualquier otro proceso podría pedir el secreto de
        // cualquier aplicación pasando su `app_id`: el backend no puede verificar
        // ese dato, sólo puede verificar quién lo trae.
        if !self.llama_el_portal(&cabecera).await {
            eprintln!("vasak-keyring: se rechaza un pedido de secreto que no viene del portal");
            return (RESPUESTA_FALLO, HashMap::new());
        }

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
    use std::collections::BTreeSet;
    use std::path::PathBuf;

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

    /// Si el ejecutable es el del portal, y sólo el del portal.
    ///
    /// Esto ya **no** es la puerta: es el refuerzo de la segunda condición de
    /// [`deja_pasar`]. Si esta función desapareciera, la puerta seguiría
    /// cerrando, porque la primera condición —que la conexión que llama tenga
    /// tomado `org.freedesktop.portal.Desktop`— no se toca. Y es la que
    /// comprueba lo que el nombre no alcanza: un nombre lo puede tomar, después
    /// de morir quien lo tenía, cualquiera que llegue al `RequestName` primero.
    ///
    /// Sigue siendo la que evita el agujero grande, el de pedir el secreto de
    /// otra aplicación pasando su `app_id`: eso lo dice quien llama y el backend
    /// no lo puede verificar. Nada de lo de arriba lo arregla por sí solo.
    #[test]
    fn solo_el_ejecutable_del_portal_puede_pedir() {
        assert!(es_el_portal(Some("/usr/lib/xdg-desktop-portal")));

        // Un impostor con nombre parecido, que es la forma en que este chequeo se
        // rompe si se hace con `contains` o `starts_with`.
        assert!(!es_el_portal(Some("/usr/lib/xdg-desktop-portal-falso")));
        assert!(!es_el_portal(Some("/tmp/xdg-desktop-portal")));
        assert!(!es_el_portal(Some("/usr/lib/xdg-desktop-portal-gtk")));
        assert!(!es_el_portal(Some("/usr/bin/algo")));
    }

    /// Lo que no se sabe no se convierte en permiso.
    ///
    /// `es_el_portal(None)` sigue dando `false`, y conviene que siga: la función
    /// no puede afirmar que un ejecutable que no leyó es el del portal.
    ///
    /// Lo que cambia es lo que ese `false` significa. Antes el `None` era la
    /// puerta entera —el `.ok()` se lo tragaba y el pedido moría ahí—, y por eso
    /// decir «no» parecía lo prudente. Hoy es la segunda condición de
    /// [`deja_pasar`], que con el nombre confirmado **entra igual**: con la
    /// unidad aislada, `/proc/<pid>/exe` de la sesión no se puede leer, y eso es
    /// lo de todos los pedidos y no la excepción.
    ///
    /// El hueco sigue cerrado, pero por la otra condición, y ésa no se abre desde
    /// adentro: un `None` no es una puerta, es la falta de una comparación.
    #[test]
    fn sin_poder_saber_quien_llama_se_dice_que_no() {
        assert!(!es_el_portal(None));
    }

    /// Dónde está el ejecutable del portal en esta máquina.
    ///
    /// La constante nombra una sola ruta, y mudarse de ruta es justo lo que esta
    /// prueba tiene que detectar: si el ejecutable se movió, la segunda condición
    /// de [`deja_pasar`] deja de reconocer al portal de verdad y el backend se
    /// apaga en silencio, sin ningún otro síntoma. Así que el portal se busca en
    /// todos los lugares donde un paquete lo pondría, no sólo en el que dice la
    /// constante.
    ///
    /// Las rutas vuelven **resueltas**, sin enlaces, porque lo que se compara en
    /// producción es `/proc/<pid>/exe`, que es el ejecutable real: un enlace en
    /// `/usr/bin` tiene que contar como lo que apunta, y no como `/usr/bin`.
    ///
    /// Una lista vacía significa que en esta máquina no hay portal. No es un
    /// fallo: es el runner del CI, que no es una máquina de VasakOS.
    fn rutas_del_portal_instaladas() -> BTreeSet<PathBuf> {
        const NOMBRE: &str = "xdg-desktop-portal";

        let mut candidatas = vec![PathBuf::from(EJECUTABLE_DEL_PORTAL)];
        if let Some(path) = std::env::var_os("PATH") {
            candidatas.extend(std::env::split_paths(&path).map(|dir| dir.join(NOMBRE)));
        }
        // El `PATH` solo no alcanza: en Arch el ejecutable vive en `/usr/lib` sin
        // enlace en `/usr/bin`, y una mudanza a `libexec` tampoco suele ponerse
        // en el `PATH`. Estos son los dos directorios donde un paquete la pondría.
        candidatas.extend(
            [
                "/usr/lib",
                "/usr/libexec",
                "/usr/local/lib",
                "/usr/local/libexec",
            ]
            .into_iter()
            .map(|dir| PathBuf::from(dir).join(NOMBRE)),
        );

        candidatas
            .into_iter()
            .filter(|candidata| candidata.is_file())
            .filter_map(|candidata| candidata.canonicalize().ok())
            .collect()
    }

    /// El ejecutable que se exige tiene que ser el que la máquina realmente
    /// tiene.
    ///
    /// Antes miraba una sola cosa —que la ruta de la constante exista— y con eso
    /// ya no miraba nada: el commit anterior la hizo saltarse cuando el portal no
    /// estaba, porque el runner del CI no es una máquina de VasakOS, y lo que
    /// quedó después de ese salto era exactamente la condición del salto. La
    /// afirmación no podía fallar nunca, y con el portal mudado la prueba se
    /// saltaba: el backend dejaba de darle secreto a nadie y la suite en verde.
    ///
    /// Ahora el portal se busca donde esté y se lo compara con lo que acepta
    /// `es_el_portal`, que es lo que importa. Sin portal en la máquina se dice
    /// que se saltó, que es el caso del runner del CI; con portal, se mira.
    #[test]
    fn el_portal_instalado_esta_donde_la_puerta_lo_busca() {
        let rutas = rutas_del_portal_instaladas();
        if rutas.is_empty() {
            println!(
                "se salta: en esta máquina no hay xdg-desktop-portal, \
                 así que no hay ejecutable real contra el que comparar"
            );
            return;
        }

        // Que alguna coincida y no que todas: una máquina puede tener un portal
        // propio además del del sistema, y lo que importa es que al del sistema
        // —el único que el escritorio arranca— lo dejen entrar.
        let aceptadas: Vec<&PathBuf> = rutas
            .iter()
            .filter(|ruta| es_el_portal(ruta.to_str()))
            .collect();

        assert!(
            !aceptadas.is_empty(),
            "la puerta sólo acepta a {EJECUTABLE_DEL_PORTAL} y el portal de esta máquina está \
             en {rutas:?}: hay que cambiar EJECUTABLE_DEL_PORTAL, o el backend no le va a \
             dar secreto a nadie"
        );
    }

    // ── La puerta, entera y sin bus ──────────────────────────────────────
    //
    // Lo que se comprueba acá es la puerta de `deja_pasar`, que es donde se
    // decide. Las dos condiciones y el `None` de cada una se prueban por
    // separado, porque lo que se rompió fue justo ese `None`: con la unidad
    // aislada, `/proc/<pid>/exe` de la sesión no se deja leer, y la puerta
    // anterior —`es_el_portal(None)` y nada más— rechazaba al portal de verdad.
    //
    // Estos casos son los que la puerta anterior no tenía: con un `None` en
    // `ejecutable` no se podía ni decidir, y `es_del_portal` no existía.

    /// La condición que decide sola: la conexión que llama tiene que ser la que
    /// tiene tomado el nombre del portal.
    #[test]
    fn es_del_portal_solo_cuando_el_nombre_lo_tiene_el_mismo() {
        let portal = ":1.42";

        assert!(es_del_portal(portal, Some(portal)));

        // Otra conexión: el nombre es del portal, pero el pedido viene de otro.
        assert!(!es_del_portal(":1.99", Some(portal)));
        // Nadie tiene el nombre. No es un fallo de la pregunta: es la respuesta.
        assert!(!es_del_portal(portal, None));
    }

    /// El caso del bug: el portal de verdad, con su `/proc/<pid>/exe` ilegible.
    ///
    /// Es la situación de la unidad como está —`PrivateTmp`, `ProtectSystem`,
    /// `PrivateDevices`, `ProtectHostname`, `ProtectClock` la encierran en un
    /// namespace de usuario propio—, y la que hace que un `None` acá sea lo de
    /// todos los pedidos y no la excepción. Antes esto daba `false` y el
    /// backend no le daba el secreto a nadie, tampoco al portal.
    #[test]
    fn el_portal_pasa_aunque_no_se_pueda_leer_su_ejecutable() {
        let portal = ":1.42";

        assert!(deja_pasar(portal, Some(portal), None));
    }

    /// Con el ejecutable legible, tiene que ser el del portal.
    ///
    /// La segunda condición no se afloja por lo anterior: sólo deja de decidir
    /// cuando no hay nada que comparar. Si el ejecutable se pudo leer y no es el
    /// del portal, el que tiene el nombre tampoco pasa.
    #[test]
    fn el_duenio_del_nombre_no_pasa_con_otro_ejecutable() {
        let portal = ":1.42";

        assert!(deja_pasar(
            portal,
            Some(portal),
            Some(EJECUTABLE_DEL_PORTAL)
        ));
        assert!(!deja_pasar(portal, Some(portal), Some("/usr/bin/algo")));
        // Un impostor con nombre parecido, que es la forma en que este chequeo se
        // rompe si se hace con `contains` o `starts_with`.
        assert!(!deja_pasar(
            portal,
            Some(portal),
            Some("/usr/lib/xdg-desktop-portal-falso")
        ));
    }

    /// El ejecutable del portal no alcanza: el nombre es lo que se exige.
    ///
    /// Al revés de los casos anteriores, y es el que importa para la seguridad:
    /// un programa cualquiera que achieve a parecer el portal —con el nombre
    /// del portal, o con un ejecutable que se le parezca— no puede pedir el
    /// secreto de otra aplicación, porque el nombre del portal no lo tiene él.
    #[test]
    fn el_ejecutable_del_portal_no_alcanza_sin_el_nombre() {
        let impostor = ":1.99";

        // Nombre del portal, ejecutable del portal, y no es el portal: el
        // impostor queda afuera igual.
        assert!(!deja_pasar(
            impostor,
            Some(":1.42"),
            Some(EJECUTABLE_DEL_PORTAL)
        ));
        // Y tampoco cuando su ejecutable tampoco se puede leer: sin nombre no
        // hay caso en que se sepa algo de él.
        assert!(!deja_pasar(impostor, Some(":1.42"), None));
        // El nombre no lo tiene nadie: no hay portal al que se lo hayan pedido.
        assert!(!deja_pasar(impostor, None, Some(EJECUTABLE_DEL_PORTAL)));
        assert!(!deja_pasar(impostor, None, None));
    }

    // ── La puerta, con un bus de verdad detrás ────────────────────────
    //
    // Lo de arriba decide la puerta sin bus. Acá se la decide **con** un bus:
    // dos puntas de un `UnixStream::pair()` —el patrón de `dbus_api`—, con un
    // `org.freedesktop.DBus` falso en la otra punta que contesta lo que el bus
    // de la sesión contestaría.
    //
    // Es la capa que faltaba, porque lo que el arreglo volvió importante son
    // dos cosas que antes no existían: preguntar al bus quién tiene
    // `org.freedesktop.portal.Desktop`, y **no** leer el `Err` de
    // `/proc/<pid>/exe` como un «no». Las dos viajan por el bus, y una función
    // de Rust a la que se le pasa un `Option` no las prueba.
    //
    // El bus falso se publica en `/org/freedesktop/DBus`, que es adonde
    // pregunta el backend: si algún día el backend preguntara en otro lado,
    // estas pruebas se quedan esperando una respuesta que no llega y fallan
    // nombrando el caso, en vez de pasar en silencio.

    const RUTA_BUS: &str = "/org/freedesktop/DBus";
    const IFACE_SECRET: &str = "org.freedesktop.impl.portal.Secret";
    const METODO: &str = "RetrieveSecret";
    const REQUERIMIENTO: &str = "/org/freedesktop/portal/desktop/request/s1";
    const APP_ID: &str = "org.example.Aplicacion";
    const ESPERA: std::time::Duration = std::time::Duration::from_secs(10);
    /// Cuánto se espera a que una conexión recién hecha conteste algo. Es el
    /// tiempo de entre un mensaje y el siguiente, no el de una prueba: si una
    /// pregunta de la prueba se pierde, el fallo lo tiene que decir la prueba.
    const ESPERA_DE_ENTRADA: std::time::Duration = std::time::Duration::from_millis(500);

    /// El bus mínimo que la puerta necesita: sólo las dos preguntas que hace.
    ///
    /// `preguntados` guarda por qué nombres se preguntó, porque el nombre es
    /// la fuente de verdad de la puerta y una errata ahí no se ve: abriría la
    /// puerta a quien tenga el nombre mal escrito y cerraría al de verdad.
    struct BusFalso {
        /// Quién contesta tener el nombre del portal. `None` es el
        /// `NameHasNoOwner` de verdad, no una respuesta que no llega.
        duenia: Option<String>,
        /// El pid que el bus le atribuye a la conexión del emisor.
        pid: u32,
        preguntados: Arc<Mutex<Vec<String>>>,
    }

    #[interface(name = "org.freedesktop.DBus")]
    impl BusFalso {
        #[zbus(name = "GetNameOwner")]
        async fn duenia_de(&self, nombre: &str) -> Result<String, zbus::fdo::Error> {
            self.preguntados.lock().await.push(nombre.to_owned());
            match &self.duenia {
                Some(duenia) => Ok(duenia.clone()),
                // El error con el que un bus de verdad contesta que nadie tiene
                // el nombre. Es una respuesta, no una pregunta que salió mal, y
                // es lo que `dueno_de` tiene que traducir a `None`.
                None => Err(zbus::fdo::Error::NameHasNoOwner(nombre.to_owned())),
            }
        }

        // En `PascalCase` como lo escribe el bus, y no como lo dejaría el
        // `PascalCase` automático: produciría `GetConnectionUnixProcessId` y
        // el bus de verdad no lo entiende.
        #[zbus(name = "GetConnectionUnixProcessID")]
        fn pid_de(&self, _emisor: &str) -> u32 {
            self.pid
        }
    }

    /// Lo que contestó el backend y qué llegó al descriptor.
    struct Pedido {
        codigo: u32,
        opciones: HashMap<String, OwnedValue>,
        secreto: Vec<u8>,
    }

    /// La puerta de prueba: el backend de un lado, el bus falso del otro.
    struct Escenario {
        /// La conexión en la que vive el backend, y de la que sale al bus.
        demonio: zbus::Connection,
        /// La otra punta: de aquí sale el pedido, con el emisor que se quiera.
        portal: zbus::Connection,
        /// Otra instancia del backend, sólo para poder preguntarle a
        /// `llama_el_portal` sin pasar por el bus.
        puerta: SecretBackend,
        preguntados: Arc<Mutex<Vec<String>>>,
    }

    impl Escenario {
        /// Levanta el bus falso y deja el backend listo en la otra punta.
        ///
        /// `duenia` es la respuesta a «¿quién tiene el nombre del portal?» y
        /// `pid` el pid que el bus le atribuye al emisor. Cambiar cualquiera de
        /// los dos cambia el caso que se está probando.
        async fn nuevo(duenia: Option<&str>, pid: u32) -> Self {
            let (extremo_del_demonio, extremo_del_portal) =
                tokio::net::UnixStream::pair().expect("par de sockets");
            let demonio = zbus::connection::Builder::unix_stream(extremo_del_demonio)
                .server(zbus::Guid::generate())
                .expect("guid del bus de la prueba")
                .p2p()
                .build();
            let portal = zbus::connection::Builder::unix_stream(extremo_del_portal)
                .p2p()
                .build();
            let (demonio, portal) = tokio::join!(demonio, portal);
            let demonio = demonio.expect("no se pudo levantar el bus de la prueba");
            let portal = portal.expect("no se pudo levantar la otra punta");

            let preguntados = Arc::new(Mutex::new(Vec::new()));
            portal
                .object_server()
                .at(
                    RUTA_BUS,
                    BusFalso {
                        duenia: duenia.map(str::to_owned),
                        pid,
                        preguntados: Arc::clone(&preguntados),
                    },
                )
                .await
                .expect("no se pudo publicar el bus falso");

            let estado = Arc::new(Mutex::new(KeyringState::new()));
            let escenario = Self {
                puerta: SecretBackend::new(Arc::clone(&estado), demonio.clone()),
                demonio,
                portal,
                preguntados,
            };
            escenario.calentar().await;
            escenario
        }

        /// Publica el backend en el bus, para poder llamarlo como lo llamaría
        /// el portal.
        ///
        /// Va aparte y no en `nuevo` a propósito: lo que hay detrás de la puerta
        /// es `secreto_maestro_de_app`, que escribe en el llavero de verdad de
        /// quien corre la prueba. Las pruebas de la puerta no lo necesitan —
        /// con la cabecera que llegó ya se contesta — y así ninguna puede llegar
        /// a escribir aunque la máquina de quien las corra tenga una contraseña
        /// maestra puesta.
        async fn publicar_backend(&self) {
            self.demonio
                .object_server()
                .at(
                    RUTA_BACKEND,
                    SecretBackend::new(
                        Arc::new(Mutex::new(KeyringState::new())),
                        self.demonio.clone(),
                    ),
                )
                .await
                .expect("no se pudo publicar el backend");
        }

        /// Una ida y vuelta antes de que la prueba pregunte nada.
        ///
        /// Recién construida la conexión, el primer mensaje se pierde: la otra
        /// punta todavía no está leyendo. Es una cosa de `p2p` y no del
        /// backend, pero sin esto la primera pregunta de cada prueba se queda
        /// esperando una respuesta que no va a llegar, y el fallo aparece como
        /// una compuerta de tiempo y no como lo que es.
        ///
        /// El intento perdido se corta rápido a propósito: no está fallando,
        /// está abriendo la conexión, y hacerlo esperar `ESPERA` agregaría
        /// segundos a cada prueba sin decir nada.
        async fn calentar(&self) {
            for _ in 0..5 {
                if tokio::time::timeout(
                    ESPERA_DE_ENTRADA,
                    dueno_de(&self.demonio, NOMBRE_DEL_PORTAL),
                )
                .await
                .is_ok()
                {
                    return;
                }
            }
            panic!("el bus de la prueba no contestó ni una vez: la conexión no quedó viva");
        }

        /// El pedido de secreto, tal como lo mandaría el portal, y el otro
        /// extremo del descriptor para poder leer lo que llegue.
        ///
        /// Los dos van juntos porque el descriptor del pedido y el que se lee
        /// son la misma cosa partida en dos: si fueran dos pares distintos, lo
        /// que el backend escribiera caería en un socket que nadie mira.
        ///
        /// `emisor` va en la cabecera a propósito. Sobre una conexión punto a
        /// punto no hay `dbus-daemon` que le asigne un nombre único a nadie:
        /// `unique_name()` es `None` y el emisor de un mensaje también, así que
        /// sin esto **todo** pedido entraría por la rama de «vino sin emisor» y
        /// ninguna de estas pruebas probaría la puerta. Poner el nombre en la
        /// cabecera es justo lo que un bus real garantiza —es el broker el que
        /// lo pone, nunca el que pide—, y es lo que hace falta para poder
        /// fingir ser el portal o un impostor.
        fn mandar(&self, emisor: Option<&str>) -> (zbus::Message, std::os::unix::net::UnixStream) {
            use std::os::fd::{FromRawFd, IntoRawFd};

            let (lectura, escritura) =
                std::os::unix::net::UnixStream::pair().expect("par de sockets");
            // El descriptor viaja dentro del mensaje, así que el `OwnedFd` se lo
            // queda zvariant y lo manda como el `h` que espera D-Bus.
            let descriptor = zbus::zvariant::OwnedFd::from(unsafe {
                OwnedFd::from_raw_fd(escritura.into_raw_fd())
            });

            let (handle, app_id, opciones): (ObjectPath, String, HashMap<String, OwnedValue>) = (
                ObjectPath::try_from(REQUERIMIENTO).expect("ruta del requerimiento"),
                APP_ID.to_owned(),
                HashMap::new(),
            );
            let mut armado = zbus::Message::method_call(RUTA_BACKEND, METODO)
                .expect("no se pudo armar el pedido")
                .interface(IFACE_SECRET)
                .expect("interfaz del pedido");
            if let Some(emisor) = emisor {
                armado = armado.sender(emisor).expect("emisor del pedido");
            }
            let pedido = armado
                .build(&(handle, app_id, descriptor, opciones))
                .expect("no se pudo serializar el pedido");
            (pedido, lectura)
        }

        /// Lo que el backend hace con un pedido de `emisor`, sin mandarlo por el
        /// bus de vuelta.
        ///
        /// Devuelve el `true` o el `false` de `llama_el_portal` sobre la
        /// cabecera **real** del mensaje que llegó, que es lo que decide. Se
        /// apoya en que zbus reparte lo que entra a todos los que escuchan, así
        /// que el servidor de objetos y esta escucha ven el mismo mensaje.
        async fn puerta_para(&self, emisor: Option<&str>) -> bool {
            use futures_util::StreamExt;

            let (pedido, _descriptor) = self.mandar(emisor);
            let mut entrantes = zbus::MessageStream::from(&self.demonio);
            let espera = tokio::spawn(async move {
                while let Some(mensaje) = entrantes.next().await {
                    let Ok(mensaje) = mensaje else { continue };
                    if mensaje.header().message_type() == zbus::message::Type::MethodCall {
                        return Some(mensaje);
                    }
                }
                None
            });
            self.portal.send(&pedido).await.expect("mandar el pedido");

            let mensaje = tokio::time::timeout(ESPERA, espera)
                .await
                .unwrap_or_else(|_| panic!("el pedido no llegó al backend en {ESPERA:?}"))
                .ok()
                .flatten()
                .unwrap_or_else(|| panic!("se cortó la conexión antes de que el pedido llegara"));

            self.puerta.llama_el_portal(&mensaje.header()).await
        }

        /// El pedido completo, por el bus: lo que contesta el backend y qué
        /// llega al descriptor.
        async fn pedir(&self, emisor: Option<&str>) -> Pedido {
            use futures_util::StreamExt;
            use std::io::Read;

            let (pedido, mut lectura) = self.mandar(emisor);
            let serial = pedido.header().primary().serial_num();

            let mut salientes = zbus::MessageStream::from(&self.portal);
            self.portal.send(&pedido).await.expect("mandar el pedido");

            let respuesta = tokio::time::timeout(ESPERA, async {
                while let Some(mensaje) = salientes.next().await {
                    let Ok(mensaje) = mensaje else { continue };
                    if mensaje.header().reply_serial() == Some(serial) {
                        return Some(mensaje);
                    }
                }
                None
            })
            .await
            .unwrap_or_else(|_| panic!("el backend no contestó al pedido en {ESPERA:?}"))
            .unwrap_or_else(|| panic!("nunca llegó la respuesta con serial {serial}"));

            let (codigo, opciones) = respuesta
                .body()
                .deserialize()
                .expect("la respuesta de RetrieveSecret no se entiende");

            // Suelta el mensaje antes de leer: es el que todavía tiene el otro
            // extremo del descriptor, y sin soltarlo la lectura de abajo no
            // termina nunca.
            drop(pedido);
            let secreto = tokio::task::spawn_blocking(move || {
                let mut recibido = Vec::new();
                lectura
                    .read_to_end(&mut recibido)
                    .expect("leer el descriptor");
                recibido
            })
            .await
            .expect("la lectura del descriptor");

            Pedido {
                codigo,
                opciones,
                secreto,
            }
        }
    }

    /// Un pid que no existe, sin adivinar un número alto.
    ///
    /// Lo que la unidad aislada produce no es un `ENOENT` sino un `EACCES`, y
    /// sin namespaces no se puede provocar un `EACCES` de verdad sobre
    /// `/proc/<pid>/exe`. Para la puerta es lo mismo: la lectura falla,
    /// `ejecutable_de` devuelve `Err` y de ese `Err` sale el `None` con el que
    /// `deja_pasar` tiene que decidir. Lo que cambia es el motivo, y la puerta
    /// no lo mira.
    fn pid_inexistente() -> u32 {
        (1..)
            .map(|n| u32::MAX - n)
            .find(|pid| !PathBuf::from(format!("/proc/{pid}")).exists())
            .expect("algún pid tiene que estar libre")
    }

    /// El nombre que decide se le pregunta al bus, y se le pregunta al del
    /// portal.
    ///
    /// Es lo que hace de la puerta una puerta y no un chequeo de un nombre. La
    /// pregunta viaja como un `GetNameOwner` de verdad, y lo que se mira es el
    /// nombre que salió por el cable, no el que la función dice que pregunta.
    #[tokio::test]
    async fn el_nombre_que_decide_se_le_pregunta_al_bus() {
        let escenario = Escenario::nuevo(Some(":1.42"), std::process::id()).await;

        let duenia = dueno_de(&escenario.demonio, NOMBRE_DEL_PORTAL)
            .await
            .expect("el bus tiene que contestar");
        assert_eq!(
            duenia.as_deref(),
            Some(":1.42"),
            "el bus dijo que {NOMBRE_DEL_PORTAL} lo tiene :1.42 y eso es lo que tiene que volver"
        );

        let preguntados = escenario.preguntados.lock().await;
        assert!(
            preguntados.iter().all(|nombre| nombre == NOMBRE_DEL_PORTAL),
            "la puerta tiene que preguntar sólo por {NOMBRE_DEL_PORTAL} y preguntó por {preguntados:?}: \
             con otro nombre se le abre a quien lo tenga y se le cierra al portal"
        );
    }

    /// Un nombre que no tiene nadie es una respuesta, no una pregunta que salió
    /// mal.
    ///
    /// `GetNameOwner` contesta con `NameHasNoOwner` cuando nadie tomó el nombre,
    /// y ese error es la respuesta. Si se lo tomara por un fallo, entonces en
    /// una máquina donde el portal todavía no arrancó —o donde se está
    /// apagando— se rechazaría a todo el mundo con una causa inventada; y si se
    /// tradujera a `Some`, se le abriría la puerta a la primera conexión que
    /// apareciera.
    #[tokio::test]
    async fn un_nombre_sin_dueno_es_una_respuesta_y_no_un_fallo() {
        let escenario = Escenario::nuevo(None, std::process::id()).await;

        let duenia = dueno_de(&escenario.demonio, NOMBRE_DEL_PORTAL).await;
        assert_eq!(
            duenia,
            Ok(None),
            "que nadie tenga {NOMBRE_DEL_PORTAL} es la respuesta «nadie», y no un fallo: \
             un bus que contesta NameHasNoOwner está perfecto, y leerlo como error \
             rechazaría a todo el mundo con un motivo que no ocurrió"
        );
    }

    /// El ejecutable se busca por el pid que el bus le da al emisor, y cuando no
    /// se puede leer se dice por qué.
    ///
    /// El `Err` importa: con la unidad aislada es lo que pasa con **todos** los
    /// pedidos, y antes se lo tragaba con `.ok()`, así que el motivo —el que
    /// sirve para entender por qué la puerta rechaza a alguien— desaparecía.
    #[tokio::test]
    async fn el_ejecutable_se_busca_por_el_pid_del_emisor() {
        let escenario = Escenario::nuevo(Some(":1.42"), std::process::id()).await;

        // Con un pid vivo, el ejecutable es el de ese proceso: el que sea, pero
        // el de verdad, y no una cadena cualquiera.
        let leido = ejecutable_de(&escenario.demonio, ":1.42")
            .await
            .expect("este proceso existe, su /proc tiene que poder leerse");
        assert_eq!(
            leido,
            std::fs::read_link("/proc/self/exe")
                .expect("leer el ejecutable de uno mismo")
                .to_string_lossy()
                .into_owned(),
            "el ejecutable que se busca tiene que ser el del pid que dio el bus"
        );

        // Con un pid que no existe, la lectura falla y el motivo queda dicho.
        let libre = pid_inexistente();
        let escenario = Escenario::nuevo(Some(":1.42"), libre).await;
        let motivo = ejecutable_de(&escenario.demonio, ":1.42")
            .await
            .expect_err("un pid que no existe no puede dar un ejecutable");
        assert!(
            motivo.contains(&format!("/proc/{libre}/exe")),
            "el motivo tiene que decir qué no se pudo leer, y no sólo que falló: dice {motivo:?}"
        );
    }

    /// El caso del bug, con bus: el portal de verdad entra con su `/proc`
    /// ilegible.
    ///
    /// Es la situación de la unidad como está —`PrivateTmp`, `ProtectSystem`,
    /// `PrivateDevices`, `ProtectHostname` y `ProtectClock` la encierran en un
    /// namespace de usuario propio— y la que dejó al backend sin darle el
    /// secreto a nadie: la puerta anterior era `es_el_portal(ejecutable)`, el
    /// `None` del `.ok()` le llegaba como «no es el portal», y el pedido moría
    /// ahí. La comparación del nombre dice que sí, el nombre lo tiene la misma
    /// conexión que pregunta, y eso alcanza.
    #[tokio::test]
    async fn el_portal_de_verdad_entra_aunque_no_se_sepa_su_ejecutable() {
        let escenario = Escenario::nuevo(Some(":1.42"), pid_inexistente()).await;

        assert!(
            escenario.puerta_para(Some(":1.42")).await,
            "el portal de verdad —el bus dice que :1.42 tiene {NOMBRE_DEL_PORTAL} y no se le puede \
             leer el ejecutable— tiene que entrar: es lo que devuelve el error de /proc a «no se \
             sé», y si vuelve a ser «no», el backend no le da el secreto a nadie y tampoco al portal"
        );
    }

    /// El refuerzo sigue siendo refuerzo: el nombre no tapa al ejecutable.
    ///
    /// Cuando el ejecutable **se pudo** leer tiene que ser el del portal. No es
    /// desconfianza del nombre —la confianza viene de que sea el broker el que
    /// lo asigna, y no el pedido el que lo diga—, sino que un nombre lo puede
    /// tomar después de morir quien lo tenía, y el ejecutable sigue diciendo si
    /// quien pregunta es el portal o no.
    #[tokio::test]
    async fn el_nombre_no_tapa_un_ejecutable_que_no_es_el_del_portal() {
        // El pid es el de la propia prueba, así que el ejecutable se puede leer
        // y sale siendo el del binario de pruebas, que no es el del portal.
        let escenario = Escenario::nuevo(Some(":1.42"), std::process::id()).await;

        assert!(
            !escenario.puerta_para(Some(":1.42")).await,
            "tener el nombre del portal y ejecutar otra cosa tiene que quedar afuera: \
             se leería /proc/<pid>/exe, no sería {EJECUTABLE_DEL_PORTAL}, y la segunda condición \
             de la puerta existe justo para eso"
        );
    }

    /// Un impostor no entra, y lo que lo prueba es el caso que el arreglo abrió.
    ///
    /// El nombre es lo único que decide cuando el ejecutable no se puede leer, así
    /// que la pregunta es si un `None` —el caso nuevo— se vuelve un «sí» para
    /// cualquiera. No: sin el nombre del portal no hay caso, y el impostor queda
    /// afuera con el ejecutable legible o no legible.
    #[tokio::test]
    async fn un_impostor_no_entra_aunque_no_se_sepa_su_ejecutable() {
        // El impostor dice ser :1.99, y :1.99 no tiene el nombre del portal.
        let ilegible = Escenario::nuevo(Some(":1.42"), pid_inexistente()).await;
        assert!(
            !ilegible.puerta_para(Some(":1.99")).await,
            "un pedido de :1.99 con :1.42 teniendo {NOMBRE_DEL_PORTAL} tiene que rechazarse: \
             es el caso que un «no se sé el ejecutable» tratado como «dale» dejaría pasar"
        );

        // Y con el ejecutable legible tampoco, que es el caso de siempre.
        let legible = Escenario::nuevo(Some(":1.42"), std::process::id()).await;
        assert!(!legible.puerta_para(Some(":1.99")).await);

        // Aunque el impostor sea quien tiene el nombre y el ejecutable no se
        // pueda leer de nadie: sin nombre del portal del lado del emisor, no
        // hay por dónde entrar.
        let otro = Escenario::nuevo(Some(":1.99"), pid_inexistente()).await;
        assert!(!otro.puerta_para(Some(":1.42")).await);
    }

    /// Sin emisor no hay a quién preguntarle, y sin nombre del portal no entra
    /// nadie: ni el propio emisor.
    ///
    /// Cuando el nombre del portal no lo tiene nadie, `deja_pasar` no puede
    /// encontrar un `emisor` al que se lo hayan tomado, así que el rechazo es
    /// de todos, no sólo de los ajenos. Es lo que corresponde: sin portal no hay
    /// pedidos que darle la vuelta.
    #[tokio::test]
    async fn sin_dueno_del_nombre_no_entra_nadie() {
        let escenario = Escenario::nuevo(None, pid_inexistente()).await;

        // El que dice ser el portal, con el nombre del portal sin dueño.
        assert!(!escenario.puerta_para(Some(":1.42")).await);

        // Un pedido sin emisor en la cabecera. Sobre el bus de la sesión no
        // pasa —el broker siempre lo pone—, pero es la rama que tiene que
        // estar, porque un `None` en la puerta no puede ser un «sí».
        let escenario = Escenario::nuevo(Some(":1.42"), std::process::id()).await;
        assert!(!escenario.puerta_para(None).await);
    }

    /// La puerta está en el camino del pedido, y no en una función aparte.
    ///
    /// Lo de arriba decide la puerta; esto la mete en `RetrieveSecret`, que es
    /// donde importa. Un pedido de un impostor tiene que contestar el código de
    /// fallo de la especificación y **no escribir nada** en el descriptor: si
    /// escribiera, o si contestara `RESPUESTA_OK`, el backend habría entregado
    /// el secreto de `APP_ID` a un proceso cualquiera.
    #[tokio::test]
    async fn un_pedido_que_no_es_del_portal_no_recibe_el_secreto() {
        let escenario = Escenario::nuevo(Some(":1.42"), std::process::id()).await;
        escenario.publicar_backend().await;

        let pedido = escenario.pedir(Some(":1.99")).await;

        assert_eq!(
            pedido.codigo, RESPUESTA_FALLO,
            "un pedido que no viene del portal tiene que contestar el fallo de la especificación, \
             y no {RESPUESTA_OK} con un secreto en el descriptor"
        );
        assert!(
            pedido.opciones.is_empty(),
            "la especificación no define opciones en esta llamada y un rechazo no agrega ninguna: \
             volvió {:?}",
            pedido.opciones
        );
        assert!(
            pedido.secreto.is_empty(),
            "al descriptor de un pedido rechazado tiene que haberle llegado algo \
             ({} bytes), y no el secreto de {APP_ID}",
            pedido.secreto.len()
        );
    }

    /// Que lo escrito sea exactamente el secreto, y que el descriptor quede
    /// cerrado — que es lo que le dice al cliente que terminó.
    #[test]
    fn se_escribe_el_secreto_y_se_cierra() {
        use std::io::Read;
        use std::os::fd::{FromRawFd, IntoRawFd};

        let (lector, escritor) = std::os::unix::net::UnixStream::pair().expect("par de sockets");
        let crudo = escritor.into_raw_fd();
        let como_zvariant = zbus::zvariant::OwnedFd::from(unsafe { OwnedFd::from_raw_fd(crudo) });

        let secreto = b"un secreto de prueba con acentos: \xc3\xb1";
        escribir_en_descriptor(como_zvariant, secreto).expect("escribir");

        let mut recibido = Vec::new();
        // Termina porque el otro lado se cerró. Si no se cerrara, esto no vuelve.
        let mut lector = lector;
        lector.read_to_end(&mut recibido).expect("leer");
        assert_eq!(recibido, secreto);
    }
}
