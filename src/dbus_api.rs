use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::Arc;
use std::sync::{Mutex as StdMutex, OnceLock};
use tokio::sync::Mutex;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{self, OwnedObjectPath, OwnedValue, Type, Value};
use zbus::{interface, Connection};
use zeroize::Zeroizing;

use crate::crypto;
use crate::portal_secret::dueno_de;
use crate::session_crypto;

fn dbus_err(msg: impl Into<String>) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(msg.into())
}

/// Lo que contesta una interfaz de Secret Service, con los nombres de error que
/// el estándar define.
///
/// `zbus::fdo::Error` sólo trae los de `org.freedesktop.DBus.Error`, y
/// `org.freedesktop.Secret.Error` —del que `IsLocked` es el que más se usa— no
/// está. No se puede agregar un nombre suelto: `zbus::Error::MethodError` es
/// `#[non_exhaustive]` y no se arma fuera del crate de zbus. Lo que sí funciona
/// es implementar [`zbus::DBusError`] a mano, porque el macro `#[interface]`
/// acepta cualquier error que lo implemente, y `zbus::message::Message::error`
/// —con el que se arma la respuesta— es público.
///
/// El derive `zbus::DBusError` habría servido con un solo prefijo, pero acá
/// hacen falta dos: los nombres del estándar de Secret Service y los de D-Bus,
/// que es lo que contesta el resto de los fallos. Por eso el nombre lo decide
/// el **variante**, no el mensaje: es el estado del llavero el que dice que está
/// bloqueado, nunca una palabra en el texto —que además lo escribe el servidor,
/// en el idioma del servidor, y es exactamente lo que un cliente no debería
/// tener que adivinar.
#[derive(Debug)]
enum SecretError {
    /// La colección está bloqueada, y por eso no sale el secreto.
    IsLocked(String),
    /// El proceso que llama no tiene permiso para acceder a este ítem.
    AccessDenied,
    /// Cualquier otro fallo, con el nombre que ya le daba `zbus::fdo::Error`.
    Plain(zbus::fdo::Error),
}

impl From<zbus::fdo::Error> for SecretError {
    fn from(e: zbus::fdo::Error) -> Self {
        Self::Plain(e)
    }
}

impl From<zbus::Error> for SecretError {
    fn from(e: zbus::Error) -> Self {
        Self::Plain(zbus::fdo::Error::ZBus(e))
    }
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IsLocked(d) => write!(f, "{d}"),
            Self::AccessDenied => write!(f, "access denied"),
            Self::Plain(e) => write!(f, "{}", zbus::DBusError::description(e).unwrap_or_default()),
        }
    }
}

impl std::error::Error for SecretError {}

impl zbus::DBusError for SecretError {
    fn name(&self) -> zbus::names::ErrorName<'_> {
        match self {
            Self::IsLocked(_) => zbus::names::ErrorName::from_static_str_unchecked(
                "org.freedesktop.Secret.Error.IsLocked",
            ),
            // El nombre del **bus**, no uno inventado con prefijo `Secret`:
            // `org.freedesktop.Secret.Error.AccessDenied` no existe en ninguna
            // especificación, y un cliente que no lo reconoce lo trata como un
            // fallo genérico —igual que un llavero roto—. El nombre que sabe
            // distinguir «no tenés permiso» es el de D-Bus, y es el que libsecret
            // traduce a `SECRET_ERROR_ACCESS_DENIED`.
            Self::AccessDenied => zbus::names::ErrorName::from_static_str_unchecked(
                "org.freedesktop.DBus.Error.AccessDenied",
            ),
            Self::Plain(e) => zbus::DBusError::name(e),
        }
    }

    fn description(&self) -> Option<&str> {
        match self {
            Self::IsLocked(d) => Some(d),
            Self::AccessDenied => Some("access denied"),
            Self::Plain(e) => zbus::DBusError::description(e),
        }
    }

    fn create_reply(
        &self,
        call: &zbus::message::Header<'_>,
    ) -> zbus::Result<zbus::message::Message> {
        let name = self.name();
        // El cuerpo de un error de D-Bus es un texto, y va o no va: el nombre es
        // lo que el cliente mira, y el texto es para quien lee el diario.
        match self.description() {
            Some(d) => zbus::message::Message::error(call, name)?.build(&d),
            None => zbus::message::Message::error(call, name)?.build(&()),
        }
    }
}

/// Ruta de objeto de D-Bus, cayendo a la raíz si no es válida.
///
/// Todos los llamadores actuales pasan `"/"` o una ruta armada acá, así que el
/// `unwrap` que había no podía fallar. Pero un demonio de D-Bus que paniquea por
/// una ruta mal formada es un servicio que se puede tirar desde afuera el día
/// que alguien pase un valor de otro origen, y al lado vive `owned_path_try`
/// para cuando la entrada sí es ajena.
fn owned_path(s: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(s).unwrap_or_else(|_| {
        OwnedObjectPath::try_from("/").expect("la raíz siempre es una ruta válida")
    })
}

fn owned_path_try(s: &str) -> Result<OwnedObjectPath, zbus::fdo::Error> {
    zvariant::ObjectPath::try_from(s)
        .map(Into::into)
        .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("{e}")))
}

// ── helpers ───────────────────────────────────────────────

fn now() -> u64 {
    // Cero y no un panic si el reloj está antes de 1970. Pasa con una pila RTC
    // muerta o un arranque sin red, y acá tiraba el demonio del llavero entero
    // —o sea, dejaba la sesión sin contraseñas— por una marca de tiempo que
    // sólo se usa para informar cuándo se creó o modificó una entrada.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn u8_array_value(v: Vec<u8>) -> OwnedValue {
    OwnedValue::try_from(Value::Array(zvariant::Array::from(v))).unwrap_or(OwnedValue::from(false))
}

fn value_to_string(v: &Value<'_>) -> Option<String> {
    match v {
        Value::Str(s) => Some(s.to_string()),
        _ => None,
    }
}

fn value_to_attrmap(v: &Value<'_>) -> Option<HashMap<String, String>> {
    HashMap::<String, String>::try_from(v.clone()).ok()
}

fn extract_bytes(value: &Value<'_>) -> Result<Vec<u8>, zbus::fdo::Error> {
    Vec::<u8>::try_from(value.clone()).map_err(|_| dbus_err("expected byte array"))
}

/// Where the keyring database lives.
///
/// # Why this goes through `dirs` and is not read from the environment
///
/// It used to read `XDG_DATA_HOME` directly, with `unwrap_or_else` for the
/// fallback, and that has a hole that only shows up on a misconfigured session.
/// `var` returns `Ok("")` when the variable is **set but empty**, so the
/// fallback never fires: `PathBuf::from("")` joined with the rest yields
/// `vasak-keyring/keyring.db`, **relative to the working directory**. Same with
/// any relative value, which the XDG spec says to ignore.
///
/// For a keyring that is worse than an error. The caller creates the parent
/// directory and writes, so the database lands somewhere unpredictable — and
/// `spawn_unlock_prompt` asks `path.exists()` to decide whether there is a
/// keyring at all. Against the wrong path that answers `false`, so the daemon
/// behaves like a fresh install and the user's stored credentials look like
/// they vanished.
///
/// `dirs::data_dir()` already implements the rule, and it is one rule and not
/// two: an empty string is not an absolute path either, so both cases fall out
/// of the same check. Using it rather than a local copy is also what stops
/// every program here from getting this subtly wrong on its own.
///
/// `dirs` validates the XDG variable but only checks `HOME` for emptiness, so
/// the filter below closes the other half: a relative `HOME` would otherwise
/// come back as a relative base.
fn keyring_path() -> Option<std::path::PathBuf> {
    // En las pruebas, nunca el llavero de quien las corre.
    //
    // Pasó: una prueba de las puertas del almacén, con la puerta saboteada
    // para comprobar que la prueba fallaba, dejó pasar un `CreateItem` con la
    // sesión abierta, y `save_db` reescribió `~/.local/share/vasak-keyring/
    // keyring.db` de verdad con los ítems de la prueba. Lo salvó que el
    // demonio real tenía el llavero en memoria y lo volvió a escribir.
    // Que una prueba no escriba en disco no puede depender de que la puerta
    // que prueba funcione.
    #[cfg(test)]
    {
        keyring_path_under(Some(
            std::env::temp_dir().join(format!("vasak-keyring-pruebas-{}", std::process::id())),
        ))
    }
    #[cfg(not(test))]
    {
        keyring_path_under(dirs::data_dir())
    }
}

/// The same decision without reading the environment.
///
/// Split out so it can be tested: the environment is global to the process and
/// tests run in parallel, so one that sets a variable decides the outcome of
/// another.
///
/// Returning `None` rather than guessing is deliberate. Refusing to answer
/// makes the caller fail loudly; writing secrets to a directory nobody chose
/// does not.
fn keyring_path_under(base: Option<std::path::PathBuf>) -> Option<std::path::PathBuf> {
    let base = base.filter(|base| base.is_absolute())?;
    Some(base.join("vasak-keyring").join("keyring.db"))
}

/// In-memory master password (used to derive the DB key via Argon2). It is set
/// at login by `pam_vasak_keyring` through the PAM unlock interface and is
/// NEVER written to disk.
fn master_store() -> &'static StdMutex<Option<Zeroizing<String>>> {
    static STORE: OnceLock<StdMutex<Option<Zeroizing<String>>>> = OnceLock::new();
    STORE.get_or_init(|| StdMutex::new(None))
}

/// Adopt `password` as the in-memory master password for this session.
fn set_master_password(password: &str) {
    if let Ok(mut guard) = master_store().lock() {
        *guard = Some(Zeroizing::new(password.to_string()));
    }
}

/// Return the master password held in memory.
///
/// Lo que se guarda acá es la **maestra derivada**, no la contraseña de la
/// cuenta: los dos caminos que la entregan —el módulo de PAM y el diálogo
/// gráfico— derivan antes de mandarla, con el crate `vasak-keyring-derivacion`.
/// El demonio no deriva: usa lo que recibe tal cual.
///
/// Falls back to the `VASAK_KEYRING_PASSWORD` environment variable for
/// headless/testing scenarios only (y ahí también va la derivada). The old plaintext
/// `~/.config/vasak-keyring/master.key` file is deliberately NOT read: keeping
/// the key next to the encrypted database defeats the encryption entirely.
fn master_password() -> Option<Zeroizing<String>> {
    if let Ok(guard) = master_store().lock() {
        if let Some(pw) = guard.as_ref() {
            return Some(pw.clone());
        }
    }
    std::env::var("VASAK_KEYRING_PASSWORD")
        .ok()
        .map(Zeroizing::new)
}

/// Message shown when the keyring cannot be written because it was never
/// unlocked. Checked before a write mutates anything, so a rejected store
/// leaves no half-created item behind that a later lookup would find.
const LOCKED_MESSAGE: &str = "el llavero está bloqueado: no hay contraseña maestra en memoria. \
     Se establece al iniciar sesión mediante pam_vasak_keyring; \
     si el demonio se reinició, hay que volver a iniciar sesión.";

/// Message shown when a write is refused because the database on disk exists and
/// this session never opened it.
const UNDECRYPTED_MESSAGE: &str = "la base del llavero del disco existe y esta sesión no la pudo \
     descifrar, así que no se escribió nada: lo que hay en memoria no es su contenido y guardarlo la \
     dejaría vacía. Hay que volver a iniciar sesión, o responder en el diálogo de desbloqueo con la \
     contraseña que la abre.";

/// Message shown when a secret cannot be read because its collection is locked.
///
/// Uno solo para los dos casos que `effectively_locked` junta —el bloqueo
/// por colección de `Service.Lock` y la falta de contraseña maestra—, porque
/// quien lo lee no puede distinguirlos desde afuera: los dos son «desbloqueá y
/// preguntá de nuevo», y el texto de la contraseña maestra [`LOCKED_MESSAGE`] ya
/// se lleva el que corresponde cuando el motivo se conoce, que es en los caminos
/// de escritura ([`escritura_bloqueada`]).
const COLLECTION_LOCKED_MESSAGE: &str = "la colección está bloqueada: hay que desbloquear el \
     llavero para leer sus secretos.";

/// Por qué no se puede escribir la base todavía, si es que no se puede.
///
/// `None` es lo normal y lo que se quiere casi siempre. `Some(motivo)` significa
/// que hay una base en el disco que esta sesión **no abrió**, y por eso lo que
/// hay en memoria no es su contenido.
///
/// El estado es global al proceso y no una bandera por colección, a propósito: la
/// base es un solo archivo con las entradas de **todas** las colecciones, así que
/// un bloqueo puesto en una colección no protegería el archivo. Una colección
/// creada después con `CreateCollection` se registraría abierta y vacía —`spawn_collection`
/// no puede saber que la base del disco es otra cosa—, y su primer `CreateItem`
/// guardaría la lista entera por encima de la que la persona tenía.
///
/// Se pone donde se descubre que la base no abre (`items_from_disk`, al sembrar
/// una colección) y se levanta en el único lugar donde una contraseña la abre de
/// verdad (`adopt_password`): tener una contraseña en memoria no dice que esa
/// contraseña haya abierto nada, que es justo lo que había antes de esto.
fn write_block() -> &'static StdMutex<Option<String>> {
    static BLOQUEO: OnceLock<StdMutex<Option<String>>> = OnceLock::new();
    BLOQUEO.get_or_init(|| StdMutex::new(None))
}

/// Prohíbe escribir la base hasta que una contraseña la abra.
fn block_writes() {
    if let Ok(mut bloqueo) = write_block().lock() {
        *bloqueo = Some(UNDECRYPTED_MESSAGE.to_string());
    }
}

/// Levanta el bloqueo, desde el lugar donde una contraseña abrió la base.
fn unblock_writes() {
    if let Ok(mut bloqueo) = write_block().lock() {
        *bloqueo = None;
    }
}

/// El motivo por el que no se puede escribir ahora, o `None` si se puede.
fn writes_blocked() -> Option<String> {
    write_block()
        .lock()
        .ok()
        .and_then(|bloqueo| bloqueo.clone())
}

/// Por qué una escritura no puede seguir ahora, si es que no puede.
///
/// Los dos motivos se leen **una vez** y se devuelven tipados, y no como un
/// texto, porque quien contesta por el bus tiene que poder ponerles nombres de
/// error distintos a cada uno —[`escritura_bloqueada`]— y preguntar dos veces por
/// el mismo estado es leerlo en dos momentos que pueden no ser el mismo.
enum Escritura {
    /// Se puede escribir.
    Allowed,
    /// No hay contraseña maestra en memoria: la colección está bloqueada.
    Bloqueado,
    /// Hay una base en el disco que esta sesión no abrió.
    SinBaseDescifrada(String),
}

fn estado_de_escritura() -> Escritura {
    // El bloqueo va antes que la contraseña, y no después: tener una en memoria
    // no dice que haya abierto la base, y una que no la abre es precisamente el
    // caso que hay que parar.
    if let Some(motivo) = writes_blocked() {
        return Escritura::SinBaseDescifrada(motivo);
    }
    match master_password() {
        Some(_) => Escritura::Allowed,
        None => Escritura::Bloqueado,
    }
}

/// Checked before a write mutates anything, so a rejected store leaves no
/// half-created item behind that a later lookup would find.
///
/// `String` y no `zbus::fdo::Error` porque no todos los que preguntan están
/// hablando por el bus: el backend del portal necesita el texto para el diario.
fn ensure_unlocked() -> Result<(), String> {
    match estado_de_escritura() {
        Escritura::Allowed => Ok(()),
        Escritura::Bloqueado => Err(LOCKED_MESSAGE.to_string()),
        Escritura::SinBaseDescifrada(motivo) => Err(motivo),
    }
}

/// Falla si una escritura no puede seguir ahora, con el nombre del estándar.
///
/// Es [`ensure_unlocked`] con el motivo tipado: el portal pide el texto y los
/// métodos de D-Bus el nombre, y los dos leen el mismo estado una vez.
///
/// Los dos motivos de [`estado_de_escritura`] se separan, y por eso el nombre se
/// decide por el **estado** y no por el texto del motivo:
///
/// - Sin contraseña maestra no hay nada que leer ni que escribir: eso es
///   `IsLocked`, y es lo que [`ItemInterface::get_secret`] contesta cuando la
///   colección está bloqueada. Es el mismo nombre porque es la misma situación
///   desde el punto de vista del cliente.
/// - «La base del disco existe y esta sesión no la abrió» **no** es un bloqueo
///   de la colección: la colección puede estar abierta y consultable, lo que no
///   se puede es escribir un archivo que ya tiene. `IsLocked` ahí mandaría al
///   cliente a un camino de desbloqueo que no abre la base —no hay contraseña
///   que la abra en esta sesión— y por eso sigue siendo un `Failed`, con el
///   texto entero que dice qué hacer.
fn escritura_bloqueada() -> Result<(), SecretError> {
    match estado_de_escritura() {
        Escritura::Allowed => Ok(()),
        Escritura::Bloqueado => Err(SecretError::IsLocked(LOCKED_MESSAGE.to_string())),
        Escritura::SinBaseDescifrada(motivo) => Err(SecretError::Plain(dbus_err(motivo))),
    }
}

/// Whether a collection (or an item inside it) can serve secrets right now.
///
/// There are two independent notions of "locked": the per-collection flag that
/// `Service.Lock`/`Unlock` toggles, and whether a master password is held in
/// memory. Only the first one used to reach the `Locked` property, and it
/// starts out `false` when the default collection is registered — so the
/// property answered "unlocked" while every operation failed with
/// `LOCKED_MESSAGE`. libsecret reads exactly this property to decide whether it
/// has to unlock before using the keyring; seeing `false` it went straight to
/// the operation and surfaced the raw error, which is why applications reported
/// that there was no keyring service instead of asking to unlock it.
fn effectively_locked(collection_locked: bool) -> bool {
    collection_locked || master_password().is_none()
}

/// El esquema que protege el almacén de cuentas de Vasak-OS.
///
/// Los ítems con este esquema en `xdg:schema` sólo se le entregan al
/// sincronizador: la conexión que tenga tomado `ar.net.vasak.os.AccountsSync` en
/// el bus **y** cuyo ejecutable sea `/usr/bin/vasak-accounts-sync`. Ver
/// [`es_el_sincronizador`].
const ESQUEMA_PROTEGIDO: &str = "ar.net.vasak.os.AccountsStore";
const ATRIBUTO_ESQUEMA: &str = "xdg:schema";
const EJECUTABLE_AUTORIZADO: &str = "/usr/bin/vasak-accounts-sync";

/// El nombre con el que el sincronizador se presenta en el bus de sesión.
///
/// Una de las dos condiciones de [`es_el_sincronizador`], y **no alcanza sola**:
/// el sincronizador lo toma al arrancar, pero un nombre lo puede tomar cualquiera
/// que llegue primero, y el servicio viene `disabled`, así que casi siempre está
/// libre. Por eso el ejecutable también se exige.
///
/// El sincronizador lo pide **después** de publicar el almacén
/// (`sync/src/main.rs`, `StoreService::start` antes del `request_name`). Hoy no
/// pide la clave en ese intervalo —las cuentas se abren con `accounts_listed`,
/// que viene después—, pero si algún día la pidiera, este control se la negaría.
const NOMBRE_DEL_SINCRONIZADOR: &str = "ar.net.vasak.os.AccountsSync";

/// Obtiene el PID del proceso que envió el mensaje D-Bus.
///
/// Pregunta al bus de sesión por el PID asociado a la conexión del remitente.
/// Si algo falla, devuelve `None`.
async fn pid_del_emisor(conn: &Connection, cabecera: &zbus::message::Header<'_>) -> Option<u32> {
    let emisor = cabecera.sender()?;
    let respuesta = conn
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetConnectionUnixProcessID",
            &(emisor.as_str(),),
        )
        .await
        .ok()?;
    respuesta.body().deserialize().ok()
}

/// Obtiene la ruta del ejecutable a partir del PID.
/// La ruta del ejecutable de un proceso, sin el adorno de los borrados.
///
/// `readlink /proc/<pid>/exe` no devuelve la ruta del archivo: devuelve la del
/// inodo que se está ejecutando, y si ese archivo ya no está —porque `pacman`
/// lo desenlazó para instalar la versión nueva— le cuelga `" (deleted)"` al
/// final. Comprobado sobre un binario borrado en caliente: `readlink` da
/// `/tmp/x/miapp (deleted)`.
///
/// Sin quitarlo, una actualización del sistema con la unidad del sincronizador
/// corriendo le negaría el acceso al proceso **legítimo** en cada `GetSecret`
/// hasta que se reinicie la unidad, y el síntoma —«el almacén de cuentas se
/// rompió después de actualizar»— no lleva a ninguna parte. Falla cerrado, que
/// es lo correcto; lo que no es correcto es que falle.
///
/// El sufijo se quita y no se recorta: la comparación de abajo sigue siendo
/// exacta contra la ruta entera, así que quitarlo no abre la puerta a que un
/// `/usr/bin/vasak-accounts-sync.malicioso` passe por el sincronizador.
///
/// El `Err` es el motivo, y no se traga: un `.ok()` acá es lo que dejó a la
/// puerta rechazando al sincronizador sin que nada lo dijera, cuando la unidad
/// tenía un namespace de usuario propio y la lectura daba `EACCES`.
fn ejecutable_de(pid: u32) -> Result<String, std::io::Error> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|r| r.to_string_lossy().into_owned())
        .map(|r| sin_adorno_de_borrado(&r).to_string())
}

/// Saca el `" (deleted)"` que el kernel le cuelga a un inodo sin archivo.
///
/// Va aparte de `ejecutable_de` por la misma razón que `es_el_autorizado` va
/// aparte de `autorizado_para_esquema_protegido`: la regla se prueba sola, sin
/// un proceso que haya que arrancar ni un `/proc` que haya que existido. Que la
/// cadena con el adorno llegue como llega, eso lo comprueba la otra prueba, que
/// sí arranca un proceso de verdad.
fn sin_adorno_de_borrado(ruta: &str) -> &str {
    ruta.strip_suffix(SUFIJO_DE_BORRADO).unwrap_or(ruta)
}

/// Lo que le cuelga el kernel a la ruta de un inodo que ya no tiene archivo.
const SUFIJO_DE_BORRADO: &str = " (deleted)";

/// Verifica si un ítem tiene un esquema protegido.
fn es_esquema_protegido(item: &ItemInfo) -> bool {
    atributos_protegidos(&item.attributes)
}

/// Si una lista de atributos lleva el esquema protegido.
///
/// Aparte de [`es_esquema_protegido`] porque `CreateItem` la necesita sobre los
/// atributos que **llegan**, antes de que haya un ítem.
fn atributos_protegidos(atributos: &HashMap<String, String>) -> bool {
    atributos
        .get(ATRIBUTO_ESQUEMA)
        .is_some_and(|s| s == ESQUEMA_PROTEGIDO)
}

/// Si quien llama puede tocar lo que pide.
///
/// `protegido` es si el pedido toca algún ítem del almacén —leerlo,
/// describirlo, reemplazarlo, borrarlo o crear uno con su esquema—. Si no toca
/// ninguno, sí, y sin preguntarle nada al bus: la puerta cuesta dos idas y
/// vueltas y una lectura de `/proc`, y cada contraseña del navegador no tiene
/// por qué pagarlas.
///
/// Es la misma puerta que protege `GetSecret` desde Vasak-OS/vasak-keyring#24.
/// Leer la clave era la mitad: con `CreateItem`, `SetSecret` o los borrados, un
/// proceso cualquiera **elegía** la clave con la que se abre la base, y con
/// `SearchItems` y `Attributes` encontraba el ítem para hacerlo
/// (Vasak-OS/vasak-keyring#29 y #30).
///
/// El estado se toma un momento para copiar el ejecutable esperado y se suelta
/// antes de ir al bus.
async fn puede_tocar_el_almacen(
    conn: &Connection,
    cabecera: &zbus::message::Header<'_>,
    state: &Mutex<KeyringState>,
    protegido: bool,
) -> bool {
    if !protegido {
        return true;
    }
    let esperado = state.lock().await.ejecutable_del_sincronizador();
    autorizado_para_esquema_protegido(conn, cabecera, &esperado).await
}

/// Si un ítem coincide con lo que se busca: tiene cada atributo pedido con ese
/// valor. Un mapa vacío coincide con todos, como pide la especificación.
fn coincide(item: &ItemInfo, buscados: &HashMap<String, String>) -> bool {
    buscados
        .iter()
        .all(|(k, v)| item.attributes.get(k) == Some(v))
}

/// Si una colección guarda algún ítem del almacén.
fn coleccion_protegida(state: &KeyringState, ruta: &str) -> bool {
    state.collections.get(ruta).is_some_and(|col| {
        col.items
            .iter()
            .any(|ip| state.items.get(ip).is_some_and(es_esquema_protegido))
    })
}

/// Si el ítem de esa ruta es del almacén. Uno que no existe no lo es: el que
/// llama recibe el mismo «no encontrado» de siempre.
async fn ruta_protegida(state: &Mutex<KeyringState>, ruta: &str) -> bool {
    state
        .lock()
        .await
        .items
        .get(ruta)
        .is_some_and(es_esquema_protegido)
}

/// Si a quien pregunta se le puede entregar este ítem.
///
/// Es la decisión sola, sin bus ni async, a propósito. El «quién pregunta» ya
/// está resuelto para cuando se la llama: es el `bool` que devuelve
/// [`autorizado_para_esquema_protegido`].
///
/// Una regla de dos líneas tiene que poder probarse sin montar nada, y por eso
/// vive acá y no repartida en los dos métodos que la usan: los dos la llaman,
/// ninguno la reimplementa. Y separada de la puerta, porque la puerta se puede
/// romper sin que se rompa esta, así que las pruebas de las dos cosas tienen que
/// poder fallar por separado.
///
/// Un secreto del portal no se le entrega a nadie, autorizado o no: el
/// `autorizado` es el del almacén de cuentas, y el portal no tiene a nadie
/// autorizado en el bus (Vasak-OS/vasak-keyring#33). Va acá y no sólo en los
/// métodos porque es la segunda mirada, la que se hace con el candado tomado.
fn access_allowed(item: &ItemInfo, autorizado: bool) -> bool {
    !is_portal_item(item) && (!es_esquema_protegido(item) || autorizado)
}

/// Verifica si el proceso que llama está autorizado para acceder a un esquema protegido.
///
/// Sólo el sincronizador puede leer ítems con el esquema protegido, y hacen
/// falta las dos cosas de [`es_el_sincronizador`]: que la conexión que llama sea
/// la dueña de `ar.net.vasak.os.AccountsSync`, y que el ejecutable de su pid
/// sea `esperado`. Cualquier cosa que no se pueda averiguar es un no.
///
/// `esperado` es siempre [`EJECUTABLE_AUTORIZADO`] fuera de las pruebas: sale de
/// [`KeyringState::ejecutable_del_sincronizador`], que no se cambia desde ningún
/// lado del demonio.
///
/// **Lo que esto autentica es el binario, no a quien lo ejecuta.** Un proceso del
/// mismo UID al que el sincronizador le pase su conexión D-Bus la usa sin
/// problema —el bus devuelve el PID de quien *abrió* la conexión, no el de quien
/// escribe— y el código inyectado dentro del propio sincronizador pasa el
/// control de la misma manera. Ninguna comprobación más sobre `/proc` cierra
/// esos dos casos: hacen falta un UID propio o un sandbox. Está anotado igual en
/// el `README.md`, y es la misma frontera que ya tenían `vasak-permissions` y el
/// control del portal.
async fn autorizado_para_esquema_protegido(
    conn: &Connection,
    cabecera: &zbus::message::Header<'_>,
    esperado: &str,
) -> bool {
    let emisor = match cabecera.sender() {
        Some(emisor) => emisor.as_str().to_owned(),
        None => {
            eprintln!(
                "vasak-keyring: se rechaza el acceso a un ítem del almacén que vino sin emisor \
                 en la cabecera"
            );
            return false;
        }
    };

    let duenia = match dueno_de(conn, NOMBRE_DEL_SINCRONIZADOR).await {
        Ok(duenia) => duenia,
        Err(e) => {
            eprintln!(
                "vasak-keyring: se rechaza el acceso a un ítem del almacén de {emisor}: no se \
                 pudo preguntar al bus quién tiene {NOMBRE_DEL_SINCRONIZADOR}: {e}"
            );
            return false;
        }
    };

    let ejecutable = match ejecutable_del_emisor(conn, cabecera).await {
        Ok(ejecutable) => ejecutable,
        Err(motivo) => {
            // Sin ejecutable no hay puerta: el nombre solo no alcanza. Si esto
            // aparece con el sincronizador de verdad, lo primero es mirar si la
            // unidad volvió a tener un namespace de usuario propio.
            eprintln!(
                "vasak-keyring: se rechaza el acceso a un ítem del almacén de {emisor}: \
                 {motivo}, y sin el ejecutable el nombre no alcanza"
            );
            return false;
        }
    };

    if es_el_sincronizador(&emisor, duenia.as_deref(), Some(&ejecutable), esperado) {
        return true;
    }

    if duenia.as_deref() == Some(emisor.as_str()) {
        eprintln!(
            "vasak-keyring: se rechaza el acceso a un ítem del almacén de {emisor}: tiene el \
             nombre del sincronizador pero su ejecutable es {ejecutable} y no {esperado}"
        );
    } else {
        match duenia.as_deref() {
            Some(duenia) => eprintln!(
                "vasak-keyring: se rechaza el acceso a un ítem del almacén de {emisor}: no es el \
                 sincronizador, y {NOMBRE_DEL_SINCRONIZADOR} lo tiene {duenia}"
            ),
            None => eprintln!(
                "vasak-keyring: se rechaza el acceso a un ítem del almacén de {emisor}: en el \
                 bus nadie tiene {NOMBRE_DEL_SINCRONIZADOR}, así que el sincronizador no está \
                 andando"
            ),
        }
    }
    false
}

/// El ejecutable de quien llama, o el motivo por el que no se pudo saber.
///
/// El pid se le pregunta al bus, que es el único que lo sabe, y de ahí sale el
/// ejecutable. Cualquiera de los dos pasos que falle es un `Err` con el motivo
/// —un pid que el bus no da, un `/proc/<pid>/exe` que no existe o no se deja
/// leer—, y para la puerta todos son un no.
async fn ejecutable_del_emisor(
    conn: &Connection,
    cabecera: &zbus::message::Header<'_>,
) -> Result<String, String> {
    // `match` y no `let...else`: el inicializador de un `let...else` no
    // parsea cuando termina en `.await`, y esto vive dentro de un `async fn`.
    let pid = match pid_del_emisor(conn, cabecera).await {
        Some(pid) => pid,
        None => return Err("el bus no dio su pid".to_owned()),
    };

    // En un hilo aparte: esto corre en el hilo del bus, y una lectura
    // bloqueante ahí frena a todos los demás pedidos mientras tanto.
    tokio::task::spawn_blocking(move || ejecutable_de(pid))
        .await
        .map_err(|e| format!("se cortó la lectura de /proc/{pid}/exe: {e}"))?
        .map_err(|e| format!("no se pudo leer /proc/{pid}/exe: {e}"))
}

/// Si la conexión que llama es la del sincronizador.
///
/// Dos condiciones y hacen falta las dos:
///
/// 1. La conexión tiene que tener tomado `ar.net.vasak.os.AccountsSync`. La
///    contesta el bus.
/// 2. El ejecutable de su pid tiene que ser `esperado`. Un `None` —no se pudo
///    leer— es un no: el nombre solo lo puede tener cualquiera que haya llegado
///    primero, y el ejecutable es lo que no se puede fingir.
fn es_el_sincronizador(
    emisor: &str,
    duenia: Option<&str>,
    ejecutable: Option<&str>,
    esperado: &str,
) -> bool {
    duenia == Some(emisor) && ejecutable.is_some_and(|ruta| es_el_autorizado(ruta, esperado))
}

/// Si esta ruta de ejecutable es la del sincronizador.
///
/// La comparación es exacta y no por prefijo, y eso es el punto: con un
/// `starts_with`, `/usr/bin/vasak-accounts-sync.malicioso` —o cualquier
/// `...-sync2`— pasaría por el sincronizador. No hace falta ser root para
/// exploitear eso, alcanza con poder dejar un archivo en un directorio que esté
/// en el `PATH` del atacante... salvo que el camino esté completo, que es
/// justamente por lo que se compara contra la ruta entera y no contra el
/// nombre. Separáda de `autorizado_para_esquema_protegido` para que se pueda
/// probar sin un bus: la de acá es la regla, y una regla que no se prueba sola
/// termina cediendo en el `if` de arriba.
fn es_el_autorizado(ejecutable: &str, esperado: &str) -> bool {
    ejecutable == esperado
}

// ── El espacio de nombres del portal ───────────────────────
//
// Los secretos maestros que el backend del portal le da a cada aplicación son
// del demonio, no de quien habla por el Secret Service. Antes cualquier proceso
// de la sesión podía plantar el de una aplicación antes de que lo pidiera
// (`CreateItem`), reemplazarlo (`CreateItem` con `replace`, `SetSecret`),
// leerlo (`GetSecret`) o borrarlo, y la aplicación terminaba cifrando con una
// clave que el otro conocía (Vasak-OS/vasak-keyring#33).
//
// La regla es «nadie desde el bus», sin excepción y sin preguntarle nada a
// nadie: el backend del portal corre adentro del demonio y lee el estado
// directo, así que no hay ningún cliente legítimo del Secret Service para estos
// ítems. No es la puerta del almacén de cuentas, que deja pasar a uno: acá no
// pasa ni el sincronizador.
//
// Y no sólo se niegan: **no existen** para el bus. No se publican como
// objetos, no aparecen en `Items` ni en `SearchItems`, y `GetSecrets` los
// omite. Negarlos con `AccessDenied` en un listado dejaría saber qué
// aplicaciones usan el portal, y cada método nuevo tendría que acordarse de la
// negación. Los métodos de `Item` igual los niegan, como segunda capa, por si
// algún camino futuro llega a publicar uno.

/// El esquema con el que el backend del portal guarda el secreto maestro de
/// cada aplicación, por convención de freedesktop.
pub const PORTAL_SCHEMA: &str = "org.freedesktop.portal.Secret";

/// El atributo con el que el demonio marca los secretos maestros que crea.
///
/// Sirve para una sola cosa: distinguir los que creó el demonio de los que ya
/// estaban en el llavero antes de esta versión. Hasta acá cualquier proceso
/// podía crear un ítem con el esquema del portal, y uno plantado y uno legítimo
/// son indistinguibles —el mismo nombre, los mismos atributos, 64 bytes que
/// cualquiera sabe generar—. Desde esta versión ningún cliente del bus puede
/// crear un ítem con el esquema **ni con esta marca**, así que un ítem que la
/// tiene lo creó el demonio. Ver [`app_master_secret`].
const PORTAL_ORIGIN_ATTRIBUTE: &str = "vasak-keyring:origin";
const PORTAL_ORIGIN_VALUE: &str = "portal-backend";

/// Lo que queda de un texto para compararlo contra un nombre reservado: sólo
/// letras y dígitos ASCII, en minúscula.
///
/// Es a propósito más ancho que la búsqueda del portal, que compara exacto. La
/// búsqueda sólo encuentra lo que tiene los atributos exactos, así que un
/// parecido —`Org.Freedesktop.Portal.Secret`, un espacio al final, un espacio
/// de ancho cero, `xdg_schema` por `xdg:schema`— hoy no se le daría a ninguna
/// aplicación. Pero que la reserva sea más ancha que la búsqueda es lo que hace
/// que la búsqueda se pueda aflojar mañana sin abrir el agujero de nuevo, y que
/// nadie pueda dejar en el llavero algo que en un listado se lea como un
/// secreto del portal.
fn skeleton(text: &str) -> impl Iterator<Item = char> + '_ {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
}

/// Si dos textos son el mismo nombre para la reserva. Ver [`skeleton`].
fn same_skeleton(a: &str, b: &str) -> bool {
    skeleton(a).eq(skeleton(b))
}

/// Si una lista de atributos es de un secreto del portal.
///
/// Lo es si **algún** par lleva el esquema del portal —con la clave y el valor
/// comparados por [`skeleton`]— o si lleva la marca de origen, con cualquier
/// valor. Se recorren todos los pares y no se busca la clave exacta: un mapa
/// con `xdg:schema` y `XDG:Schema` a la vez tiene dos claves distintas, y la
/// que importa puede ser cualquiera de las dos.
fn is_portal_attributes(attributes: &HashMap<String, String>) -> bool {
    attributes.iter().any(|(key, value)| {
        same_skeleton(key, PORTAL_ORIGIN_ATTRIBUTE)
            || (same_skeleton(key, ATRIBUTO_ESQUEMA) && same_skeleton(value, PORTAL_SCHEMA))
    })
}

/// Si un ítem es un secreto del portal.
fn is_portal_item(item: &ItemInfo) -> bool {
    is_portal_attributes(&item.attributes)
}

/// Si el ítem de esa ruta es un secreto del portal. Uno que no existe no lo es.
async fn is_portal_path(state: &Mutex<KeyringState>, path: &str) -> bool {
    state
        .lock()
        .await
        .items
        .get(path)
        .is_some_and(is_portal_item)
}

/// Si una colección guarda algún secreto del portal.
fn holds_portal_items(state: &KeyringState, collection: &str) -> bool {
    state.collections.get(collection).is_some_and(|col| {
        col.items
            .iter()
            .any(|ip| state.items.get(ip).is_some_and(is_portal_item))
    })
}

/// De estas rutas, las que se publican en el bus: todas menos las del portal.
///
/// Es el único lugar que lo decide, y lo usan los caminos que publican ítems
/// —el arranque y el desbloqueo—, para que ninguno publique un secreto del
/// portal por su cuenta.
fn published_paths(state: &KeyringState, paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|ip| {
            state
                .items
                .get(ip.as_str())
                .is_some_and(|item| !is_portal_item(item))
        })
        .cloned()
        .collect()
}

/// El negativo de un método de `Item` sobre un secreto del portal.
fn portal_denied() -> zbus::fdo::Error {
    zbus::fdo::Error::AccessDenied(
        "el ítem es un secreto del portal: sólo lo usa el propio llavero".into(),
    )
}

/// Writes every item to the encrypted database.
///
/// Returns an error instead of only logging one: a store that cannot reach the
/// disk used to answer the client with success, so an application believed a
/// password was saved and only found out at the next login that it was gone.
fn save_db(items: &[ItemInfo]) -> Result<(), String> {
    let path = keyring_path().ok_or("no se pudo determinar la ruta del llavero (¿falta HOME?)")?;
    write_to(&path, items)
}

/// Lo mismo, con la ruta dada.
///
/// La ruta entra por parámetro para que las pruebas puedan apuntarla a un
/// directorio propio: `keyring_path` sale del entorno, que es del proceso
/// entero, y una prueba que escribiera ahí tocaría el llavero de quien la corre.
fn write_to(path: &std::path::Path, items: &[ItemInfo]) -> Result<(), String> {
    // El bloqueo va **dentro** de la escritura y no repetido en cada llamador:
    // esta función es la única que toca el archivo, así que acá queda la última
    // palabra sobre qué se puede escribir —hoy y para lo que se agregue después—,
    // en vez de depender de que cada camino nuevo se acuerde de preguntar.
    if let Some(motivo) = writes_blocked() {
        return Err(motivo);
    }
    let pwd = master_password().ok_or(LOCKED_MESSAGE)?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        // The directory name alone leaks nothing, but its listing shouldn't be
        // readable by other local users either.
        let _ = std::fs::set_permissions(parent, PermissionsExt::from_mode(0o700));
    }
    let db_items: Vec<crypto::SecretItem> = items
        .iter()
        .map(|i| crypto::SecretItem {
            label: i.label.clone(),
            attributes: i.attributes.clone(),
            secret: i.secret.clone(),
        })
        .collect();
    let db = crypto::KeyringDatabase { items: db_items };
    let data = crypto::encrypt_database(&db, pwd.as_str())
        .map_err(|e| format!("no se pudo cifrar el llavero: {e}"))?;

    write_atomically(path, &data)
        .map_err(|e| format!("no se pudo escribir {}: {e}", path.display()))
}

/// Replaces the database in one step, so an interrupted write can never leave a
/// truncated file behind — the database is the only copy of every stored
/// password, and a partial one decrypts to nothing.
///
/// The temporary file is created 0600 from the start rather than fixed up
/// afterwards, so the ciphertext is never briefly world-readable.
fn write_atomically(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let temp = path.with_extension("tmp");

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)?;

    // fsync before the rename: without it the rename can land while the
    // contents are still in the page cache, and a power cut leaves an empty
    // file where the keyring used to be.
    let written = file.write_all(data).and_then(|_| file.sync_all());
    drop(file);

    let result = written.and_then(|_| std::fs::rename(&temp, path));

    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Lee la base cifrada del disco, o devuelve `None` si todavía no hay archivo.
///
/// `None` es el caso normal de una máquina nueva. Cualquier otro error se
/// propaga, y esa distinción es deliberada: una base que **existe** pero de la
/// que no se puede leer no es una base vacía, y tratarla como si lo fuera haría
/// que el primer guardado escribiera encima de una base que nunca se abrió.
///
/// Antes de esto cada llamador preguntaba primero con `Path::exists` y después
/// leía. Son dos llamadas al sistema donde alcanza con una, la primera además
/// es bloqueante, y entre las dos queda una carrera: un archivo que aparece o
/// desaparece entre el `stat` y el `read` se pierde en silencio.
async fn leer_base(path: &std::path::Path) -> std::io::Result<Option<Vec<u8>>> {
    match tokio::fs::read(path).await {
        Ok(raw) => Ok(Some(raw)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

// ── shared state ──────────────────────────────────────────

struct SessionInfo {
    algorithm: String,
    /// `None` for a plain session; the AES-128 transport key for a DH one.
    shared_key: Option<Vec<u8>>,
    created: u64,
}

impl SessionInfo {
    /// Prepares a stored secret for delivery over this session, returning
    /// `(parameters, value)`.
    fn encode(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), zbus::fdo::Error> {
        match self.shared_key.as_deref() {
            None => Ok((Vec::new(), plaintext.to_vec())),
            Some(key) => session_crypto::encrypt(key, plaintext)
                .map_err(|e| dbus_err(format!("could not encrypt the secret: {e}"))),
        }
    }

    /// Recovers a secret a client sent over this session.
    ///
    /// Without this, secrets arrived encrypted and were stored verbatim while
    /// `GetSecret` encrypted them again on the way out — so anything written
    /// through a DH session came back as ciphertext of ciphertext.
    fn decode(&self, parameters: &[u8], value: Vec<u8>) -> Result<Vec<u8>, zbus::fdo::Error> {
        match self.shared_key.as_deref() {
            None => Ok(value),
            Some(key) => session_crypto::decrypt(key, parameters, &value)
                .map_err(|e| dbus_err(format!("could not decrypt the secret: {e}"))),
        }
    }
}

#[derive(Clone)]
pub struct ItemInfo {
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secret: Vec<u8>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

struct CollectionInfo {
    label: String,
    locked: bool,
    items: Vec<String>,
    created: u64,
    modified: u64,
}

pub struct KeyringState {
    sessions: HashMap<String, SessionInfo>,
    collections: HashMap<String, CollectionInfo>,
    items: HashMap<String, ItemInfo>,
    // alias -> collection object path (e.g. "default" -> the login collection).
    aliases: HashMap<String, String>,
    next_session: u64,
    next_collection: u64,
    next_item: u64,
    /// El ejecutable que tiene que tener quien lee el almacén cifrado. Siempre
    /// [`EJECUTABLE_AUTORIZADO`]: sólo las pruebas lo cambian, para poder
    /// recorrer el camino que acepta con un binario que exista en la máquina que
    /// las corre.
    ejecutable_del_sincronizador: String,
}

impl KeyringState {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            collections: HashMap::new(),
            items: HashMap::new(),
            aliases: HashMap::new(),
            next_session: 0,
            next_collection: 0,
            next_item: 0,
            ejecutable_del_sincronizador: EJECUTABLE_AUTORIZADO.to_owned(),
        }
    }

    /// Ver el campo del mismo nombre.
    fn ejecutable_del_sincronizador(&self) -> String {
        self.ejecutable_del_sincronizador.clone()
    }

    /// Reserves the next free item id.
    ///
    /// Every item path must go through this. Loading used to number items from
    /// `enumerate()` without advancing the counter, so the first secret stored
    /// after a restart was handed id 0 and silently overwrote the oldest loaded
    /// one — while `CreateItem` still returned success.
    fn take_item_id(&mut self) -> u64 {
        let id = self.next_item;
        self.next_item += 1;
        id
    }
}

// ── Secret D‑Bus struct ────────────────────────────────────

#[derive(Type, Serialize, Deserialize)]
pub struct SecretStruct {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

// ── Session interface ─────────────────────────────────────

struct SessionInterface {
    state: Arc<Mutex<KeyringState>>,
    path: String,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionInterface {
    async fn close(&mut self) -> Result<(), zbus::fdo::Error> {
        self.state.lock().await.sessions.remove(&self.path);
        Ok(())
    }
}

// ── Item interface ────────────────────────────────────────

struct ItemInterface {
    state: Arc<Mutex<KeyringState>>,
    conn: Connection,
    path: String,
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemInterface {
    /// El nombre del ítem. El del almacén lo dice (`Almacén local de VasakOS
    /// (<cuenta>)`), así que se describe sólo al sincronizador.
    #[zbus(property)]
    async fn label(
        &self,
        #[zbus(header)] cabecera: Option<zbus::message::Header<'_>>,
    ) -> Result<String, zbus::fdo::Error> {
        self.check_describe(cabecera.as_ref()).await?;
        self.state
            .lock()
            .await
            .items
            .get(&self.path)
            .map(|i| i.label.clone())
            .ok_or_else(|| dbus_err("item not found"))
    }

    /// Los atributos. Los del almacén son el mapa que hace falta para reemplazar
    /// su clave con `CreateItem` (Vasak-OS/vasak-keyring#30): se describen sólo
    /// al sincronizador.
    #[zbus(property)]
    async fn attributes(
        &self,
        #[zbus(header)] cabecera: Option<zbus::message::Header<'_>>,
    ) -> Result<HashMap<String, String>, zbus::fdo::Error> {
        self.check_describe(cabecera.as_ref()).await?;
        self.state
            .lock()
            .await
            .items
            .get(&self.path)
            .map(|i| i.attributes.clone())
            .ok_or_else(|| dbus_err("item not found"))
    }

    #[zbus(property)]
    async fn locked(&self) -> Result<bool, zbus::fdo::Error> {
        let state = self.state.lock().await;
        if state.items.get(&self.path).is_some_and(is_portal_item) {
            return Err(portal_denied());
        }
        for col in state.collections.values() {
            if col.items.contains(&self.path) {
                return Ok(effectively_locked(col.locked));
            }
        }
        Ok(effectively_locked(false))
    }

    #[zbus(property)]
    async fn created(&self) -> Result<u64, zbus::fdo::Error> {
        let state = self.state.lock().await;
        let item = state
            .items
            .get(&self.path)
            .ok_or_else(|| dbus_err("item not found"))?;
        if is_portal_item(item) {
            return Err(portal_denied());
        }
        Ok(item.created)
    }

    #[zbus(property)]
    async fn modified(&self) -> Result<u64, zbus::fdo::Error> {
        let state = self.state.lock().await;
        let item = state
            .items
            .get(&self.path)
            .ok_or_else(|| dbus_err("item not found"))?;
        if is_portal_item(item) {
            return Err(portal_denied());
        }
        Ok(item.modified)
    }

    /// Returns the secret as a single struct argument.
    ///
    /// The one-element tuple is load-bearing: returning `SecretStruct` bare
    /// made zbus flatten it into four separate out-arguments (`oayays`), and
    /// libsecret rejected every reply as a signature mismatch against the
    /// `((oayays))` the spec declares.
    ///
    /// La colección bloqueada se avisa con el nombre del estándar
    /// ([`SecretError::IsLocked`]) y no con `Failed` y un texto: es lo que le
    /// dice a un cliente que tiene que **desbloquear** y reintentar, en vez de
    /// quedarse adivinando por el mensaje.
    async fn get_secret(
        &self,
        #[zbus(header)] cabecera: zbus::message::Header<'_>,
        session: OwnedObjectPath,
    ) -> Result<(SecretStruct,), SecretError> {
        // La identidad del emisor se resuelve **antes** del lock del estado, y
        // sólo si el ítem es del almacén. Son dos idas y vueltas al bus y una
        // lectura de `/proc`: hacerlas con el lock tomado deja a todos los demás
        // esperando a que un proceso ajeno conteste, y hacerlas para cualquier
        // ítem le cobra eso —y una línea de «se rechaza» en el diario— a cada
        // contraseña que lee el navegador.
        //
        // Entre las dos tomas del lock el ítem puede cambiar. Si pasa a ser
        // protegido, `autorizado` quedó en `false` y se niega: falla cerrado.
        //
        // Un secreto del portal se niega antes que nada y sin ir al bus: no hay
        // nadie a quien preguntar por él (#33).
        let (protegido, esperado) = {
            let state = self.state.lock().await;
            let item = state.items.get(&self.path);
            if item.is_some_and(is_portal_item) {
                return Err(SecretError::AccessDenied);
            }
            (
                item.is_some_and(es_esquema_protegido),
                state.ejecutable_del_sincronizador(),
            )
        };
        let autorizado =
            protegido && autorizado_para_esquema_protegido(&self.conn, &cabecera, &esperado).await;

        let state = self.state.lock().await;
        // Never release a secret from a locked collection.
        if state
            .collections
            .values()
            .any(|c| effectively_locked(c.locked) && c.items.contains(&self.path))
        {
            return Err(SecretError::IsLocked(COLLECTION_LOCKED_MESSAGE.into()));
        }
        let item = state
            .items
            .get(&self.path)
            .ok_or_else(|| dbus_err("item not found"))?;

        if !access_allowed(item, autorizado) {
            return Err(SecretError::AccessDenied);
        }

        let ses = state
            .sessions
            .get(session.as_str())
            .ok_or_else(|| dbus_err("session not found"))?;

        let (parameters, value) = ses.encode(&item.secret)?;

        Ok((SecretStruct {
            session: session.clone(),
            parameters,
            value,
            content_type: item.content_type.clone(),
        },))
    }

    async fn set_secret(
        &mut self,
        #[zbus(header)] cabecera: zbus::message::Header<'_>,
        secret: SecretStruct,
    ) -> Result<(), SecretError> {
        // Reemplazar el secreto del ítem del almacén es elegir la clave con la
        // que se abre la base. Se mira el ítem que **está**, no lo que llega, y
        // antes que si se puede escribir.
        //
        // Y el secreto de una aplicación, que no lo cambia nadie desde el bus:
        // era la forma de dejarla cifrando con una clave ajena (#33).
        if is_portal_path(&self.state, &self.path).await {
            return Err(SecretError::AccessDenied);
        }
        let protegido = ruta_protegida(&self.state, &self.path).await;
        if !puede_tocar_el_almacen(&self.conn, &cabecera, &self.state, protegido).await {
            return Err(SecretError::AccessDenied);
        }
        escritura_bloqueada()?;

        let col_path = {
            let mut state = self.state.lock().await;

            let plaintext = state
                .sessions
                .get(secret.session.as_str())
                .ok_or_else(|| dbus_err("session not found"))?
                .decode(&secret.parameters, secret.value)?;

            match state.items.get_mut(&self.path) {
                Some(item) => {
                    item.secret = plaintext;
                    item.content_type = secret.content_type;
                    item.modified = now();
                }
                None => return Err(dbus_err("item not found").into()),
            }
            state
                .collections
                .iter()
                .find(|(_, c)| c.items.contains(&self.path))
                .map(|(cp, _)| cp.clone())
        };
        if let (Some(cp), Ok(item)) = (col_path, owned_path_try(&self.path)) {
            if let Ok(emitter) = SignalEmitter::new(&self.conn, cp.as_str()) {
                let _ = CollectionInterface::item_changed(&emitter, item).await;
            }
        }
        self.persist_all().await?;
        Ok(())
    }

    async fn delete(
        &mut self,
        #[zbus(header)] cabecera: zbus::message::Header<'_>,
    ) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        // Borrar la clave del almacén deja la base sin quien la abra, y el
        // sincronizador crearía una nueva: es la misma sustitución por otro lado.
        // Con el secreto de una aplicación pasa igual, y ése no lo borra nadie.
        if is_portal_path(&self.state, &self.path).await {
            return Err(portal_denied());
        }
        let protegido = ruta_protegida(&self.state, &self.path).await;
        if !puede_tocar_el_almacen(&self.conn, &cabecera, &self.state, protegido).await {
            return Err(zbus::fdo::Error::AccessDenied(
                "el ítem es del almacén de cuentas".into(),
            ));
        }

        let col_path = {
            let mut state = self.state.lock().await;
            state.items.remove(&self.path);
            let mut owner = None;
            for (cp, col) in state.collections.iter_mut() {
                if col.items.contains(&self.path) {
                    col.items.retain(|p| p != &self.path);
                    owner = Some(cp.clone());
                }
            }
            owner
        };
        if let (Some(cp), Ok(item)) = (col_path, owned_path_try(&self.path)) {
            if let Ok(emitter) = SignalEmitter::new(&self.conn, cp.as_str()) {
                let _ = CollectionInterface::item_deleted(&emitter, item).await;
            }
        }
        self.persist_all().await?;
        Ok(owned_path("/"))
    }
}

impl ItemInterface {
    /// Si a quien pide se le puede describir este ítem (nombre y atributos).
    ///
    /// La cabecera es `Option` porque así la da zbus en una propiedad: un
    /// `Get` desde adentro del propio demonio no trae mensaje. Sin cabecera no
    /// se sabe quién pide, y para un ítem del almacén eso es un no.
    async fn check_describe(
        &self,
        cabecera: Option<&zbus::message::Header<'_>>,
    ) -> Result<(), zbus::fdo::Error> {
        // Un secreto del portal no se le describe a nadie, ni con cabecera.
        if is_portal_path(&self.state, &self.path).await {
            return Err(portal_denied());
        }
        if !ruta_protegida(&self.state, &self.path).await {
            return Ok(());
        }
        let autorizado = match cabecera {
            Some(cabecera) => puede_tocar_el_almacen(&self.conn, cabecera, &self.state, true).await,
            None => false,
        };
        if autorizado {
            Ok(())
        } else {
            Err(zbus::fdo::Error::AccessDenied(
                "el ítem es del almacén de cuentas".into(),
            ))
        }
    }

    /// Persist the full in-memory item set to the encrypted DB. Used after
    /// mutations (set_secret/delete) so changes survive a daemon restart;
    /// no-ops if the keyring is locked (no master password in memory).
    async fn persist_all(&self) -> Result<(), zbus::fdo::Error> {
        let items: Vec<ItemInfo> = {
            let state = self.state.lock().await;
            state.items.values().cloned().collect()
        };
        save_db(&items).map_err(dbus_err)
    }
}

// ── Collection interface ──────────────────────────────────

struct CollectionInterface {
    state: Arc<Mutex<KeyringState>>,
    conn: Connection,
    path: String,
    alias: String,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionInterface {
    #[zbus(signal)]
    async fn item_created(emitter: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_deleted(emitter: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_changed(emitter: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(property)]
    async fn label(&self) -> Result<String, zbus::fdo::Error> {
        self.state
            .lock()
            .await
            .collections
            .get(&self.path)
            .map(|c| c.label.clone())
            .ok_or_else(|| dbus_err("collection not found"))
    }

    #[zbus(property)]
    async fn locked(&self) -> Result<bool, zbus::fdo::Error> {
        self.state
            .lock()
            .await
            .collections
            .get(&self.path)
            .map(|c| effectively_locked(c.locked))
            .ok_or_else(|| dbus_err("collection not found"))
    }

    #[zbus(property)]
    async fn created(&self) -> Result<u64, zbus::fdo::Error> {
        self.state
            .lock()
            .await
            .collections
            .get(&self.path)
            .map(|c| c.created)
            .ok_or_else(|| dbus_err("collection not found"))
    }

    #[zbus(property)]
    async fn modified(&self) -> Result<u64, zbus::fdo::Error> {
        self.state
            .lock()
            .await
            .collections
            .get(&self.path)
            .map(|c| c.modified)
            .ok_or_else(|| dbus_err("collection not found"))
    }

    /// Los ítems de la colección, sin los secretos del portal: para el bus no
    /// existen (#33).
    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        let state = self.state.lock().await;
        state
            .collections
            .get(&self.path)
            .map(|c| {
                published_paths(&state, &c.items)
                    .iter()
                    .filter_map(|ip| owned_path_try(ip).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    // Per the Secret Service spec, Collection.SearchItems returns a single
    // array of matching items (unlike Service.SearchItems, which splits them
    // into unlocked/locked).
    ///
    /// Los ítems del almacén aparecen sólo para el sincronizador. Para los
    /// demás no existen: con `{}` esto devolvía todos los ítems de la colección,
    /// y era el primer paso para reemplazar la clave del almacén
    /// (Vasak-OS/vasak-keyring#30).
    async fn search_items(
        &self,
        #[zbus(header)] cabecera: zbus::message::Header<'_>,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        let encontrados: Vec<(String, bool)> = {
            let state = self.state.lock().await;
            state
                .collections
                .get(&self.path)
                .map(|col| {
                    col.items
                        .iter()
                        .filter_map(|ip| {
                            let item = state.items.get(ip)?;
                            // Los del portal, para nadie: ni se cuentan para
                            // decidir si hay que preguntarle al bus.
                            if is_portal_item(item) {
                                return None;
                            }
                            coincide(item, &attributes)
                                .then(|| (ip.clone(), es_esquema_protegido(item)))
                        })
                        .collect()
                })
                .unwrap_or_default()
        };

        let alguno_protegido = encontrados.iter().any(|(_, protegido)| *protegido);
        let autorizado =
            puede_tocar_el_almacen(&self.conn, &cabecera, &self.state, alguno_protegido).await;

        Ok(encontrados
            .into_iter()
            .filter(|(_, protegido)| autorizado || !protegido)
            .map(|(ip, _)| owned_path_try(&ip).unwrap_or_else(|_| owned_path("/")))
            .collect())
    }

    ///
    /// Un ítem con el esquema del almacén lo crea sólo el sincronizador. El
    /// esquema es un espacio de nombres del demonio, no de quien llama: con
    /// `replace`, un proceso cualquiera borraba la clave del almacén y ponía una
    /// que eligió él, y sin `replace` plantaba otra que el sincronizador podía
    /// encontrar primero (Vasak-OS/vasak-keyring#29). Se rechaza el pedido
    /// entero, no sólo el `replace`.
    async fn create_item(
        &mut self,
        #[zbus(header)] cabecera: zbus::message::Header<'_>,
        properties: HashMap<String, Value<'_>>,
        secret: SecretStruct,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretError> {
        let label = properties
            .get("org.freedesktop.Secret.Item.Label")
            .and_then(value_to_string)
            .unwrap_or_else(|| "Unnamed".to_string());

        let attributes = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .and_then(value_to_attrmap)
            .unwrap_or_default();

        // El esquema del portal —o la marca con la que el demonio firma sus
        // secretos— no lo crea nadie desde el bus, con `replace` o sin él: sin
        // `replace` se plantaba el secreto de una aplicación antes de que lo
        // pidiera, y con `replace` se le cambiaba el que tenía (#33). Va antes
        // que todo y sin preguntarle nada al bus: no hay a quién.
        if is_portal_attributes(&attributes) {
            eprintln!(
                "vasak-keyring: se rechaza un CreateItem de {} con el esquema del portal",
                cabecera
                    .sender()
                    .map(|s| s.as_str().to_owned())
                    .unwrap_or_else(|| "un emisor desconocido".into())
            );
            return Err(SecretError::AccessDenied);
        }

        // Quién pide, antes que si se puede escribir: a quien no puede tocar el
        // almacén no le importa si el llavero está abierto.
        let protegido = atributos_protegidos(&attributes);
        if !puede_tocar_el_almacen(&self.conn, &cabecera, &self.state, protegido).await {
            return Err(SecretError::AccessDenied);
        }
        escritura_bloqueada()?;

        let mut state = self.state.lock().await;

        // Decrypt before anything else: a client that opened a DH session sends
        // ciphertext, and storing that verbatim would corrupt the item.
        let plaintext = state
            .sessions
            .get(secret.session.as_str())
            .ok_or_else(|| dbus_err("session not found"))?
            .decode(&secret.parameters, secret.value)?;

        if replace {
            let existing: Vec<String> = {
                let col = state
                    .collections
                    .get(&self.path)
                    .ok_or_else(|| dbus_err("collection not found"))?;
                col.items
                    .iter()
                    .filter(|ip| {
                        // Un secreto del portal nunca se reemplaza, aunque los
                        // atributos coincidan: la puerta de arriba ya lo impide,
                        // y esto es la segunda mirada, con el candado tomado.
                        state.items.get(*ip).is_some_and(|item| {
                            item.attributes == attributes && !is_portal_item(item)
                        })
                    })
                    .cloned()
                    .collect()
            };
            for ip in &existing {
                state.items.remove(ip);
            }
            if let Some(col) = state.collections.get_mut(&self.path) {
                col.items.retain(|p| !existing.contains(p));
            }
        }

        let item_path = format!("{}/items/{}", self.path, state.take_item_id());

        let info = ItemInfo {
            label,
            attributes,
            secret: plaintext,
            content_type: secret.content_type,
            created: now(),
            modified: now(),
        };
        state.items.insert(item_path.clone(), info);

        if let Some(col) = state.collections.get_mut(&self.path) {
            col.items.push(item_path.clone());
            col.modified = now();
        }

        // Register item interface
        let owned = owned_path_try(&item_path)?;
        drop(state);

        let iface = ItemInterface {
            state: self.state.clone(),
            conn: self.conn.clone(),
            path: item_path.clone(),
        };
        self.conn
            .object_server()
            .at(item_path.clone(), iface)
            .await
            .map(|_| ())
            .map_err(|e| dbus_err(format!("{e}")))?;

        self.persist().await?;

        if let Ok(emitter) = SignalEmitter::new(&self.conn, self.path.as_str()) {
            let _ = CollectionInterface::item_created(&emitter, owned.clone()).await;
        }

        Ok((owned, owned_path("/")))
    }

    ///
    /// Una colección que guarda la clave del almacén la borra sólo el
    /// sincronizador: borrarla se lleva la clave con todo lo demás, y es la
    /// misma sustitución que `Item.Delete` por un camino más ancho.
    async fn delete(
        &mut self,
        #[zbus(header)] cabecera: zbus::message::Header<'_>,
    ) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        let negado = || {
            zbus::fdo::Error::AccessDenied(
                "la colección guarda la clave del almacén de cuentas".into(),
            )
        };
        // Una colección con secretos del portal no la borra nadie: se llevaría
        // el de cada aplicación, que al volver a pedirlo recibiría uno nuevo y
        // perdería todo lo que había cifrado (#33).
        let negado_portal = || {
            zbus::fdo::Error::AccessDenied(
                "la colección guarda secretos del portal, que sólo usa el llavero".into(),
            )
        };
        let (protegida, del_portal) = {
            let state = self.state.lock().await;
            (
                coleccion_protegida(&state, &self.path),
                holds_portal_items(&state, &self.path),
            )
        };
        if del_portal {
            return Err(negado_portal());
        }
        let autorizado =
            puede_tocar_el_almacen(&self.conn, &cabecera, &self.state, protegida).await;
        if !autorizado {
            return Err(negado());
        }

        let orphaned_aliases: Vec<String>;
        let removed_items: Vec<String>;
        {
            let mut state = self.state.lock().await;
            // Se vuelve a mirar con el candado que borra: mientras la puerta iba
            // al bus, el sincronizador pudo haber guardado su clave acá. Si la
            // colección pasó a tenerla y la puerta no se consultó, falla cerrado.
            if !protegida && coleccion_protegida(&state, &self.path) {
                return Err(negado());
            }
            // Lo mismo con el portal: mientras la puerta iba al bus, una
            // aplicación pudo haber pedido su secreto por primera vez.
            if holds_portal_items(&state, &self.path) {
                return Err(negado_portal());
            }
            removed_items = match state.collections.remove(&self.path) {
                Some(col) => col.items,
                None => Vec::new(),
            };
            for ip in &removed_items {
                state.items.remove(ip);
            }
            // Drop any aliases (e.g. "default") that pointed at this collection.
            orphaned_aliases = state
                .aliases
                .iter()
                .filter(|(_, v)| *v == &self.path)
                .map(|(k, _)| k.clone())
                .collect();
            state.aliases.retain(|_, v| v != &self.path);
        }

        // Take the objects off the bus too. Leaving them registered would let a
        // client keep calling into a collection that no longer exists.
        let server = self.conn.object_server();
        for ip in &removed_items {
            let _ = server.remove::<ItemInterface, _>(ip.as_str()).await;
        }
        for alias in &orphaned_aliases {
            let _ = server
                .remove::<CollectionInterface, _>(ServiceInterface::alias_path(alias).as_str())
                .await;
        }

        if let Ok(item) = owned_path_try(&self.path) {
            if let Ok(emitter) = SignalEmitter::new(&self.conn, "/org/freedesktop/secrets") {
                let _ = ServiceInterface::collection_deleted(&emitter, item).await;
            }
        }
        Ok(owned_path("/"))
    }
}

impl CollectionInterface {
    /// Writes the whole keyring, not just this collection.
    ///
    /// The database is a single flat item list, so saving only this
    /// collection's items used to erase every other collection's secrets from
    /// disk the moment an item was added here — the loss only became visible
    /// after the next restart.
    async fn persist(&self) -> Result<(), zbus::fdo::Error> {
        let items: Vec<ItemInfo> = {
            let state = self.state.lock().await;
            state.items.values().cloned().collect()
        };
        save_db(&items).map_err(dbus_err)
    }
}

// ── El aviso de que `Locked` cambió ────────────────────────

/// Emite `PropertiesChanged` de `Locked` para una colección y para los ítems que
/// tiene, con el valor **actual** de la propiedad.
///
/// No es específico de un sentido: bloquear y desbloquear se avisan igual, y por
/// eso el nombre no dice ninguno de los dos. Lo que se emite es la propiedad
/// releída del estado, así que un cliente que recibe el aviso tiene que volver
/// a leerla —que es lo que hacen todos— en vez de interpretar el aviso.
///
/// Vive afuera del `#[interface]` a propósito: es un helper interno, no algo
/// para exponer en el bus. Los fallos se ignoran porque el llavero ya quedó
/// como tenía que quedar cuando esto se llama, y un cliente que pierde la señal
/// igual lee bien la propiedad después; lo que no puede es decidir si usar el
/// llavero a ciegas.
///
/// **El candado del estado tiene que estar soltado cuando se llama.** Tanto
/// `object_server().interface()` como el envío son `await` sobre el bus, que
/// puede tardar lo que quiera, y `KeyringState` está detrás de un
/// `tokio::Mutex` del que dependen todas las propiedades y todos los métodos
/// del demonio: emitir con el candado tomado puede dejarlo entero sin
/// contestar.
async fn announce_locked_changed(conn: &Connection, coll_path: &str, item_paths: &[String]) {
    let server = conn.object_server();

    if let Ok(iface) = server.interface::<_, CollectionInterface>(coll_path).await {
        let _ = iface
            .get()
            .await
            .locked_changed(iface.signal_emitter())
            .await;
    }

    for ip in item_paths {
        if let Ok(iface) = server.interface::<_, ItemInterface>(ip.as_str()).await {
            let _ = iface
                .get()
                .await
                .locked_changed(iface.signal_emitter())
                .await;
        }
    }
}

/// Lo que hay que sembrar en una colección recién registrada.
struct DiskLoad {
    items: Vec<ItemInfo>,
    /// Hay una base en el disco y esta sesión no la pudo descifrar.
    ///
    /// No es un fallo —así arranca una sesión nueva, con la contraseña todavía
    /// sin llegar— pero sí es lo que impide guardar: lo que hay en memoria no es
    /// el contenido de esa base, y escribirlo la dejaría vacía.
    undecrypted: bool,
}

impl DiskLoad {
    /// La carga de una máquina sin llavero, o la de una base que no hay.
    fn empty() -> Self {
        Self {
            items: Vec::new(),
            undecrypted: false,
        }
    }
}

/// Las entradas con las que se siembra una colección recién creada.
///
/// Son tres las situaciones en que puede estar la base, y se distinguen a
/// propósito porque dos de ellas se parecían y costaban datos:
///
/// - **Todavía no hay base**: una máquina nueva. Se sigue con una lista vacía y
///   no es un fallo, así que un llavero nuevo se puede abrir.
/// - **Hay base y se puede leer**: se descifra con la contraseña maestra que hay
///   en memoria.
/// - **Hay base y no se puede leer**: el error sube. Antes el `Err` se lo
///   comía el `if let Ok(...)` de quien llamaba, la colección se registraba
///   abierta y sin entradas, y el primer guardado escribía encima de la base
///   que la persona tenía y que nadie había abierto todavía.
///
/// Que el **descifrado** falle sí es normal y no corta nada, y es distinto de
/// una lectura fallida: la base del disco está escrita con una contraseña y la
/// de esta sesión todavía no llegó, así que la colección queda vacía y `aplicar`
/// la carga cuando la contraseña llega por el módulo de PAM o por el diálogo.
///
/// Pero vacío no es lo mismo que «se sabe que está vacío», y esa diferencia es la
/// que se perdía: con una lista vacía en memoria y una base llena en el disco,
/// el primer guardado de la sesión escribía esa lista vacía por encima. Por eso
/// el tercer caso sale marcado en `undecrypted` y no como una lista vacía
/// cualquiera, y quien siembra lo convierte en un bloqueo de escritura.
///
/// `password` va por parámetro y no se lee acá adentro porque las dos
/// situaciones —no llegó ninguna, o llegó una que no abre— tienen que poder
/// provocarse por separado en las pruebas.
async fn items_from_disk(
    db_path: &std::path::Path,
    password: Option<&str>,
) -> Result<DiskLoad, zbus::fdo::Error> {
    let raw = match leer_base(db_path).await {
        Ok(Some(raw)) => raw,
        Ok(None) => return Ok(DiskLoad::empty()),
        Err(e) => {
            return Err(dbus_err(format!(
                "no se pudo leer la base del llavero: {e}"
            )));
        }
    };

    let mut loaded: Vec<ItemInfo> = Vec::new();

    let Some(pwd) = password else {
        // Lo normal al arrancar: la contraseña llega después, al
        // iniciar sesión. Se dice en tono informativo y no como
        // un fallo, que es como se leía en el diario de cada
        // arranque mientras el problema real estaba en otra parte.
        println!(
            "[vasak-keyring] hay una base en disco; \
             esperando la contraseña del inicio de sesión"
        );
        return Ok(DiskLoad {
            items: loaded,
            undecrypted: false,
        });
    };

    match crypto::decrypt_database(&raw, pwd) {
        Ok(db) => {
            let items = &db.items;
            for si in items {
                loaded.push(ItemInfo {
                    label: si.label.clone(),
                    attributes: si.attributes.clone(),
                    secret: si.secret.clone(),
                    content_type: "text/plain".into(),
                    created: now(),
                    modified: now(),
                });
            }
            Ok(DiskLoad {
                items: loaded,
                undecrypted: false,
            })
        }
        Err(e) => {
            // El mensaje va al diario como hasta ahora, pero la lista vacía ya no
            // sale de acá como si fuera la base: sale marcada, y `seed_items` la
            // convierte en un bloqueo de escritura.
            eprintln!("[vasak-keyring] cannot decrypt keyring.db: {e}");
            Ok(DiskLoad {
                items: Vec::new(),
                undecrypted: true,
            })
        }
    }
}

/// Saca las entradas a sembrar y, si la base del disco no se pudo descifrar,
/// deja la escritura bloqueada.
///
/// Vive acá y no dentro de `items_from_disk` para que la decisión se pueda
/// probar sin un bus: `spawn_collection` necesita una conexión para registrar
/// los objetos, y lo que hay que comprobar es que una base sin descifrar frena la
/// escritura.
fn seed_items(carga: DiskLoad) -> Vec<ItemInfo> {
    if carga.undecrypted {
        block_writes();
    }
    carga.items
}

/// Abre la base de `path` con `password` y la adopta como contraseña maestra de
/// la sesión.
///
/// Las tres respuestas significan tres cosas distintas, y por eso no se funden en
/// un `bool`:
///
/// - `Ok(Some(db))`: la contraseña abre la base —o no hay base y ésa va a ser la
///   maestra de la que se cree—. Queda en memoria y se borra el registro de
///   intentos fallidos.
/// - `Ok(None)`: la contraseña no abre la base que hay. No se adopta y cuenta como
///   intento fallido. Es lo que el diálogo y el módulo de PAM leen como «no es
///   la contraseña».
/// - `Err`: la base ni siquiera se pudo leer. No se adopta nada.
///
/// **Acá no se levanta el bloqueo de escritura**, y es deliberado: en el momento
/// en que esta función vuelve, lo que hay en memoria todavía es la lista de antes
/// —vacía, si es el caso que hace falta cuidar—, así que dejarlo escribiendo acá
/// abre la ventana que `reload_collection` cierra. El que sabe cuándo la lista
/// pasó a ser el contenido del disco es el que la carga, y levanta el bloqueo
/// ahí.
///
/// Va con la ruta por parámetro y separada de `aplicar` porque lo que decide acá
/// no necesita el bus —`aplicar` sólo usa la conexión para registrar los objetos
/// en el— y porque es el único lugar del demonio donde una contraseña abre una
/// base: si la decisión de levantar el bloqueo viviera repartida en dos funciones,
/// volvería a ser cierto que basta con tener cualquier contraseña en memoria para
/// escribir por encima de la base de la persona.
async fn adopt_password(
    path: &std::path::Path,
    password: &str,
) -> Result<Option<crypto::KeyringDatabase>, String> {
    let db = match leer_base(path).await {
        Ok(Some(raw)) => match crypto::decrypt_database(&raw, password) {
            Ok(db) => db,
            Err(_) => {
                note_failed_unlock();
                return Ok(None);
            }
        },
        // Todavía no hay archivo: máquina nueva, y la contraseña que acaba de
        // llegar es la maestra de la base que se va a crear.
        Ok(None) => crypto::KeyringDatabase { items: vec![] },
        Err(e) => return Err(e.to_string()),
    };

    set_master_password(password);
    note_successful_unlock();

    Ok(Some(db))
}

/// Reemplaza el contenido de la colección del login por el de la base recién
/// abierta, y levanta el bloqueo de escritura.
///
/// Devuelve las rutas de los items que quedaron y las que se fueron, que el
/// llamador usa para registrar y retirar los objetos en el bus.
///
/// El bloqueo se levanta **adentro** del candado del estado, después de que la
/// colección quedó cargada, y ése es el punto de todo el asunto: desde ese
/// momento «ya se puede guardar» y «lo que hay en memoria es el contenido del
/// disco» son la misma cosa para cualquiera que venga después. El candado del
/// estado sirve porque es el mismo que toma cada camino que guarda —todos
/// fotografían la lista completa de entradas y recién después escriben—, así que
/// un `CreateItem` que ya pasó `ensure_unlocked` y está esperando este candado no
/// puede fotografiar la lista vieja: para cuando lo tome, la lista ya es la
/// nueva.
///
/// Levantarlo antes —al volver de `adopt_password`, que es donde estaba— abría una
/// ventana entre las dos cosas, y en ella la lista en memoria seguía siendo la
/// de antes: vacía en el caso que importa, que es una base que esta sesión no
/// pudo descifrar. Un `CreateItem` que entrara en esa ventana pasaba
/// `ensure_unlocked`, tomaba la foto de una lista vacía y la guardaba encima de
/// la base de la persona. La pérdida no se veía hasta el reinicio siguiente, con
/// el archivo ya pisado y sin forma de saber qué se perdió.
async fn reload_collection(
    state: &Arc<Mutex<KeyringState>>,
    coll_path: &str,
    db: &crypto::KeyringDatabase,
) -> (Vec<String>, Vec<String>) {
    let mut item_paths: Vec<String> = Vec::new();
    let mut state = state.lock().await;

    if !state.collections.contains_key(coll_path) {
        state.collections.insert(
            coll_path.to_string(),
            CollectionInfo {
                label: "Default collection".into(),
                locked: false,
                items: vec![],
                created: now(),
                modified: now(),
            },
        );
    }

    // Unlocking reloads the collection from disk, so whatever it held
    // before is replaced. Item ids are never reused now, so the old
    // paths have to be dropped explicitly or they linger on the bus as
    // duplicates that no longer belong to any collection.
    let stale_paths: Vec<String> = state
        .collections
        .get(coll_path)
        .map(|col| col.items.clone())
        .unwrap_or_default();
    for ip in &stale_paths {
        state.items.remove(ip);
    }

    for si in db.items.iter() {
        let ip = format!("{coll_path}/items/{}", state.take_item_id());
        let info = ItemInfo {
            label: si.label.clone(),
            attributes: si.attributes.clone(),
            secret: si.secret.clone(),
            content_type: "text/plain".into(),
            created: now(),
            modified: now(),
        };
        state.items.insert(ip.clone(), info);
        item_paths.push(ip);
    }

    if let Some(col) = state.collections.get_mut(coll_path) {
        col.items = item_paths.clone();
    }

    // Todo lo de arriba es invisible para quien vaya a leer la lista de entradas:
    // el candado no se suelta hasta acá, y para entonces la lista ya es la del
    // disco.
    unblock_writes();

    (item_paths, stale_paths)
}

// ── Service (root) interface ───────────────────────────────

pub struct ServiceInterface {
    state: Arc<Mutex<KeyringState>>,
    conn: Connection,
}

impl ServiceInterface {
    pub fn new(conn: Connection, state: Arc<Mutex<KeyringState>>) -> Self {
        Self { state, conn }
    }

    pub fn new_default(conn: Connection) -> Self {
        Self::new(conn, Arc::new(Mutex::new(KeyringState::new())))
    }

    pub async fn register_default_collection(&self) -> Result<(), zbus::fdo::Error> {
        self.spawn_collection(
            "/org/freedesktop/secrets/collection/login",
            "login",
            "Default collection",
        )
        .await
    }

    /// Object path an alias is addressed by, per the Secret Service spec.
    fn alias_path(alias: &str) -> String {
        format!("/org/freedesktop/secrets/aliases/{alias}")
    }

    /// Publishes a collection at its alias path as well as its real one.
    ///
    /// libsecret does not call `ReadAlias` to find the default keyring: it
    /// addresses `/org/freedesktop/secrets/aliases/default` directly. With
    /// nothing served there, every store and lookup failed outright with
    /// `Unknown object '/org/freedesktop/secrets/aliases/default'` — so
    /// `secret-tool`, and every app using the `keyring` crate, could not use
    /// the keyring at all.
    ///
    /// The interface keeps pointing at the collection's real path, so items
    /// created through the alias land in the collection itself and signals are
    /// emitted on the canonical path.
    async fn publish_alias(
        &self,
        alias: &str,
        collection_path: &str,
    ) -> Result<(), zbus::fdo::Error> {
        let iface = CollectionInterface {
            state: self.state.clone(),
            conn: self.conn.clone(),
            path: collection_path.to_string(),
            alias: alias.to_string(),
        };
        self.conn
            .object_server()
            .at(Self::alias_path(alias), iface)
            .await
            .map(|_| ())
            .map_err(|e| dbus_err(format!("{e}")))
    }

    /// The object a client is told to prompt on when an unlock cannot happen
    /// right away, or "/" when asking would be a bad idea.
    ///
    /// It is a bad idea when there is no database on disk yet: whatever is typed
    /// would become the master password of a brand new keyring, and a typo there
    /// creates one that the login password will never open again. The first
    /// unlock has to come from the login, where the password is not typed into a
    /// dialog but already known to be the account's.
    async fn spawn_unlock_prompt(&self, objects: Vec<OwnedObjectPath>) -> OwnedObjectPath {
        if !keyring_path().map(|p| p.exists()).unwrap_or(false) {
            return owned_path("/");
        }

        static NEXT_PROMPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_PROMPT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = format!("/org/freedesktop/secrets/prompt/u{id}");

        let iface = PromptInterface {
            conn: self.conn.clone(),
            path: path.clone(),
            objects,
        };

        match self.conn.object_server().at(path.as_str(), iface).await {
            Ok(_) => owned_path(&path),
            // Without an object to prompt on, "/" at least tells the client the
            // truth: nothing was unlocked and nothing is going to ask.
            Err(_) => owned_path("/"),
        }
    }

    async fn spawn_collection(
        &self,
        path: &str,
        alias: &str,
        label: &str,
    ) -> Result<(), zbus::fdo::Error> {
        // Las entradas las decide `items_from_disk`, y su error sube por el `?`:
        // registrar la colección abierta y vacía porque la base no se pudo leer
        // es lo que terminaba escribiendo encima de la base de la persona.
        let pwd = master_password();
        let carga = match keyring_path() {
            Some(db_path) => items_from_disk(&db_path, pwd.as_deref().map(String::as_str)).await?,
            None => DiskLoad::empty(),
        };
        // Y si la base existe pero no la abrió ninguna contraseña, la colección se
        // registra igual —eso es lo normal, la contraseña llega al iniciar sesión—
        // pero sembrarla deja la escritura bloqueada: sin ese paso, una lista
        // vacía en memoria se confundía con una base vacía en el disco.
        let loaded: Vec<ItemInfo> = seed_items(carga);

        let mut state = self.state.lock().await;
        let col_info = CollectionInfo {
            label: label.to_string(),
            locked: false,
            items: vec![],
            created: now(),
            modified: now(),
        };
        // Las entradas se arman **antes** de insertar la colección, así se
        // inserta ya completa.
        //
        // Estaba al revés —insertar, llenar, y volver a buscarla con
        // `get_mut().unwrap()`— para sortear el préstamo mutable de
        // `take_item_id()`. Correcto, pero el `unwrap` dependía de que las dos
        // partes usaran la misma clave: cualquier cambio en el medio lo
        // convertía en un panic dentro del demonio del llavero.
        let mut item_paths = Vec::new();
        for si in loaded {
            let ip = format!("{path}/items/{}", state.take_item_id());
            state.items.insert(ip.clone(), si);
            item_paths.push(ip);
        }

        let col_info = CollectionInfo {
            items: item_paths.clone(),
            ..col_info
        };
        state.collections.insert(path.to_string(), col_info);
        state.aliases.insert(alias.to_string(), path.to_string());
        // The login collection is the default keyring; libsecret resolves the
        // "default" alias when storing/looking up passwords.
        if alias == "login" {
            state
                .aliases
                .insert("default".to_string(), path.to_string());
        }

        // Register item interfaces. Los secretos del portal no: para el bus no
        // existen (#33).
        for ip in &published_paths(&state, &item_paths) {
            let iface = ItemInterface {
                state: self.state.clone(),
                conn: self.conn.clone(),
                path: ip.clone(),
            };
            self.conn
                .object_server()
                .at(ip.clone(), iface)
                .await
                .map(|_| ())
                .map_err(|e| dbus_err(format!("{e}")))?;
        }

        // Register collection interface
        let iface = CollectionInterface {
            state: self.state.clone(),
            conn: self.conn.clone(),
            path: path.to_string(),
            alias: alias.to_string(),
        };
        self.conn
            .object_server()
            .at(path.to_string(), iface)
            .await
            .map(|_| ())
            .map_err(|e| dbus_err(format!("{e}")))?;

        self.publish_alias(alias, path).await?;
        if alias == "login" {
            self.publish_alias("default", path).await?;
        }
        Ok(())
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl ServiceInterface {
    #[zbus(signal)]
    async fn collection_created(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_deleted(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_changed(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        let state = self.state.lock().await;
        state
            .collections
            .keys()
            .filter_map(|p| owned_path_try(p).ok())
            .collect()
    }

    async fn open_session(
        &mut self,
        algorithm: &str,
        input: Value<'_>,
    ) -> Result<(OwnedValue, OwnedObjectPath), zbus::fdo::Error> {
        // `output` is the server's DH public value, or an empty array for a
        // plain session.
        let (shared_key, output) = match algorithm {
            session_crypto::PLAIN_ALGORITHM => (None, Vec::new()),

            session_crypto::DH_ALGORITHM => {
                let client_public = extract_bytes(&input)?;
                let dh = session_crypto::negotiate(&client_public)
                    .map_err(zbus::fdo::Error::InvalidArgs)?;
                (Some(dh.session_key), dh.server_public)
            }

            // Clients try the algorithms they support in order and fall back on
            // this error, so it has to be NotSupported: Failed reads as "the
            // keyring is broken" and they give up instead of retrying plain.
            other => {
                return Err(zbus::fdo::Error::NotSupported(format!(
                    "unsupported algorithm: {other}"
                )))
            }
        };

        let path = {
            let mut state = self.state.lock().await;
            let id = state.next_session;
            state.next_session += 1;
            let path = format!("/org/freedesktop/secrets/session/s{id}");

            state.sessions.insert(
                path.clone(),
                SessionInfo {
                    algorithm: algorithm.to_string(),
                    shared_key,
                    created: now(),
                },
            );
            path
        };

        let iface = SessionInterface {
            state: self.state.clone(),
            path: path.clone(),
        };
        self.conn
            .object_server()
            .at(path.clone(), iface)
            .await
            .map(|_| ())
            .map_err(|e| dbus_err(format!("{e}")))?;

        Ok((u8_array_value(output), owned_path_try(&path)?))
    }

    async fn create_collection(
        &mut self,
        properties: HashMap<String, Value<'_>>,
        alias: &str,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), zbus::fdo::Error> {
        {
            let state = self.state.lock().await;
            let p = format!("/org/freedesktop/secrets/collection/{alias}");
            if state.collections.contains_key(&p) {
                return Ok((owned_path_try(&p)?, owned_path("/")));
            }
        }

        let label = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(value_to_string)
            .unwrap_or_else(|| alias.to_string());

        let path = format!("/org/freedesktop/secrets/collection/{alias}");
        self.spawn_collection(&path, alias, &label).await?;

        let owned = owned_path_try(&path)?;
        if let Ok(emitter) = SignalEmitter::new(&self.conn, "/org/freedesktop/secrets") {
            let _ = ServiceInterface::collection_created(&emitter, owned.clone()).await;
        }
        Ok((owned, owned_path("/")))
    }

    /// Los ítems del almacén aparecen sólo para el sincronizador; ver
    /// `Collection.SearchItems`.
    async fn search_items(
        &self,
        #[zbus(header)] cabecera: zbus::message::Header<'_>,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), zbus::fdo::Error> {
        // (ruta, bloqueado, protegido)
        let encontrados: Vec<(String, bool, bool)> = {
            let state = self.state.lock().await;
            state
                .collections
                .values()
                .flat_map(|col| {
                    col.items.iter().filter_map(|ip| {
                        let item = state.items.get(ip)?;
                        if is_portal_item(item) {
                            return None;
                        }
                        coincide(item, &attributes).then(|| {
                            (
                                ip.clone(),
                                effectively_locked(col.locked),
                                es_esquema_protegido(item),
                            )
                        })
                    })
                })
                .collect()
        };

        let alguno_protegido = encontrados.iter().any(|(_, _, protegido)| *protegido);
        let autorizado =
            puede_tocar_el_almacen(&self.conn, &cabecera, &self.state, alguno_protegido).await;

        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        for (ip, bloqueado, protegido) in encontrados {
            if protegido && !autorizado {
                continue;
            }
            let o = owned_path_try(&ip).unwrap_or_else(|_| owned_path("/"));
            if bloqueado {
                locked.push(o)
            } else {
                unlocked.push(o)
            }
        }
        Ok((unlocked, locked))
    }

    async fn read_alias(&self, alias: &str) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        let state = self.state.lock().await;
        if let Some(path) = state.aliases.get(alias) {
            return owned_path_try(path);
        }
        // Fall back to the path convention for collections without an alias.
        let p = format!("/org/freedesktop/secrets/collection/{alias}");
        if state.collections.contains_key(&p) {
            owned_path_try(&p)
        } else {
            Ok(owned_path("/"))
        }
    }

    async fn set_alias(
        &mut self,
        alias: &str,
        collection: OwnedObjectPath,
    ) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        let target = {
            let mut state = self.state.lock().await;
            if collection.as_str() == "/" {
                state.aliases.remove(alias);
                None
            } else if state.collections.contains_key(collection.as_str()) {
                state
                    .aliases
                    .insert(alias.to_string(), collection.as_str().to_string());
                Some(collection.as_str().to_string())
            } else {
                return Err(dbus_err("collection not found"));
            }
        };

        // The alias object has to follow the map, or clients keep reaching the
        // collection the alias used to point at.
        let _ = self
            .conn
            .object_server()
            .remove::<CollectionInterface, _>(Self::alias_path(alias).as_str())
            .await;

        if let Some(path) = target {
            self.publish_alias(alias, &path).await?;
        }

        Ok(owned_path("/"))
    }

    async fn unlock(
        &mut self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), zbus::fdo::Error> {
        // Clearing the per-collection flag cannot unlock anything while there is
        // no master password in memory. The spec's answer for "not now, ask the
        // user" is a prompt object: the client calls Prompt() on it and waits
        // for Completed, which is the flow libsecret already drives on its own.
        // Reporting the objects as unlocked instead made clients carry on and
        // hit LOCKED_MESSAGE.
        if master_password().is_none() {
            return Ok((Vec::new(), self.spawn_unlock_prompt(objects).await));
        }

        let mut out = Vec::new();
        // Igual que en `lock`: las colecciones que cambian de verdad, con sus
        // ítems, se anotan adentro y se avisan con el candado suelto.
        let mut abiertas: Vec<(String, Vec<String>)> = Vec::new();
        {
            let mut state = self.state.lock().await;
            for obj in &objects {
                let s = obj.as_str().to_string();
                if let Some(col) = state.collections.get_mut(&s) {
                    col.locked = false;
                    abiertas.push((s, col.items.clone()));
                    out.push(obj.clone());
                }
            }
        }

        // **Avisar el desbloqueo es lo mismo que avisar el bloqueo.** Si sólo se
        // avisara uno de los dos sentidos, el cliente que oyó «se bloqueó» se
        // quedaría creyendo que el llavero sigue bloqueado después del
        // `Unlock`, que es el otro camino para levantarlo.
        for (path, items) in &abiertas {
            announce_locked_changed(&self.conn, path, items).await;
        }

        Ok((out, owned_path("/")))
    }

    async fn lock(
        &mut self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), zbus::fdo::Error> {
        let mut out = Vec::new();
        // La colección que quedó bloqueada, con los ítems que tiene, para
        // avisar abajo. Se anotan **dentro** del recorrido porque es el único
        // lugar donde se sabe cuáles eran.
        let mut bloqueadas: Vec<(String, Vec<String>)> = Vec::new();
        {
            let mut state = self.state.lock().await;
            for obj in &objects {
                let s = obj.as_str().to_string();
                if let Some(col) = state.collections.get_mut(&s) {
                    col.locked = true;
                    bloqueadas.push((s, col.items.clone()));
                    out.push(obj.clone());
                }
            }
        }

        // El candado del estado ya está soltado, y por algo: emitir con el
        // tomado puede dejar al demonio entero sin contestar, y `Locked` acaba
        // de cambiar. Es el mismo cuidado que en el camino del desbloqueo, que
        // registra los objetos y avisa con el candado suelto.
        for (path, items) in &bloqueadas {
            announce_locked_changed(&self.conn, path, items).await;
        }

        Ok((out, owned_path("/")))
    }

    /// Los secretos de varios ítems, de una vez.
    ///
    /// **Acá no va `IsLocked`, y es a propósito.** Los ítems de una colección
    /// bloqueada se omiten y se devuelve el mapa parcial: es lo que contesta
    /// desde siempre, y pasarlo a error cambiaría el contrato con cada cliente
    /// que anda bien hoy —`libsecret` incluido, que ya sabe qué hacer con un
    /// `IsLocked— sin que el issue lo pida. Queda anotado acá para que la
    /// próxima vez que se toque no parezca un olvido: si algún día se decide
    /// pasarlo a error, es una decisión de contrato, no un nombre de error.
    ///
    /// La lectura de a uno sí lleva el nombre del estándar
    /// ([`ItemInterface::get_secret`]), y es la que usa el sincronizador de
    /// `vasak-accounts`.
    async fn get_secrets(
        &self,
        #[zbus(header)] cabecera: zbus::message::Header<'_>,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        // Keyed by object path, not string: the spec declares `a{o(oayays)}`
        // and libsecret refuses the `a{s(oayays)}` a String key produces.
    ) -> Result<HashMap<OwnedObjectPath, SecretStruct>, zbus::fdo::Error> {
        // Una sola vez por llamada, antes del lock, y sólo si la lista tiene
        // algún ítem del almacén: el chequeo no depende del ítem —depende de
        // quién pregunta—, y para una lista de contraseñas comunes no hace falta.
        // Ver `get_secret`.
        let (alguno_protegido, esperado) = {
            let state = self.state.lock().await;
            let alguno = items.iter().any(|ip| {
                state
                    .items
                    .get(ip.as_str())
                    .is_some_and(es_esquema_protegido)
            });
            (alguno, state.ejecutable_del_sincronizador())
        };
        let autorizado = alguno_protegido
            && autorizado_para_esquema_protegido(&self.conn, &cabecera, &esperado).await;

        let state = self.state.lock().await;
        let mut result = HashMap::new();
        for ip in &items {
            let ip_str = ip.as_str();
            // Skip items whose collection is locked.
            if state
                .collections
                .values()
                .any(|c| effectively_locked(c.locked) && c.items.iter().any(|p| p == ip_str))
            {
                continue;
            }
            if let Some(item) = state.items.get(ip.as_str()) {
                if let Some(ses) = state.sessions.get(session.as_str()) {
                    // Un ítem protegido se omite pero no corta el mapa entero:
                    // es el mismo trato que reciben las colecciones bloqueadas
                    // acá arriba, y el contrato de `GetSecrets` es devolver la
                    // parte que sí se puede leer.
                    if !access_allowed(item, autorizado) {
                        continue;
                    }
                    // Encrypted sessions used to be skipped outright here, so a
                    // client that opened one got an empty map back from
                    // GetSecrets and concluded it had no stored passwords.
                    let (parameters, value) = ses.encode(&item.secret)?;
                    result.insert(
                        ip.clone(),
                        SecretStruct {
                            session: session.clone(),
                            parameters,
                            value,
                            content_type: item.content_type.clone(),
                        },
                    );
                }
            }
        }
        Ok(result)
    }
}

// ── Unlock prompt ──────────────────────────────────────────

/// The dialog that asks for the password when the login did not provide it.
const PROMPTER: &str = "/usr/bin/vasak-keyring-prompt";

/// One `org.freedesktop.Secret.Prompt`, alive for a single unlock request.
///
/// The Secret Service spec puts asking the user behind this object: a client
/// that finds the keyring locked calls `Service.Unlock`, gets a prompt back,
/// calls `Prompt()` on it and waits for `Completed`. libsecret does all of that
/// on its own, so implementing it here is what makes every application — the
/// Vasak ones, browsers, editors — able to offer the unlock instead of failing.
///
/// The daemon does not draw anything: it runs the dialog, which unlocks through
/// the same private interface the PAM module uses, and then reports what
/// happened. Whether the password was right is not something this object needs
/// to know — only whether a master password ended up in memory.
pub struct PromptInterface {
    conn: Connection,
    path: String,
    /// What the caller asked to unlock, echoed back in `Completed`.
    objects: Vec<OwnedObjectPath>,
}

impl PromptInterface {
    /// Runs the dialog and answers the waiting client.
    async fn run(conn: Connection, path: String, objects: Vec<OwnedObjectPath>) {
        let unlocked = Self::ask().await && master_password().is_some();

        if let Ok(emitter) = SignalEmitter::new(&conn, path.as_str()) {
            let result = if unlocked { objects } else { Vec::new() };
            let value = Value::Array(zvariant::Array::from(result));
            let _ = Self::completed(&emitter, !unlocked, value).await;
        }

        // A prompt is good for one answer, and the client already has it.
        let _ = conn
            .object_server()
            .remove::<PromptInterface, _>(path.as_str())
            .await;
    }

    /// Shows the dialog and waits for it. `true` means the person went through
    /// with it; a cancel, a missing binary or a crash all mean `false`.
    ///
    /// It goes through `systemd-run --user` on purpose: the daemon starts with
    /// the session, usually before the compositor, so its own environment has no
    /// WAYLAND_DISPLAY and anything graphical it spawned directly would fail to
    /// open a window. The systemd user manager does have it, put there by
    /// `uwsm finalize` when the session came up.
    async fn ask() -> bool {
        let via_systemd = tokio::process::Command::new("systemd-run")
            .args([
                "--user",
                "--wait",
                "--collect",
                "--quiet",
                "--pipe",
                PROMPTER,
            ])
            .status()
            .await;

        match via_systemd {
            Ok(status) => status.success(),
            Err(_) => tokio::process::Command::new(PROMPTER)
                .status()
                .await
                .map(|status| status.success())
                .unwrap_or(false),
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptInterface {
    /// Returns as soon as the dialog is on its way, per the spec: the answer
    /// travels in `Completed`. Blocking here instead would hold the client's
    /// method call open for as long as somebody takes to type.
    async fn prompt(&mut self, _window_id: String) -> Result<(), zbus::fdo::Error> {
        let conn = self.conn.clone();
        let path = self.path.clone();
        let objects = self.objects.clone();

        tokio::spawn(async move { Self::run(conn, path, objects).await });
        Ok(())
    }

    async fn dismiss(&mut self) -> Result<(), zbus::fdo::Error> {
        if let Ok(emitter) = SignalEmitter::new(&self.conn, self.path.as_str()) {
            let empty = Value::Array(zvariant::Array::from(Vec::<OwnedObjectPath>::new()));
            let _ = Self::completed(&emitter, true, empty).await;
        }

        let conn = self.conn.clone();
        let path = self.path.clone();
        tokio::spawn(async move {
            let _ = conn
                .object_server()
                .remove::<PromptInterface, _>(path.as_str())
                .await;
        });

        Ok(())
    }

    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

// ── Rate limiting ──────────────────────────────────────────

/// Wrong passwords in a row before the daemon stops answering for a while.
const UNLOCK_MAX_ATTEMPTS: u32 = 3;
/// How long it stays shut after that.
const UNLOCK_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

/// Failed attempts, and until when to refuse.
///
/// Anything running in the session can call `Unlock`, and without a limit it can
/// sit there trying passwords as fast as the daemon answers. That is not a new
/// exposure — whoever is in the session can also read the database file and
/// attack it offline — but at least it should not be the fastest way in, and a
/// program grinding away at it now has to wait like everyone else.
///
/// Only wrong answers count. Unlocking correctly clears the record, and so does
/// letting the cooldown expire.
struct UnlockAttempts {
    failures: u32,
    blocked_until: Option<std::time::Instant>,
}

fn unlock_attempts() -> &'static StdMutex<UnlockAttempts> {
    static ATTEMPTS: OnceLock<StdMutex<UnlockAttempts>> = OnceLock::new();
    ATTEMPTS.get_or_init(|| {
        StdMutex::new(UnlockAttempts {
            failures: 0,
            blocked_until: None,
        })
    })
}

/// Seconds left of the cooldown, or `None` when there is none.
fn unlock_blocked_for() -> Option<u64> {
    let mut attempts = unlock_attempts().lock().ok()?;
    let until = attempts.blocked_until?;
    let left = until.saturating_duration_since(std::time::Instant::now());

    if left.is_zero() {
        attempts.blocked_until = None;
        attempts.failures = 0;
        return None;
    }

    Some(left.as_secs().max(1))
}

fn note_failed_unlock() {
    if let Ok(mut attempts) = unlock_attempts().lock() {
        attempts.failures += 1;
        if attempts.failures >= UNLOCK_MAX_ATTEMPTS {
            attempts.failures = 0;
            attempts.blocked_until = Some(std::time::Instant::now() + UNLOCK_COOLDOWN);
        }
    }
}

fn note_successful_unlock() {
    if let Ok(mut attempts) = unlock_attempts().lock() {
        attempts.failures = 0;
        attempts.blocked_until = None;
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;

    /// One test for the whole thing on purpose: the counter is process-wide, as
    /// it has to be, so two tests touching it in parallel would fight over it.
    #[test]
    fn three_wrong_passwords_close_the_door_and_the_right_one_opens_it() {
        assert_eq!(unlock_blocked_for(), None, "arranca sin bloqueo");

        for _ in 0..UNLOCK_MAX_ATTEMPTS - 1 {
            note_failed_unlock();
            assert_eq!(unlock_blocked_for(), None, "todavía quedan intentos");
        }

        note_failed_unlock();
        let left = unlock_blocked_for().expect("el tercer fallo bloquea");
        assert!(left <= UNLOCK_COOLDOWN.as_secs() && left > 0);

        // Unlocking is what clears it — including the wait, so somebody who
        // remembers the password is not left sitting out a cooldown.
        note_successful_unlock();
        assert_eq!(unlock_blocked_for(), None);

        // And the count starts over, rather than the next mistake locking again.
        note_failed_unlock();
        assert_eq!(unlock_blocked_for(), None);
        note_successful_unlock();
    }
}

// ── PAM unlock interface (called by pam_vasak_keyring.so) ──

pub struct PamUnlockInterface {
    state: Arc<Mutex<KeyringState>>,
    conn: Connection,
}

impl PamUnlockInterface {
    pub fn new(state: Arc<Mutex<KeyringState>>, conn: Connection) -> Self {
        Self { state, conn }
    }
}

impl PamUnlockInterface {
    /// Adopta `password` como contraseña maestra de la sesión, si abre la base.
    ///
    /// Vive acá y no dentro del método de D-Bus porque hay dos formas de llegar
    /// con la contraseña, y por buenas razones: el diálogo gráfico corre como el
    /// usuario y usa el bus, pero el módulo de PAM corre como root dentro del
    /// gestor de inicio de sesión y el bus de sesión no lo deja entrar. Ese
    /// llega por el socket de `unlock_socket.rs`.
    pub async fn aplicar(&self, password: &str) -> Result<bool, zbus::fdo::Error> {
        // Refused rather than answered `false`: the caller is being told to stop
        // trying, which is a different thing from the password being wrong, and
        // the dialog says so instead of blaming the password.
        if let Some(seconds) = unlock_blocked_for() {
            return Err(dbus_err(format!(
                "demasiados intentos fallidos: probá de nuevo en {seconds} s"
            )));
        }

        let path = match keyring_path() {
            Some(p) => p,
            None => return Ok(false),
        };

        // Toda la decisión sobre la contraseña vive en `adopt_password`: acá sólo
        // se recarga la colección con lo que salió de ahí.
        let Some(db) = adopt_password(&path, password).await.map_err(dbus_err)? else {
            return Ok(false);
        };

        let coll_path = "/org/freedesktop/secrets/collection/login".to_string();

        // La carga y el levantamiento del bloqueo van en una sola función, y en ese
        // orden: mientras la lista de entradas en memoria no sea la del disco no se
        // puede escribir. Sacarlos en funciones separadas fue lo que abrió la
        // ventana; ver `reload_collection`.
        let (item_paths, stale_paths) = reload_collection(&self.state, &coll_path, &db).await;
        // Lo que se publica y se avisa es lo que el bus puede ver: los secretos
        // del portal quedan en memoria para el backend y fuera del bus (#33).
        let item_paths = published_paths(&*self.state.lock().await, &item_paths);

        for ip in &stale_paths {
            let _ = self
                .conn
                .object_server()
                .remove::<ItemInterface, _>(ip.as_str())
                .await;
        }

        for ip in &item_paths {
            let iface = ItemInterface {
                state: self.state.clone(),
                conn: self.conn.clone(),
                path: ip.clone(),
            };
            self.conn
                .object_server()
                .at(ip.clone(), iface)
                .await
                .map(|_| ())
                .map_err(|e| dbus_err(format!("{e}")))?;
        }

        let iface = CollectionInterface {
            state: self.state.clone(),
            conn: self.conn.clone(),
            path: coll_path.clone(),
            alias: "login".into(),
        };
        self.conn
            .object_server()
            .at(coll_path.clone(), iface)
            .await
            .map(|_| ())
            .map_err(|e| dbus_err(format!("{e}")))?;

        // Everything above changed the answer of the `Locked` properties from
        // true to false. Applications started before the unlock cached the old
        // value, so without a change notification they keep believing the
        // keyring is unusable for the rest of the session.
        announce_locked_changed(&self.conn, &coll_path, &item_paths).await;

        Ok(true)
    }
}

#[interface(name = "org.vasak.Keyring")]
impl PamUnlockInterface {
    /// El desbloqueo por D-Bus, que usa el diálogo gráfico.
    async fn unlock(&mut self, password: &str) -> Result<bool, zbus::fdo::Error> {
        self.aplicar(password).await
    }
}

// ── Secreto maestro por aplicación (portal Secret) ─────────

/// Cuántos bytes tiene el secreto maestro que se le da a una aplicación.
///
/// Es una clave, no una contraseña: no la escribe nadie, así que conviene que
/// sea larga. 64 bytes es lo que usan las otras implementaciones del portal.
const PORTAL_SECRET_LEN: usize = 64;

/// Serializa la creación de secretos maestros.
///
/// Sin esto, dos pedidos simultáneos para la misma aplicación pasan los dos por
/// el «¿ya existe?», los dos generan, y los dos insertan **con rutas distintas**
/// —el contador de items da ids distintos— así que quedan dos entradas con los
/// mismos atributos. Después, `find` recorre un `HashMap`: devuelve una o la otra
/// según el orden interno, que no es estable. Lo que la aplicación cifró con la
/// que recibió primero deja de abrirse.
///
/// Un único candado global y no uno por aplicación: un secreto maestro se crea
/// una vez en la vida de cada programa, así que serializarlos todos no cuesta
/// nada y no hay que mantener un mapa de candados.
fn creation_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Los atributos con los que el demonio guarda el secreto de `app_id`: el
/// esquema del portal, la aplicación, y la marca de que lo creó el demonio.
fn portal_attributes(app_id: &str) -> HashMap<String, String> {
    HashMap::from([
        (ATRIBUTO_ESQUEMA.to_string(), PORTAL_SCHEMA.to_string()),
        ("app_id".to_string(), app_id.to_string()),
        (
            PORTAL_ORIGIN_ATTRIBUTE.to_string(),
            PORTAL_ORIGIN_VALUE.to_string(),
        ),
    ])
}

/// Los atributos con los que se guardaba el secreto de `app_id` hasta 0.7.8,
/// sin la marca. Un ítem así no se le da a la aplicación: ver
/// [`app_master_secret`].
fn legacy_portal_attributes(app_id: &str) -> HashMap<String, String> {
    HashMap::from([
        (ATRIBUTO_ESQUEMA.to_string(), PORTAL_SCHEMA.to_string()),
        ("app_id".to_string(), app_id.to_string()),
    ])
}

/// El secreto maestro de una aplicación, creándolo la primera vez.
///
/// La especificación del portal pide que sea **único por aplicación y estable
/// mientras esté instalada**, así que no se deriva de nada: se genera al azar la
/// primera vez y queda guardado en el llavero. Si se derivara de la contraseña
/// maestra, cambiar la contraseña de la cuenta cambiaría el secreto de todas las
/// aplicaciones a la vez, y lo que cada una hubiera cifrado con él dejaría de
/// abrirse.
///
/// **No se publica en el Secret Service.** Hasta 0.7.8 quedaba como una
/// entrada más, y eso era el agujero: cualquier proceso de la sesión podía
/// leerlo, cambiarlo, borrarlo o plantarlo antes (#33). Ahora es del demonio;
/// ver «El espacio de nombres del portal».
///
/// **Y un secreto de antes de esta versión no se entrega.** Mientras el esquema
/// estuvo abierto, cualquiera pudo haber creado el de una aplicación que todavía
/// no lo había pedido, y uno plantado no se distingue de uno legítimo: los dos
/// tienen los mismos atributos y un secreto que cualquiera sabe generar. Por
/// eso sólo se busca el que lleva [`PORTAL_ORIGIN_ATTRIBUTE`], que desde esta
/// versión sólo puede ponerlo el demonio, y el de antes queda en la base sin
/// usarse ni borrarse. La aplicación recibe uno nuevo y deja de abrir lo que
/// había cifrado con el anterior: es el precio de no darle una clave que otro
/// puede conocer. En VasakOS el precio es chico —el portal Secret lo usan las
/// aplicaciones en sandbox, y el sistema no las trae— y queda en el diario.
pub async fn app_master_secret(
    state: &Arc<Mutex<KeyringState>>,
    app_id: &str,
) -> Result<Vec<u8>, String> {
    if app_id.is_empty() {
        // Sin identidad no hay a qué atarlo. Devolver algo acá sería darle el
        // mismo secreto a todo lo que pregunte.
        return Err("la aplicación no tiene identificador".into());
    }
    // `ensure_unlocked` y no un «¿hay contraseña maestra?» propio: esta función
    // crea una entrada y la guarda, así que es una escritura más —y va por el
    // backend del portal, no por un alta de una aplicación—, y con la base sin
    // descifrar escribiría una base vacía por encima de la que la persona tenía.
    ensure_unlocked()?;

    let attributes = portal_attributes(app_id);

    // Todo el «buscar, y si no está crear» va bajo un mismo candado: si dos
    // pedidos simultáneos pasaran los dos por la búsqueda, crearían dos secretos
    // distintos para la misma aplicación. Ver `creation_lock`.
    let _guard = creation_lock().lock().await;

    if let Some(existing) = find_secret(state, &attributes).await {
        return Ok(existing);
    }

    if find_secret(state, &legacy_portal_attributes(app_id))
        .await
        .is_some()
    {
        eprintln!(
            "vasak-keyring: «{app_id}» tenía un secreto del portal de antes de 0.7.9, cuando \
             cualquier proceso podía crearlo o cambiarlo. No se le entrega: recibe uno nuevo, \
             y lo que haya cifrado con el anterior deja de abrirse (Vasak-OS/vasak-keyring#33)"
        );
    }

    use rand::RngCore;
    let mut secret = vec![0u8; PORTAL_SECRET_LEN];
    rand::thread_rng().fill_bytes(&mut secret);

    let collection = "/org/freedesktop/secrets/collection/login";
    let path = {
        let mut state = state.lock().await;
        let path = format!("{collection}/items/{}", state.take_item_id());

        state.items.insert(
            path.clone(),
            ItemInfo {
                label: format!("Secreto de {app_id}"),
                attributes,
                secret: secret.clone(),
                content_type: "application/octet-stream".into(),
                created: now(),
                modified: now(),
            },
        );
        if let Some(col) = state.collections.get_mut(collection) {
            col.items.push(path.clone());
            col.modified = now();
        }
        path
    };

    // Se guarda **antes** de devolverlo. Si el disco falla, la aplicación no debe
    // recibir un secreto que en el próximo arranque no va a existir: cifraría sus
    // datos con una clave que se pierde.
    let items: Vec<ItemInfo> = {
        let state = state.lock().await;
        state.items.values().cloned().collect()
    };
    if let Err(e) = save_db(&items) {
        // Y si falló, el secreto se deshace. Dejándolo en memoria, el próximo
        // pedido lo encontraría y lo devolvería sin volver a intentar escribir:
        // un error transitorio de disco alcanzaría para que la aplicación cifre
        // con una clave que desaparece al reiniciar.
        let mut state = state.lock().await;
        state.items.remove(&path);
        if let Some(col) = state.collections.get_mut(collection) {
            col.items.retain(|p| p != &path);
        }
        return Err(e);
    }

    Ok(secret)
}

/// Busca un secreto ya guardado por sus atributos, exactos.
async fn find_secret(
    state: &Arc<Mutex<KeyringState>>,
    attributes: &HashMap<String, String>,
) -> Option<Vec<u8>> {
    let state = state.lock().await;
    state
        .items
        .values()
        .find(|item| &item.attributes == attributes)
        .map(|item| item.secret.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_bus::{self, pid_inexistente, BusFalso};
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    /// Un directorio propio para cada prueba, que se borra al terminar.
    ///
    /// No hay `tempfile` entre las dependencias y no compensa agregar una por
    /// un directorio: el pid más un contador alcanzan, porque las pruebas de un
    /// mismo binario corren como hilos de un mismo proceso.
    struct DirDePrueba(PathBuf);

    impl DirDePrueba {
        fn nuevo(nombre: &str) -> Self {
            static SIGUIENTE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = SIGUIENTE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("vasak-keyring-{nombre}-{}-{n}", std::process::id()));
            // Por si una corrida anterior murió sin llegar al `Drop`.
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("no se pudo crear el directorio de la prueba");
            DirDePrueba(dir)
        }

        fn ruta(&self) -> &std::path::Path {
            &self.0
        }
    }

    // El borrado va en `Drop` y no al final de cada prueba para que también
    // corra cuando la prueba falla: el pánico desenrolla, y el `Drop` también.
    impl Drop for DirDePrueba {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn una_base_inexistente_no_es_un_error() {
        // El caso normal de una máquina recién instalada: no hay archivo y eso
        // no es un fallo. Si esto volviera a ser un error, nadie podría
        // desbloquear un llavero nuevo.
        let dir = DirDePrueba::nuevo("sin-base");

        let leido = leer_base(&dir.ruta().join("keyring.db"))
            .await
            .expect("una base que todavía no existe no puede fallar");

        assert!(leido.is_none(), "todavía no hay nada que leer");
    }

    #[tokio::test]
    async fn la_base_se_lee_entera() {
        // Los bytes que salen tienen que ser los que están en el archivo, sin
        // truncar ni alterar: de ahí sale el texto cifrado que después se
        // descifra, y un cambio acá se manifiesta como «la contraseña no abre
        // la base» con una base perfectamente buena.
        let dir = DirDePrueba::nuevo("base");
        let ruta = dir.ruta().join("keyring.db");
        let crudo: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        tokio::fs::write(&ruta, &crudo).await.unwrap();

        let leido = leer_base(&ruta)
            .await
            .expect("una base legible no puede fallar")
            .expect("la base existe");

        assert_eq!(leido, crudo);
    }

    #[tokio::test]
    async fn una_base_ilegible_no_se_toma_por_una_base_vacia() {
        // Un archivo que existe y del que no se puede leer no es una base
        // nueva. Si volviera a tratarse como una vacía, el primer guardado
        // escribiría encima de la base que la persona tenía.
        let dir = DirDePrueba::nuevo("base-ilegible");
        let archivo = dir.ruta().join("keyring.db");
        tokio::fs::write(&archivo, b"no se puede leer esto")
            .await
            .unwrap();
        // Un componente del camino que es un archivo: la lectura falla con
        // ENOTDIR, que no es «no existe». Sirve para probar el caso sea cual
        // sea el uid con el que corran las pruebas —un archivo en 0000 lo leen
        // sin problema como root, y estas pruebas se corren en CI como root.
        let debajo_de_un_archivo = archivo.join("keyring.db");

        let error = leer_base(&debajo_de_un_archivo)
            .await
            .expect_err("leer debajo de un archivo tiene que fallar");

        assert_ne!(
            error.kind(),
            std::io::ErrorKind::NotFound,
            "esto no es una base inexistente: es un error de lectura"
        );
    }

    #[tokio::test]
    async fn una_coleccion_nueva_arranca_vacia_sin_que_falte_la_base() {
        // El primer caso de los tres, del lado del que decide: una máquina sin
        // base tiene que poder registrar su colección. Si esto volviera a ser un
        // error, no se podría ni crear el primer llavero de una instalación
        // nueva.
        let dir = DirDePrueba::nuevo("coleccion-sin-base");

        let carga = items_from_disk(&dir.ruta().join("keyring.db"), None)
            .await
            .expect("una base que todavía no existe no puede impedir la colección");

        assert!(carga.items.is_empty(), "no hay nada que sembrar todavía");
    }

    #[tokio::test]
    async fn una_base_ilegible_no_deja_una_coleccion_abierta_y_vacia() {
        // El tercero, y el que se comía el `Err`. Si esto devolviera una lista
        // vacía en vez de un error, `spawn_collection` registraría la colección
        // como abierta y el primer guardado escribiría encima de la base que la
        // persona tenía: la pérdida no se vería hasta el reinicio siguiente, con
        // la base ya pisada.
        let dir = DirDePrueba::nuevo("carga-ilegible");
        let archivo = dir.ruta().join("keyring.db");
        tokio::fs::write(&archivo, b"no se puede leer esto")
            .await
            .unwrap();
        let debajo_de_un_archivo = archivo.join("keyring.db");

        // Con `expect_err` haría falta `Debug` en `DiskLoad`, y `DiskLoad` lleva
        // las entradas: un pánico imprimiría el secreto de cada una. Un `match`
        // dice lo mismo.
        let error = match items_from_disk(&debajo_de_un_archivo, None).await {
            Err(e) => e,
            Ok(_) => panic!("una base que no se puede leer no puede sembrar una colección"),
        };

        // Y el error tiene que decir que fue la lectura, para que en el diario
        // no se confunda con una contraseña que no abre.
        assert!(
            error
                .to_string()
                .contains("no se pudo leer la base del llavero"),
            "el error tiene que nombrar la lectura: {error}"
        );
    }

    #[tokio::test]
    async fn una_base_que_no_se_puede_descifrar_no_impide_arrancar() {
        // El caso del medio, y deliberadamente **no** un error: la base del disco
        // está escrita con una contraseña y la de esta sesión todavía no llegó.
        // La colección se registra vacía y `aplicar` la carga en cuanto la
        // contraseña llegue por PAM o por el diálogo. Tratar esto como un fallo
        // dejaría el llavero sin colección durante toda la sesión.
        let dir = DirDePrueba::nuevo("carga-sin-descifrar");
        let ruta = dir.ruta().join("keyring.db");
        // Bytes que no son una base: da igual qué contraseña se pruebe, la base no
        // abre. Que la sesión tenga una o no ya no se prueba acá —eso lo decide
        // quien llama— sino que se pasa explícitamente y así los dos casos se
        // pueden provocar por separado.
        tokio::fs::write(&ruta, b"no soy una base cifrada")
            .await
            .unwrap();

        let carga = items_from_disk(&ruta, Some("cualquiera"))
            .await
            .expect("no poder descifrar todavía no es un fallo");

        assert!(
            carga.items.is_empty(),
            "sin abrir la base no hay entradas, pero la colección se registra igual"
        );
    }

    /// La colección del login, que es la que `aplicar` recarga.
    const COLECCION_DEL_LOGIN: &str = "/org/freedesktop/secrets/collection/login";

    /// La carrera que el bloqueo existe para cerrar, reproducida sin reloj ni
    /// suerte: el que guarda y el que desbloquea se arman el candado del estado en
    /// el orden que la hace perder.
    ///
    /// El que guarda es un `CreateItem` que ya pasó `ensure_unlocked` —o sea, ya
    /// no lo va a volver a preguntar— y llegó al candado antes que la carga. Se
    /// queda con él, y entonces fotografía la lista de entradas tal como está:
    /// la de antes de la carga, que en este caso es una vacía. Con la base de la
    /// persona en el disco, guardar esa vacía es la pérdida entera.
    ///
    /// Lo que evita la pérdida no es que el `CreateItem` pregunte otra vez —ya
    /// preguntó y le dijeron que sí— sino que en el momento en que puede mirar la
    /// lista, el bloqueo siga puesto. Por eso el bloqueo se levanta adentro del
    /// candado del estado y no antes: mientras este lo tiene, todavía no se levantó.
    ///
    /// Se comprueba por partes, y en este orden:
    ///
    /// 1. con el candado tomado por el que guarda, el bloqueo sigue puesto;
    /// 2. el `CreateItem` no puede persistir su foto de la lista vieja;
    /// 3. el archivo del disco sigue siendo byte a byte el de la persona;
    /// 4. una vez que la carga termina, el bloqueo se levanta y la lista es la del
    ///    disco, y ahí sí se puede guardar.
    #[tokio::test]
    async fn un_guardado_concurrente_al_desbloqueo_no_puede_pisar_la_base() {
        let _sesion = estado_de_la_sesion().lock().await;
        let dir = DirDePrueba::nuevo("carrera-desbloqueo");
        let ruta = dir.ruta().join("keyring.db");
        base_con_una_entrada(&ruta, "la-buena").await;
        let original = tokio::fs::read(&ruta)
            .await
            .expect("no se pudo leer la base");

        // El arranque que bloquea: hay base, la contraseña de la sesión no la abre.
        let carga = items_from_disk(&ruta, Some("la-mala"))
            .await
            .expect("no poder descifrar todavía no es un fallo");
        assert!(carga.undecrypted);
        seed_items(carga);
        assert!(writes_blocked().is_some(), "arranco bloqueado");

        // Llega la correcta: abre la base, pero la lista en memoria sigue vacía.
        let db = adopt_password(&ruta, "la-buena")
            .await
            .expect("una base legible no puede fallar al leerla")
            .expect("la contraseña correcta abre la base");

        // El estado real de la colección en esa situación: registrada y vacía.
        let estado = Arc::new(Mutex::new(KeyringState::new()));
        {
            let mut state = estado.lock().await;
            state.collections.insert(
                COLECCION_DEL_LOGIN.to_string(),
                CollectionInfo {
                    label: "Default collection".into(),
                    locked: false,
                    items: vec![],
                    created: 0,
                    modified: 0,
                },
            );
        }

        // El que guarda toma el candado del estado antes que la carga.
        let candado = estado.lock().await;

        // La carga arranca de verdad, en otra tarea, y se queda esperando este
        // mismo candado. Importa que sea de verdad y no una llamada después: la
        // ventana que hay que cerrar es la que existe **mientras** la carga corre
        // y todavía no cargó nada, y para mirarla hace falta que esté corriendo.
        let estado_para_cargar = estado.clone();
        let carga = tokio::spawn(async move {
            reload_collection(&estado_para_cargar, COLECCION_DEL_LOGIN, &db).await
        });
        // Un par de vueltas del runtime para que la tarea llegue hasta el candado
        // y se quede esperando ahí, que es lo que hace en producción cuando un
        // `CreateItem` se adelanta a la carga. Sin esto la prueba correría con la
        // carga todavía sin empezar, que es un estado que en producción no existe:
        // el `CreateItem` y el desbloqueo llegan juntos.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !carga.is_finished(),
            "la carga tiene que estar corriendo y esperando el candado, no haber \\
             terminado ya: si terminó, esto no está probando la carrera"
        );

        // 1. Mientras el candado lo tiene el que guarda, la carga no pudo terminar,
        // y entonces el bloqueo tiene que seguir puesto.
        assert!(
            writes_blocked().is_some(),
            "el bloqueo se levantó antes de que la colección quedara cargada: \\
             entre las dos cosas hay una ventana en la que se puede guardar una \\
             lista que no es la del disco"
        );

        // 2. El `CreateItem` fotografía lo que ve —la lista vieja— y trata de
        // guardarlo. La contraseña está en memoria y ya pasó la comprobación, así
        // que lo único que lo frena es el bloqueo.
        let foto: Vec<ItemInfo> = candado.items.values().cloned().collect();
        assert!(
            foto.is_empty(),
            "antes de la carga la lista en memoria es la vieja: eso es lo que \\
             el que guarda photographía"
        );
        write_to(&ruta, &foto)
            .expect_err("una lista de antes de la carga no se puede guardar encima del disco");

        // 3. El archivo es el de la persona, intacto.
        assert_eq!(
            tokio::fs::read(&ruta)
                .await
                .expect("no se pudo leer la base"),
            original,
            "la base del disco tiene que seguir siendo la de la persona, byte a byte"
        );

        // 4. Suelto el candado: la carga entra y termina lo suyo.
        drop(candado);
        carga
            .await
            .expect("la carga no puede caerse: es la que deja el llavero servible");

        assert!(
            writes_blocked().is_none(),
            "cargada la colección, guardar tiene que estar permitido"
        );
        // Lo que una aplicación ve de la colección una vez desbloqueada: la
        // entrada de la persona, y no una colección que dice estar abierta y no
        // tiene nada. Se mira la colección y no el mapa de entradas porque esto es
        // lo que responde `Collection.Items` y lo que decide si un `GetSecret`
        // encuentra algo.
        {
            let state = estado.lock().await;
            let col = state
                .collections
                .get(COLECCION_DEL_LOGIN)
                .expect("la colección del login tiene que existir después de desbloquear");
            assert_eq!(
                col.items.len(),
                1,
                "la colección tiene que quedar con la entrada de la persona, no vacía"
            );
            assert!(
                state.items.contains_key(&col.items[0]),
                "la entrada que la colección anuncia tiene que estar cargada"
            );
        }

        // Y ahora sí se puede guardar, y no se pierde lo que ya estaba.
        let mut guardadas: Vec<ItemInfo> = {
            let state = estado.lock().await;
            state.items.values().cloned().collect()
        };
        guardadas.push(entrada(b"el secreto nuevo"));
        write_to(&ruta, &guardadas).expect("con la colección cargada se guarda");
        let guardado = crypto::decrypt_database(
            &tokio::fs::read(&ruta)
                .await
                .expect("no se pudo leer la base"),
            "la-buena",
        )
        .expect("lo guardado se tiene que poder abrir con la contraseña de la persona");
        assert_eq!(
            guardado.items.len(),
            2,
            "la de la persona no se perdió al guardar"
        );
        assert_eq!(guardado.items[0].secret, b"el secreto de la persona");
    }

    /// El estado del que dependen las pruebas de escritura es del proceso entero:
    /// la contraseña maestra vive en un `OnceLock` y el bloqueo también, y las
    /// pruebas de un mismo binario corren como hilos de un mismo proceso.
    ///
    /// Es lo mismo que hace falta con el contador de `unlock_attempts`, y por el
    /// mismo motivo. El candado es el de tokio y no uno de `std` porque las
    /// pruebas son async: uno de `std` tomado a lo largo de un `.await` bloquea
    /// el hilo del runtime, que es justo lo que se está cuidando acá.
    fn estado_de_la_sesion() -> &'static Mutex<()> {
        static ESTADO: OnceLock<Mutex<()>> = OnceLock::new();
        ESTADO.get_or_init(|| Mutex::new(()))
    }

    /// Escribe una base de verdad, con una entrada, cifrada con `password`.
    ///
    /// Con `crypto::encrypt_database` y no con `write_to`, que es lo que se está
    /// probando: hace falta una base que no haya pasado por el camino que puede
    /// estar bloqueado.
    async fn base_con_una_entrada(ruta: &std::path::Path, password: &str) {
        let db = crypto::KeyringDatabase {
            items: vec![crypto::SecretItem {
                label: "la que estaba".into(),
                attributes: HashMap::from([("app".to_string(), "de-prueba".to_string())]),
                secret: b"el secreto de la persona".to_vec(),
            }],
        };
        let datos = crypto::encrypt_database(&db, password).expect("no se pudo cifrar la base");
        tokio::fs::write(ruta, datos)
            .await
            .expect("no se pudo escribir la base");
    }

    /// Una entrada nueva, como la que dejaría una aplicación al guardar.
    fn entrada(secret: &[u8]) -> ItemInfo {
        ItemInfo {
            label: "la nueva".into(),
            attributes: HashMap::new(),
            secret: secret.to_vec(),
            content_type: "text/plain".into(),
            created: 0,
            modified: 0,
        }
    }

    /// Lo mismo que carga una colección: una entrada de la base, como queda en
    /// memoria.
    fn entrada_de_la_base(si: &crypto::SecretItem) -> ItemInfo {
        ItemInfo {
            label: si.label.clone(),
            attributes: si.attributes.clone(),
            secret: si.secret.clone(),
            content_type: "text/plain".into(),
            created: 0,
            modified: 0,
        }
    }

    /// El arranque que perdía datos: hay una base con la contraseña de la persona,
    /// la sesión arranca con otra, y lo primero que hace la sesión es guardar.
    ///
    /// Antes de esto, ese arranque producía una colección vacía **y abierta**, y
    /// el primer guardado escribía esa vacía encima de la base. La pérdida no se
    /// veía hasta el reinicio siguiente, con el archivo ya pisado y sin forma de
    /// saber qué se perdió.
    #[tokio::test]
    async fn una_contrasena_que_no_abre_la_base_no_puede_escribir_sobre_ella() {
        let _sesion = estado_de_la_sesion().lock().await;
        let dir = DirDePrueba::nuevo("escritura-bloqueada");
        let ruta = dir.ruta().join("keyring.db");
        base_con_una_entrada(&ruta, "la-buena").await;
        let original = tokio::fs::read(&ruta)
            .await
            .expect("no se pudo leer la base");

        // El arranque: hay base y la contraseña de la sesión no la abre.
        let carga = items_from_disk(&ruta, Some("la-mala"))
            .await
            .expect("no poder descifrar todavía no es un fallo");
        assert!(
            carga.items.is_empty(),
            "sin abrir la base no hay entradas en memoria"
        );
        assert!(
            carga.undecrypted,
            "esto es una base que existe y que esta sesión no abrió"
        );

        // Sembrar la colección con eso deja la escritura bloqueada.
        let items = seed_items(carga);
        let motivo = writes_blocked().expect("con la base sin abrir no se puede guardar");
        assert!(
            motivo.contains("descifrar"),
            "el error tiene que decir por qué no se guardó: {motivo}"
        );

        // Y una modificación no llega a la base que la persona tenía.
        let error =
            write_to(&ruta, &items).expect_err("no se puede escribir sobre una base sin abrir");
        assert!(
            error.contains("no se escribió nada"),
            "el error tiene que decir que no se escribió: {error}"
        );
        // El alta se rechaza antes de tocar nada en memoria: una entrada a medio
        // crear sería encontrada después por el mismo cliente.
        ensure_unlocked().expect_err("un alta tiene que rechazarse antes de tocar nada");
        assert_eq!(
            tokio::fs::read(&ruta)
                .await
                .expect("no se pudo leer la base"),
            original,
            "la base del disco tiene que seguir siendo la de la persona, byte a byte"
        );

        // La contraseña correcta abre la base. Ojo con qué NO hace: abrir la base
        // no levanta el bloqueo por sí solo, porque en este punto lo que hay en
        // memoria sigue siendo la lista vacía de recién arriba. Si lo levantara,
        // un `CreateItem` que entrara entre acá y la carga guardaría esa vacía
        // encima del archivo. Eso es lo que comprueba la prueba de la carrera.
        let db = adopt_password(&ruta, "la-buena")
            .await
            .expect("una base legible no puede fallar al leerla")
            .expect("la contraseña de la persona abre su base");
        assert_eq!(
            db.items.len(),
            1,
            "la base de la persona tiene su entrada y hay que verla"
        );
        assert!(
            writes_blocked().is_some(),
            "abrir la base no alcanza para poder guardar: la lista en memoria \\
             todavía no es su contenido"
        );

        // Ahora sí, y en el orden que corresponde: primero se carga la colección
        // —que es lo que levanta el bloqueo— y después se puede guardar.
        let estado = Arc::new(Mutex::new(KeyringState::new()));
        reload_collection(&estado, COLECCION_DEL_LOGIN, &db).await;

        assert!(
            writes_blocked().is_none(),
            "con la colección cargada se vuelve a poder guardar"
        );
        // Y lo que se guarda es lo que quedó cargado, no la vacía de antes.
        let mut guardadas: Vec<ItemInfo> = {
            let state = estado.lock().await;
            state.items.values().cloned().collect()
        };
        assert_eq!(
            guardadas.len(),
            1,
            "la carga tiene que haber repuesto la entrada de la persona"
        );
        guardadas.push(entrada(b"el secreto nuevo"));
        write_to(&ruta, &guardadas).expect("con la base abierta se guarda");
        let guardado = crypto::decrypt_database(
            &tokio::fs::read(&ruta)
                .await
                .expect("no se pudo leer la base"),
            "la-buena",
        )
        .expect("lo guardado se tiene que poder abrir con la contraseña de la persona");
        assert_eq!(
            guardado.items.len(),
            2,
            "la de la persona sigue ahí y la nueva también"
        );
        assert_eq!(guardado.items[1].secret, b"el secreto nuevo");
    }

    /// El arranque que **no** es un fallo: todavía no hay contraseña maestra, y
    /// la que corresponde llega al iniciar sesión.
    ///
    /// Es el caso que no se puede tapar con el anterior. Si se bloqueara la
    /// escritura acá, el llavero de nadie se podría volver a abrir: la contraseña
    /// llega después, y mientras no llegue no hay ni base descifrada ni motivo
    /// para negarle nada a nadie.
    #[tokio::test]
    async fn un_arranque_sin_contrasena_deja_la_coleccion_vacia_y_no_cierra_el_llavero() {
        let _sesion = estado_de_la_sesion().lock().await;
        let dir = DirDePrueba::nuevo("arranque-en-frio");
        let ruta = dir.ruta().join("keyring.db");
        base_con_una_entrada(&ruta, "la-buena").await;

        // Sin contraseña: la colección se registra igual, vacía.
        let carga = items_from_disk(&ruta, None)
            .await
            .expect("esperar la contraseña no es un fallo");
        assert!(carga.items.is_empty(), "todavía no hay nada sembrado");
        assert!(
            !carga.undecrypted,
            "no se intentó abrir la base: no hay nada que lamentar ni que bloquear"
        );

        let _items = seed_items(carga);
        assert!(
            writes_blocked().is_none(),
            "un arranque sin contraseña no puede bloquear el llavero de la persona"
        );

        // Y cuando la contraseña llega, abre la base y el llavero se vuelve a
        // poder usar. Es el camino que `aplicar` toma al iniciar sesión: la
        // contraseña abre la base y la carga la deja servible.
        let db = adopt_password(&ruta, "la-buena")
            .await
            .expect("una base legible no puede fallar al leerla")
            .expect("la contraseña del inicio de sesión abre la base");
        assert_eq!(
            db.items.len(),
            1,
            "la entrada de la persona se cargó al desbloquear"
        );

        let estado = Arc::new(Mutex::new(KeyringState::new()));
        reload_collection(&estado, COLECCION_DEL_LOGIN, &db).await;
        assert!(
            writes_blocked().is_none(),
            "desbloquear tiene que dejar el llavero escribible, o no habría \\
             desbloqueo que sirviera de nada"
        );

        // Guardar vuelve a estar permitido, y lo que ya estaba no se pierde.
        let mut guardadas: Vec<ItemInfo> = {
            let state = estado.lock().await;
            state.items.values().cloned().collect()
        };
        guardadas.push(entrada(b"el secreto nuevo"));
        write_to(&ruta, &guardadas).expect("después de desbloquear se vuelve a guardar");
        let guardado = crypto::decrypt_database(
            &tokio::fs::read(&ruta)
                .await
                .expect("no se pudo leer la base"),
            "la-buena",
        )
        .expect("lo guardado se tiene que poder abrir con la contraseña de la persona");
        assert_eq!(
            guardado.items.len(),
            2,
            "la de la persona no se perdió al guardar"
        );
        assert_eq!(guardado.items[0].secret, b"el secreto de la persona");
        assert_eq!(guardado.items[1].secret, b"el secreto nuevo");
    }

    // ── Control de acceso por ítem (#24) ────────────────────────

    /// Un ítem del almacén de cuentas, con el atributo que lo marca como protegido.
    fn entrada_protegida(secret: &[u8]) -> ItemInfo {
        ItemInfo {
            attributes: HashMap::from([(
                ATRIBUTO_ESQUEMA.to_string(),
                ESQUEMA_PROTEGIDO.to_string(),
            )]),
            ..entrada(secret)
        }
    }

    /// El bug: `vasak-keyring` es un Secret Service estándar, así que cualquier
    /// proceso de la sesión —un navegador, un script, un `.desktop` mal puesto—
    /// podía pedir la clave del almacén cifrado y abrir la base. El cifrado
    /// protege en reposo, no contra código que corre como la misma persona.
    ///
    /// Lo que decide esto no es el nombre de la conexión sino el ejecutable del
    /// proceso que pregunta: el nombre de la conexión se lo elige el llamador,
    /// y por lo tanto no prueba nada.
    #[test]
    fn un_item_protegido_no_se_le_entrega_a_un_proceso_no_autorizado() {
        let item = entrada_protegida(b"la clave del almacen");

        assert!(
            !access_allowed(&item, false),
            "un proceso que no es el sincronizador no puede leer el item protegido: \
             el llavero lo entregaba a cualquiera"
        );
    }

    /// El caso que no puede romperse para tapar el anterior: el control es por
    /// ítem, no una negación general. Si esto fallara, el navegador, el cliente
    /// de correo y el resto de las aplicaciones que hoy andan bien se quedarían
    /// sin llavero, y el arreglo de un agujero sería romper el escritorio.
    #[test]
    fn un_item_sin_proteger_se_sigue_entregando_a_cualquier_proceso() {
        let item = entrada("la contraseña del navegador".as_bytes());

        assert!(
            access_allowed(&item, false),
            "el control es sobre el item protegido, no sobre el llavero entero"
        );
    }

    /// El otro lado del mismo control: el sincronizador de cuentas tiene que poder
    /// leer lo suyo. Si esto fallara, el arreglo del #24 sería apagarle el
    /// almacén a la única aplicación que lo debe usar.
    #[test]
    fn el_proceso_autorizado_si_puede_leer_el_item_protegido() {
        let item = entrada_protegida(b"la clave del almacen");

        assert!(
            access_allowed(&item, true),
            "el sincronizador de cuentas es el que puede leer el almacen"
        );
    }

    /// Un atributo con otro valor no es el esquema protegido, aunque se parezca.
    ///
    /// El filtro es una igualdad exacta contra `ESQUEMA_PROTEGIDO`: si fuera un
    /// `contains` o un prefijo, cualquier aplicación que se Vie con
    /// `ar.net.vasak.os.AccountsStoreBackup` quedaría protegida por accidente —o,
    /// al revés, se le negaría su propia clave sin que nadie entienda por qué.
    #[test]
    fn un_esquema_que_solo_se_parece_al_protegido_no_lo_es() {
        let parecidos = [
            "ar.net.vasak.os.AccountsStore2",
            "ar.net.vasak.os.accountsstore",
            "ar.net.vasak.os.AccountsStore ",
            "com.otro.Programa",
        ];
        for esquema in parecidos {
            let item = ItemInfo {
                attributes: HashMap::from([(ATRIBUTO_ESQUEMA.to_string(), esquema.to_string())]),
                ..entrada(b"secreto")
            };
            assert!(
                access_allowed(&item, false),
                "`{esquema}` no es el esquema protegido y no puede quedar bloqueado"
            );
        }
    }

    /// Un ítem sin `xdg:schema` tampoco es un problema, y esto importa porque es
    /// lo que tiene la mayoría: el `CreateItem` de cualquier aplicación trae lo
    /// que la aplicación quiera, y la mayoría no trae nada.
    #[test]
    fn un_item_sin_el_atributo_de_esquema_no_queda_bloqueado() {
        let item = ItemInfo {
            attributes: HashMap::from([("otra-cosa".to_string(), "lo-que-sea".to_string())]),
            ..entrada(b"secreto")
        };

        assert!(
            access_allowed(&item, false),
            "sin el atributo no hay nada que proteger"
        );
    }

    /// El nombre del error es parte del contrato, no un detalle interno.
    ///
    /// Un cliente que recibe `org.freedesktop.DBus.Error.AccessDenied` —el
    /// nombre que dice la especificación— puede decir «este programa no tiene
    /// permiso» y seguir andando. Si volviera a salir `org.freedesktop.Secret.Error.Failed`,
    /// el cliente vería un fallo genérico y una clave protegida se confundiría
    /// con un llavero roto.
    #[test]
    fn el_negativo_usa_el_nombre_de_error_del_estandar() {
        let nombre = <SecretError as zbus::DBusError>::name(&SecretError::AccessDenied);

        assert_eq!(
            nombre.as_str(),
            "org.freedesktop.DBus.Error.AccessDenied",
            "el cliente tiene que poder distinguir un permiso denegado de un llavero roto"
        );
    }

    /// Y ese mismo error se distingue de `IsLocked`, que significa otra cosa y
    /// trae una acción distinta: desbloquear y reintentar.
    ///
    /// Si los dos salieran con el mismo nombre, un cliente que no puede leer la
    /// clave por permiso le preguntaría a la persona su contraseña de nuevo, para
    /// siempre, sin que eso sirva de nada.
    #[test]
    fn el_permiso_denegado_no_se_confunde_con_el_llavero_bloqueado() {
        let denegado = <SecretError as zbus::DBusError>::name(&SecretError::AccessDenied);
        let error_bloqueado = SecretError::IsLocked("bloqueada".into());
        let bloqueado = <SecretError as zbus::DBusError>::name(&error_bloqueado);

        assert_ne!(
            denegado.as_str(),
            bloqueado.as_str(),
            "el bloqueo se resuelve desbloquear; el permiso, no"
        );
    }

    /// El mismo bug, pero por el camino que de verdad lo exercise un atacante:
    /// una llamada `GetSecret` de verdad, por el bus, contra el demonio de verdad.
    ///
    /// La prueba de `access_allowed` comprobaría una función; ésta comprueba el
    /// método. La diferencia importa porque lo que estaba roto no era la regla,
    /// era que `GetSecret` no la llamaba —y una función correcta que nadie invoca
    /// deja el agujero abierto con la suite en verde—.
    ///
    /// El cliente es el proceso de la prueba, y su ejecutable no es
    /// `/usr/bin/vasak-accounts-sync`, así que es exactamente el caso que tiene
    /// que ser negativo.
    #[tokio::test]
    async fn leer_un_secreto_protegido_por_dbus_no_se_le_concede() {
        // El mutex va primero: la contraseña maestra y el estado de la sesion son
        // del proceso entero, y una prueba que corra en paralelo las pisa.
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let (demonio, cliente) = llavero_con_item_protegido().await;
        let _demonio = demonio;
        let sesion = OwnedObjectPath::try_from(SESION).unwrap();

        let error = llamar(&cliente, ITEM, IFACE_ITEM, "GetSecret", &(&sesion,))
            .await
            .expect_err(
                "un item protegido no se le entrega a un proceso que no es el sincronizador",
            );

        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.DBus.Error.AccessDenied",
            "y se dice con el nombre del estándar, no con un fallo genérico"
        );
    }

    /// Lo que el control **no** puede hacer, comprobado por el mismo camino.
    ///
    /// El ítem de al lado no está protegido y se tiene que leer igual. Si el
    /// filtro fuera «todo ítem del login» o «toda consulta de este cliente»,
    /// esta prueba lo diría —y el síntoma del otro lado sería que ningún programa
    /// del escritorio pudiera volver a guardar una contraseña—.
    #[tokio::test]
    async fn el_control_no_toca_los_items_sin_proteger() {
        // El mutex va primero: la contraseña maestra y el estado de la sesion son
        // del proceso entero, y una prueba que corra en paralelo las pisa.
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let (demonio, cliente) = llavero_con_item_protegido().await;
        let _demonio = demonio;
        let sesion = OwnedObjectPath::try_from(SESION).unwrap();

        llamar(&cliente, ITEM_COMUN, IFACE_ITEM, "GetSecret", &(&sesion,))
            .await
            .expect("un item sin proteger se sigue leyendo: el control es por item");
    }

    /// `GetSecrets` con una lista mezclada devuelve la parte que sí se puede leer
    /// y omite la protegida, en vez de un mapa vacío o de cortar la llamada.
    ///
    /// El motivo de que sea el mapa parcial y no un error es que es el contrato
    /// que ya tiene: las colecciones bloqueadas hacen exactamente esto desde
    /// siempre, y `GetSecrets` es lo que usan las aplicaciones que guardan varios
    /// secretos juntos. Si pasara a error, un solo ítem protegido en la lista
    /// rompería a todos los clientes de una vez.
    #[tokio::test]
    async fn get_secrets_omite_el_protegido_y_sigue_devolviendo_el_resto() {
        // El mutex va primero: la contraseña maestra y el estado de la sesion son
        // del proceso entero, y una prueba que corra en paralelo las pisa.
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let (demonio, cliente) = llavero_con_item_protegido().await;
        let _demonio = demonio;
        let sesion = OwnedObjectPath::try_from(SESION).unwrap();
        let pedidos = vec![
            OwnedObjectPath::try_from(ITEM).unwrap(),
            OwnedObjectPath::try_from(ITEM_COMUN).unwrap(),
        ];

        let respuesta = llamar(
            &cliente,
            SERVICIO,
            IFACE_SERVICIO,
            "GetSecrets",
            &(&pedidos, &sesion),
        )
        .await
        .expect("una lista con un item protegido se responde con la parte legible");
        let mapa: HashMap<OwnedObjectPath, SecretStruct> =
            respuesta.body().deserialize().expect("respuesta");

        assert!(
            !mapa.contains_key(&OwnedObjectPath::try_from(ITEM).unwrap()),
            "el item protegido no puede aparecer en el mapa"
        );
        assert!(
            mapa.contains_key(&OwnedObjectPath::try_from(ITEM_COMUN).unwrap()),
            "el item sin proteger sí tiene que estar: `GetSecrets` devuelve la parte que puede"
        );
    }

    /// El ejecutable se compara por la ruta entera, no por el nombre ni por un
    /// prefijo.
    ///
    /// Con un `starts_with`, `/usr/bin/vasak-accounts-sync.malicioso` pasaba por
    /// el sincronizador. Con un `ends_with` o una comparación contra el nombre
    /// pelado, alcanzaba con un binario con el mismo nombre en otro directorio.
    /// Esta prueba llama a la comparación real —no a las constantes— justamente
    /// porque una versión anterior suya comparaba `EJECUTABLE_AUTORIZADO` contra
    /// sí mismo y daba verde aunque el código usara `starts_with`.
    #[test]
    fn un_ejecutable_que_solo_se_parece_al_autorizado_no_lo_es() {
        let parecidos = [
            "/usr/bin/vasak-accounts-sync.malicioso",
            "/usr/bin/vasak-accounts-sync2",
            "/usr/bin/vasak-accounts-syn",
            "/tmp/vasak-accounts-sync",
            "/usr/local/bin/vasak-accounts-sync",
            "vasak-accounts-sync",
            "",
        ];

        for ejecutable in parecidos {
            assert!(
                !es_el_autorizado(ejecutable, EJECUTABLE_AUTORIZADO),
                "`{ejecutable}` no es el sincronizador y no puede pasar por él"
            );
        }
    }

    /// Y el otro lado, que es el que hace que el sistema ande: el binario real
    /// tiene que pasar, o el almacén cifrado se queda sin quien lo abra.
    #[test]
    fn el_ejecutable_del_sincronizador_es_autorizado() {
        assert!(
            es_el_autorizado(EJECUTABLE_AUTORIZADO, EJECUTABLE_AUTORIZADO),
            "el sincronizador de cuentas tiene que poder leer el almacen"
        );
    }

    /// El binario que la puerta exige tiene que ser el que la máquina realmente
    /// tiene.
    ///
    /// Sin esto, cambiar el nombre o el lugar del binario rompe el control en
    /// silencio: el almacen deja de abrirse y no hay ningun error en ningun lado,
    /// porque lo que falla es una negacion —que es exactamente la clase de
    /// fallo que no se ve. El sintoma es «el almacen de cuentas se rompio» y
    /// nada mas. Lo mismo que ya hace `portal_secret` con su ejecutable, y por
    /// el mismo motivo.
    ///
    /// Sin el binario instalado en ninguna parte —el caso del runner del CI, que
    /// no es una maquina de VasakOS— no hay nada que comparar y se dice.
    #[test]
    fn el_sincronizador_instalado_esta_donde_la_puerta_lo_busca() {
        let rutas = rutas_del_sincronizador_instaladas();
        if rutas.is_empty() {
            println!(
                "se salta: en esta máquina no hay vasak-accounts-sync, así que no hay \
                 ejecutable real contra el que comparar"
            );
            return;
        }

        // Que alguna coincida y no que todas: lo que importa es que la puerta
        // deje entrar al sincronizador de verdad, no que rechace a un segundo
        // binario igual que alguien tenga instalado al lado.
        let aceptadas: Vec<&PathBuf> = rutas
            .iter()
            .filter(|ruta| {
                es_el_autorizado(ruta.to_str().unwrap_or_default(), EJECUTABLE_AUTORIZADO)
            })
            .collect();

        assert!(
            !aceptadas.is_empty(),
            "la puerta sólo acepta a {EJECUTABLE_AUTORIZADO} y el sincronizador de esta máquina \
             está en {rutas:?}: hay que cambiar EJECUTABLE_AUTORIZADO, o el almacen de cuentas \
             no se va a poder abrir nunca y no va a haber ningún error que lo diga"
        );
    }

    /// Dónde puede estar un `vasak-accounts-sync` instalado.
    ///
    /// **Se busca en todos los lugares donde un paquete lo pondría, no sólo en el
    /// que dice la constante.** Una versión anterior de la prueba de arriba
    /// miraba `Path::new(EJECUTABLE_AUTORIZADO).is_file()` y se saltaba si no
    /// estaba: con la constante desactualizada no encuentra nada ahí, se salta,
    /// y da verde —que es el mismo salto que casi se lleva por delante la del
    /// portal—. Buscar el binario de verdad y compararlo es lo único que
    /// detecta una mudanza.
    ///
    /// Las rutas vuelven **resueltas**, sin enlaces, porque lo que se compara en
    /// producción es `/proc/<pid>/exe`, que es el ejecutable real.
    fn rutas_del_sincronizador_instaladas() -> BTreeSet<PathBuf> {
        const NOMBRE: &str = "vasak-accounts-sync";

        let mut candidatas = vec![PathBuf::from(EJECUTABLE_AUTORIZADO)];
        if let Some(path) = std::env::var_os("PATH") {
            candidatas.extend(std::env::split_paths(&path).map(|dir| dir.join(NOMBRE)));
        }
        candidatas.extend(
            [
                "/usr/bin",
                "/usr/lib",
                "/usr/libexec",
                "/usr/local/bin",
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

    /// Lo que el kernel le cuelga a un binario que se actualizó con el proceso
    /// corriendo no puede hacer que la puerta le cierre al proceso legítimo.
    ///
    /// Es el fallo que motivó `SUFIJO_DE_BORRADO`: con `pacman -Syu` y la unidad
    /// del sincronizador viva, el inodo viejo sigue ejecutándose y `readlink`
    /// devuelve la ruta con `" (deleted)"` pegado. La comparación exacta daba
    /// `false`, y el proceso que sí tenía derecho se quedaba sin almacen.
    ///
    /// La prueba arma el caso de verdad —copia un binario, lo borra mientras
    /// corre— en vez de escribir la cadena a mano, porque lo que se comprueba es
    /// que el kernel la ponga así. Si algún día `/usr/bin/sleep` no estuviera
    /// donde se espera, se dice y se salta en vez de dar un falso verde.
    #[tokio::test]
    async fn un_binario_borrado_en_caliente_sigue_siendo_reconocido() {
        let dir = DirDePrueba::nuevo("borrado-en-caliente");
        let ruta = dir.ruta().join("sincronizador-de-prueba");
        if std::fs::copy("/usr/bin/sleep", &ruta).is_err() {
            println!("se salta: no hay un binario que copiar en esta máquina");
            return;
        }

        let mut hijo = tokio::process::Command::new(&ruta)
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .expect("no se pudo arrancar el binario de prueba");
        let pid = hijo.id().expect("el proceso no tiene pid");

        // El archivo tiene que estar ahí *mientras corre*, que es el estado en
        // que lo pone un `pacman -Syu`.
        let con_archivo = ejecutable_de(pid).expect("el proceso tiene que estar corriendo");
        assert!(
            con_archivo.ends_with("sincronizador-de-prueba"),
            "la ruta tiene que ser la del archivo que se arrancó, no {con_archivo}"
        );

        std::fs::remove_file(&ruta).expect("no se pudo borrar el binario en caliente");

        // Y ahora la puerta tiene que dejarlo entrar igual. El nombre de la
        // ruta es el del archivo más el adorno del kernel.
        let sin_archivo = ejecutable_de(pid).expect("el proceso sigue corriendo");
        assert_eq!(
            sin_archivo, con_archivo,
            "con el archivo borrado en caliente la ruta tiene que seguir siendo la misma, \
             no {:?} — si cambia, `ejecutable_de` tiene que estar sacando otra cosa y esta \
             prueba no está probando lo que dice",
            sin_archivo
        );
        let _ = hijo.kill().await;
    }

    /// Y la comparación de la puerta, sobre esa misma ruta, tiene que dar lo
    /// mismo antes y después del adorno.
    ///
    /// El reparto importa: el adorno se saca en `ejecutable_de`, no en
    /// `es_el_autorizado`. Por eso esta prueba compone las dos como lo hace el
    /// camino real —limpiar y después comparar— en vez de pasarle la ruta con
    /// el adorno a la puerta: si el adorno se sacara en el lugar equivocado, esta
    /// forma de probarlo no se enteraría.
    #[test]
    fn el_adorno_de_borrado_no_altera_la_comparacion_de_la_puerta() {
        let con_adorno = format!("{EJECUTABLE_AUTORIZADO}{SUFIJO_DE_BORRADO}");

        assert!(
            es_el_autorizado(sin_adorno_de_borrado(&con_adorno), EJECUTABLE_AUTORIZADO),
            "una actualización del sistema no le puede cerrar el almacen al sincronizador \
             legítimo: `pacman` borra el archivo mientras el proceso sigue corriendo, y el \
             kernel cuelga el adorno a la ruta"
        );
        // Y quitar el adorno no abre la puerta de al lado: la comparación sigue
        // siendo exacta contra la ruta entera, que es lo que impide que un
        // `...-sync.malicioso` pase por el sincronizador.
        assert!(
            !es_el_autorizado(
                sin_adorno_de_borrado(&format!(
                    "{EJECUTABLE_AUTORIZADO}.malicioso{SUFIJO_DE_BORRADO}"
                )),
                EJECUTABLE_AUTORIZADO
            ),
            "quitar el adorno no puede convertir un nombre parecido en el sincronizador"
        );
    }

    /// Y una ruta que no tiene el adorno sale igual, porque si no, el `unwrap_or`
    /// del medio estaría devolviendo algo distinto de lo que entró.
    #[test]
    fn una_ruta_sin_el_adorno_sale_igual_que_entra() {
        for ruta in ["/usr/bin/vasak-accounts-sync", "/usr/bin/otro", ""] {
            assert_eq!(sin_adorno_de_borrado(ruta), ruta, "no había nada que sacar");
        }
    }

    /// Una ruta que es **sólo** el adorno se queda vacía, y eso es lo correcto:
    /// el kernel no devuelve nunca una cosa así, y un `unwrap_or(ruta)` que
    /// devolviera la ruta entera haría que `es_el_autorizado` comparara contra
    /// `" (deleted)"` —que no es el sincronizador, así que no abriría nada—.
    /// Se anota para que el cambio de `unwrap_or` a otra cosa se piense.
    #[test]
    fn una_ruta_que_es_solo_el_adorno_queda_vacia() {
        assert_eq!(sin_adorno_de_borrado(SUFIJO_DE_BORRADO), "");
    }

    /// El esquema protegido y el atributo que lo marca tienen que ser los mismos
    /// que usa `vasak-accounts`, y no una copia aproximada.
    ///
    /// El llavero no importa `SCHEMA` de ningún lado: son dos números parejos que
    /// hay que mantener iguales a mano. Si el sincronizador guardara con un
    /// esquema distinto, esta comparación seguiría dando verde acá y la clave
    /// seguiría saliendo para cualquiera. Lo que se puede comprobar sin la otra
    /// mitad del sistema es que el valor sea el declarado.
    #[test]
    fn el_esquema_protegido_es_el_del_almacen_de_cuentas() {
        assert_eq!(
            ESQUEMA_PROTEGIDO, "ar.net.vasak.os.AccountsStore",
            "este valor tiene que coincidir con store::key::SCHEMA de vasak-accounts"
        );
        assert_eq!(
            ATRIBUTO_ESQUEMA, "xdg:schema",
            "este es el atributo por el que se marca el esquema"
        );
    }

    #[test]
    fn the_database_hangs_off_the_data_directory() {
        assert_eq!(
            keyring_path_under(Some(PathBuf::from("/home/pato/.local/share"))),
            Some(PathBuf::from(
                "/home/pato/.local/share/vasak-keyring/keyring.db"
            ))
        );
    }

    #[test]
    fn a_relative_base_is_refused_rather_than_guessed() {
        // This is the bug this replaced. A relative or empty base made the
        // database land next to wherever the daemon happened to be started, and
        // `spawn_unlock_prompt` then reported no keyring at all — so a user with
        // stored credentials looked like a fresh install.
        //
        // Empty, bare name, `./` and `../`: the bare name is the one that slips
        // through when only the empty case is remembered.
        for relative in ["", "share", "./share", "../share"] {
            assert_eq!(
                keyring_path_under(Some(PathBuf::from(relative))),
                None,
                "a base of {relative:?} must not produce a path"
            );
        }
    }

    #[test]
    fn no_base_means_no_path() {
        assert_eq!(keyring_path_under(None), None);
    }

    // ── La puerta del almacén, con el bus detrás ──────────────────
    //
    // Tenía el mismo problema que la del portal y por lo mismo: con la unidad en
    // un namespace de usuario propio, `/proc/<pid>/exe` del sincronizador daba
    // `EACCES`, el `.ok()` se lo tragaba, y la puerta —que era sólo el
    // ejecutable— le negaba el almacén al propio sincronizador. No a un atacante:
    // al cliente legítimo, siempre. Y el servicio viene `disabled`, así que no se
    // notó. El arreglo de fondo está en la unidad; acá la puerta pasa a pedir
    // también el nombre, y ninguna de las dos condiciones alcanza sola.
    //
    // Va en dos capas porque fallan distinto. La de las pruebas puras llama a
    // `es_el_sincronizador` con las respuestas ya resueltas: comprueba la regla.
    // La de abajo monta un bus falso detrás del cliente y deja que corra el
    // código de verdad: comprueba que la regla se llegue a formular. Un `if` que
    // devuelve `false` siempre compila, pasa todas las pruebas de la función que
    // llama, y deja al sistema exactamente igual de roto que antes.

    /// La conexión del sincronizador en el bus de la sesión.
    const DEL_SINCRONIZADOR: &str = ":1.42";
    /// Una conexión que no es la del sincronizador.
    const DE_UN_IMPOSTOR: &str = ":1.99";

    /// El ejecutable de este mismo proceso de pruebas, que es el único que una
    /// prueba puede hacer pasar por el sincronizador: `/usr/bin/vasak-accounts-sync`
    /// no está en la máquina que corre la prueba.
    fn ejecutable_propio() -> String {
        ejecutable_de(std::process::id()).expect("esta prueba puede leerse a sí misma")
    }

    /// Lo que el demonio contestó, en el tipo que el resto de las pruebas espera.
    ///
    /// Un error de método vuelve como un mensaje, y no como un `Err` de la
    /// llamada: como la respuesta se lee de un `MessageStream` —porque el emisor
    /// va escrito a mano y `call_method` no lo pone— no hay nadie a quien
    /// `call_method` le devuelva el error. El nombre del error se arma como
    /// `MethodError` porque es lo que produce `call_method` de verdad, y así
    /// [`nombre_del_error`] sirve para las dos formas de hacer la llamada.
    fn como_resultado(mensaje: zbus::Message) -> zbus::Result<zbus::Message> {
        match mensaje.header().message_type() {
            zbus::message::Type::MethodReturn => Ok(mensaje),
            zbus::message::Type::Error => {
                // El nombre del error está en la cabecera; el cuerpo es un solo
                // string con la descripción.
                let nombre = mensaje
                    .header()
                    .error_name()
                    .expect("un error de D-Bus tiene nombre")
                    .to_string();
                let texto: String = mensaje
                    .body()
                    .deserialize()
                    .expect("el cuerpo de un error es un string");
                Err(zbus::Error::MethodError(
                    zbus::names::ErrorName::try_from(nombre)
                        .expect("el nombre del error del bus")
                        .into(),
                    Some(texto),
                    mensaje,
                ))
            }
            otro => panic!("un `GetSecret` no puede contestar con {otro:?}"),
        }
    }

    /// Un `GetSecret` con el emisor que se le ponga en la cabecera. Ver
    /// [`test_bus::armar`] para por qué el emisor va a mano.
    fn peticion(emisor: Option<&str>) -> zbus::Message {
        peticion_de(ITEM, emisor)
    }

    /// Lo mismo, para el ítem que se quiera.
    fn peticion_de(item: &str, emisor: Option<&str>) -> zbus::Message {
        let sesion = OwnedObjectPath::try_from(SESION).expect("la sesión de la prueba");
        test_bus::armar(item, IFACE_ITEM, "GetSecret", emisor, &(&sesion,))
    }

    /// El llavero de la prueba con un bus falso detrás.
    ///
    /// `duenia` y `pid` son las dos respuestas del bus, y `None` en cualquiera de
    /// las dos es una respuesta de verdad y no una ausencia: `duenia: None` es el
    /// `NameHasNoOwner` que contesta un bus cuando nadie tomó el nombre, y
    /// `pid: None` es el error que contesta cuando no conoce la conexión.
    struct Almacen {
        demonio: zbus::Connection,
        cliente: zbus::Connection,
        preguntados: Arc<Mutex<Vec<String>>>,
        /// El ejecutable que el demonio de la prueba espera del sincronizador.
        esperado: String,
    }

    impl Almacen {
        /// Con el ejecutable de producción como el esperado: nada de lo que
        /// corre en la prueba lo tiene, así que por acá no entra nadie.
        async fn nuevo(duenia: Option<&str>, pid: Option<u32>) -> Self {
            Self::con(duenia, pid, EJECUTABLE_AUTORIZADO).await
        }

        /// Con este mismo proceso haciendo de sincronizador: el pid es el
        /// propio y su ejecutable es el esperado. Es la única forma de recorrer
        /// el camino que acepta.
        async fn con_el_sincronizador_propio(duenia: Option<&str>) -> Self {
            Self::con(duenia, Some(std::process::id()), &ejecutable_propio()).await
        }

        async fn con(duenia: Option<&str>, pid: Option<u32>, esperado: &str) -> Self {
            let (demonio, cliente, preguntados) =
                llavero_con_item_protegido_y_bus(Some(BusFalso::nuevo(duenia, pid)), esperado)
                    .await;
            Almacen {
                demonio,
                cliente,
                preguntados,
                esperado: esperado.to_owned(),
            }
        }

        /// Lo que contesta la puerta del almacén para un pedido de `emisor`.
        ///
        /// Se la llama directo y no por `GetSecret` porque mirar la puerta por sí
        /// sola esconde los rechazos que vienen de otro lado: una sesión cerrada,
        /// una colección bloqueada, un ítem que no existe.
        async fn puerta(&self, emisor: Option<&str>) -> bool {
            let peticion = peticion(emisor);
            autorizado_para_esquema_protegido(&self.demonio, &peticion.header(), &self.esperado)
                .await
        }

        /// Un `GetSecret` de punta a punta: entra por el bus, lo decide el
        /// demonio, y lo que se mira es el mensaje que volvió.
        async fn pedir_secreto(&self, emisor: Option<&str>) -> zbus::Result<zbus::Message> {
            self.pedir_secreto_de(ITEM, emisor).await
        }

        /// Lo mismo, para el ítem que se quiera.
        async fn pedir_secreto_de(
            &self,
            item: &str,
            emisor: Option<&str>,
        ) -> zbus::Result<zbus::Message> {
            let peticion = peticion_de(item, emisor);
            let serial = peticion.header().primary().serial_num();

            let mut salientes = zbus::MessageStream::from(&self.cliente);
            self.cliente
                .send(&peticion)
                .await
                .expect("no se pudo mandar el GetSecret");
            como_resultado(test_bus::primera_respuesta(&mut salientes, serial).await)
        }

        /// Cualquier método, con el emisor que se le ponga en la cabecera.
        async fn llamar_como<B>(
            &self,
            emisor: &str,
            ruta: &str,
            iface: &str,
            metodo: &str,
            cuerpo: &B,
        ) -> zbus::Result<zbus::Message>
        where
            B: serde::Serialize + zbus::zvariant::DynamicType,
        {
            let peticion = test_bus::armar(ruta, iface, metodo, Some(emisor), cuerpo);
            let serial = peticion.header().primary().serial_num();
            let mut salientes = zbus::MessageStream::from(&self.cliente);
            self.cliente
                .send(&peticion)
                .await
                .unwrap_or_else(|e| panic!("no se pudo mandar {metodo}: {e}"));
            como_resultado(test_bus::primera_respuesta(&mut salientes, serial).await)
        }

        /// Por qué nombres se le preguntó al bus, en orden.
        async fn preguntados(&self) -> Vec<String> {
            self.preguntados.lock().await.clone()
        }
    }

    // ── La regla, sin bus ──

    /// Con el nombre y el binario real, entra: si no, el almacén cifrado se
    /// queda sin quien lo abra.
    #[test]
    fn el_sincronizador_con_su_nombre_y_su_binario_entra() {
        assert!(
            es_el_sincronizador(
                DEL_SINCRONIZADOR,
                Some(DEL_SINCRONIZADOR),
                Some(EJECUTABLE_AUTORIZADO),
                EJECUTABLE_AUTORIZADO
            ),
            "la conexión del sincronizador, con el nombre y con el binario, tiene que poder leer \
             el almacén: una puerta que rechaza esto no abre nada"
        );
    }

    /// El nombre solo no alcanza: sin ejecutable legible no entra nadie, tampoco
    /// quien tiene el nombre.
    ///
    /// Es la decisión que separa esta puerta de la que tuvo este PR en su primera
    /// versión, donde un `None` acá dejaba pasar. El servicio viene `disabled`,
    /// así que `ar.net.vasak.os.AccountsSync` casi siempre está libre y lo toma
    /// cualquiera que llegue primero; el ejecutable no se finge.
    #[test]
    fn sin_ejecutable_no_entra_ni_quien_tiene_el_nombre() {
        assert!(!es_el_sincronizador(
            DEL_SINCRONIZADOR,
            Some(DEL_SINCRONIZADOR),
            None,
            EJECUTABLE_AUTORIZADO
        ));
    }

    /// Tener el nombre y ejecutar otra cosa no alcanza: es exactamente el caso
    /// de quien tomó el nombre antes que el sincronizador.
    #[test]
    fn el_nombre_con_otro_ejecutable_no_entra() {
        for otro in [
            "/usr/bin/python3",
            "/tmp/vasak-accounts-sync",
            "/usr/bin/vasak-accounts-sync.malicioso",
        ] {
            assert!(
                !es_el_sincronizador(
                    DEL_SINCRONIZADOR,
                    Some(DEL_SINCRONIZADOR),
                    Some(otro),
                    EJECUTABLE_AUTORIZADO
                ),
                "con el nombre del sincronizador y el ejecutable {otro} no se entra"
            );
        }
    }

    /// Y el binario bueno sin el nombre tampoco: la conexión que pide tiene que
    /// ser la que tiene tomado el nombre.
    #[test]
    fn el_binario_bueno_sin_el_nombre_no_entra() {
        assert!(!es_el_sincronizador(
            DE_UN_IMPOSTOR,
            Some(DEL_SINCRONIZADOR),
            Some(EJECUTABLE_AUTORIZADO),
            EJECUTABLE_AUTORIZADO
        ));
        assert!(!es_el_sincronizador(
            DE_UN_IMPOSTOR,
            None,
            Some(EJECUTABLE_AUTORIZADO),
            EJECUTABLE_AUTORIZADO
        ));
    }

    // ── La puerta, con el bus falso ──

    /// El caso del bug, con bus: el sincronizador entra.
    ///
    /// Con el nombre tomado por la misma conexión que pide, y su ejecutable
    /// legible y siendo el esperado. Es lo que la puerta no dejaba pasar nunca
    /// mientras la unidad tuvo un namespace de usuario propio.
    #[tokio::test]
    async fn el_sincronizador_entra() {
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        assert!(
            almacen.puerta(Some(DEL_SINCRONIZADOR)).await,
            "el bus dice que {DEL_SINCRONIZADOR} tiene {NOMBRE_DEL_SINCRONIZADOR} y su ejecutable \
             es el esperado: tiene que entrar, o el almacén cifrado no lo abre nadie"
        );
    }

    /// El nombre que decide se le pregunta al bus, y es el del sincronizador.
    ///
    /// Lo que se mira es el nombre que salió por el cable: una errata en la
    /// constante no se ve en el resultado de la llamada, se ve en quién puede
    /// leer, que es peor.
    #[tokio::test]
    async fn el_nombre_que_decide_es_el_del_sincronizador() {
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        assert!(!almacen.puerta(Some(DE_UN_IMPOSTOR)).await);

        let preguntados = almacen.preguntados().await;
        assert!(
            !preguntados.is_empty() && preguntados.iter().all(|n| n == NOMBRE_DEL_SINCRONIZADOR),
            "la puerta tiene que preguntar sólo por {NOMBRE_DEL_SINCRONIZADOR} y preguntó por \
             {preguntados:?}: con otro nombre se le abre a quien lo tenga y se le cierra al \
             sincronizador"
        );
    }

    /// Sin ejecutable legible no entra, aunque tenga el nombre.
    ///
    /// Al revés de la primera versión de este arreglo, que dejaba pasar al dueño
    /// del nombre cuando `/proc/<pid>/exe` no se podía leer.
    #[tokio::test]
    async fn sin_ejecutable_legible_no_entra_ni_el_duenio_del_nombre() {
        let almacen = Almacen::nuevo(Some(DEL_SINCRONIZADOR), Some(pid_inexistente())).await;

        assert!(
            !almacen.puerta(Some(DEL_SINCRONIZADOR)).await,
            "no se puede leer el ejecutable de {DEL_SINCRONIZADOR}: tener \
             {NOMBRE_DEL_SINCRONIZADOR} solo no alcanza"
        );
    }

    /// Un pid que el bus no da tampoco es un sí: sin pid no hay ejecutable, y
    /// sin ejecutable no se entra. Es lo que CodeRabbit marcó en la primera
    /// versión, donde cualquier error de la lectura dejaba decidir al nombre.
    #[tokio::test]
    async fn un_pid_que_el_bus_no_da_no_entra() {
        let almacen = Almacen::nuevo(Some(DEL_SINCRONIZADOR), None).await;

        assert!(
            !almacen.puerta(Some(DEL_SINCRONIZADOR)).await,
            "si el bus no da el pid de la conexión no se sabe qué ejecuta, y eso es un no"
        );
    }

    /// El nombre no tapa al ejecutable: con el nombre, el ejecutable legible y
    /// no siendo el del sincronizador, no entra.
    #[tokio::test]
    async fn el_nombre_bueno_con_otro_ejecutable_no_entra() {
        // El pid es el de la propia prueba, así que el ejecutable se lee y es el
        // binario de pruebas; el esperado es el de producción.
        let almacen = Almacen::nuevo(Some(DEL_SINCRONIZADOR), Some(std::process::id())).await;

        assert!(
            !almacen.puerta(Some(DEL_SINCRONIZADOR)).await,
            "con el nombre del sincronizador pero el ejecutable {} no se entra",
            ejecutable_propio()
        );
    }

    /// Un impostor sin el nombre no entra, aunque su ejecutable sea el esperado.
    #[tokio::test]
    async fn un_impostor_con_el_nombre_de_otro_no_entra() {
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        assert!(
            !almacen.puerta(Some(DE_UN_IMPOSTOR)).await,
            "el bus dice que {DEL_SINCRONIZADOR} tiene el nombre del sincronizador y el pedido \
             viene de {DE_UN_IMPOSTOR}: no le abre el almacén"
        );
    }

    /// Nadie tiene el nombre ⇒ nadie entra: el sincronizador no está andando.
    #[tokio::test]
    async fn sin_duena_del_nombre_no_entra_nadie() {
        let almacen = Almacen::con_el_sincronizador_propio(None).await;

        assert!(!almacen.puerta(Some(DEL_SINCRONIZADOR)).await);
        assert!(!almacen.puerta(Some(DE_UN_IMPOSTOR)).await);
    }

    /// Que el `NameHasNoOwner` del bus sea una respuesta y no un fallo, también
    /// para esta puerta: las dos pasan por [`crate::portal_secret::dueno_de`], y
    /// una prueba que sólo mirara una dejaría a la otra descubrirlo en producción.
    #[tokio::test]
    async fn un_nombre_sin_duena_es_una_respuesta_y_no_un_fallo() {
        let almacen = Almacen::nuevo(None, Some(pid_inexistente())).await;

        let duenia = crate::portal_secret::dueno_de(&almacen.demonio, NOMBRE_DEL_SINCRONIZADOR)
            .await
            .expect("`NameHasNoOwner` es la respuesta del bus, no una pregunta que salió mal");

        assert_eq!(duenia, None);
    }

    /// Una cabecera sin emisor no entra, y ni siquiera se le pregunta al bus.
    #[tokio::test]
    async fn una_cabecera_sin_emisor_no_entra() {
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        assert!(!almacen.puerta(None).await);
        assert!(
            almacen.preguntados().await.is_empty(),
            "sin emisor con qué comparar, preguntarle al bus no dice nada"
        );
    }

    // ── De punta a punta, por `GetSecret` ──

    /// El sincronizador lee su clave del almacén cifrado con un `GetSecret`.
    ///
    /// La cadena entera: cabecera con emisor, ida y vuelta al bus por el nombre,
    /// pid que el bus atribuye, `/proc/<pid>/exe`, `access_allowed`, y la
    /// respuesta con la clave adentro.
    ///
    /// La sesión abierta no es un detalle del andamiaje: `get_secret` comprueba el
    /// bloqueo **antes** del control de acceso, así que sin contraseña maestra el
    /// `GetSecret` cortaría con `IsLocked` sin que la puerta se mirara nunca.
    #[tokio::test]
    async fn el_sincronizador_recibe_el_secreto_del_almacen_por_dbus() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let respuesta = almacen
            .pedir_secreto(Some(DEL_SINCRONIZADOR))
            .await
            .expect("el sincronizador tiene que poder leer su propia clave por `GetSecret`");
        let (secreto,): (SecretStruct,) = respuesta
            .body()
            .deserialize()
            .expect("la respuesta de `GetSecret` no se entiende");

        assert!(
            secreto.value == b"la clave del almacen",
            "lo que llega tiene que ser la clave de verdad"
        );
        assert_eq!(secreto.session.as_str(), SESION);
    }

    /// Y por el mismo camino, quien tiene el nombre pero no el ejecutable no la
    /// saca: es el caso de quien tomó el nombre antes que el sincronizador.
    #[tokio::test]
    async fn el_duenio_del_nombre_sin_el_ejecutable_no_recibe_el_secreto_por_dbus() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let almacen = Almacen::nuevo(Some(DEL_SINCRONIZADOR), Some(std::process::id())).await;

        let error = almacen
            .pedir_secreto(Some(DEL_SINCRONIZADOR))
            .await
            .expect_err("el almacén cifrado no se le entrega a quien sólo tiene el nombre");

        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.DBus.Error.AccessDenied",
            "y se dice con el nombre del estándar, no con un fallo genérico"
        );
    }

    /// Y un impostor sin el nombre tampoco.
    #[tokio::test]
    async fn un_impostor_no_recibe_el_secreto_del_almacen_por_dbus() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let error = almacen
            .pedir_secreto(Some(DE_UN_IMPOSTOR))
            .await
            .expect_err("el almacén cifrado no se le entrega a una conexión sin el nombre");

        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.DBus.Error.AccessDenied"
        );

        // Y la pregunta que viajó por el bus fue por el nombre del sincronizador.
        let preguntados = almacen.preguntados().await;
        assert!(
            !preguntados.is_empty() && preguntados.iter().all(|n| n == NOMBRE_DEL_SINCRONIZADOR),
            "en un `GetSecret` de verdad la puerta tiene que preguntar por \
             {NOMBRE_DEL_SINCRONIZADOR}, y preguntó por {preguntados:?}"
        );
    }

    /// Una contraseña común se entrega sin preguntar nada del sincronizador.
    ///
    /// La puerta es sólo para los ítems del almacén. Correrla en cada lectura le
    /// cobraba a cada contraseña del navegador dos idas y vueltas al bus, una
    /// lectura de `/proc` y una línea de «se rechaza la lectura de un ítem del
    /// almacén» en el diario, para un pedido que igual se entregaba. Lo marcó
    /// CodeRabbit.
    #[tokio::test]
    async fn una_contrasena_comun_no_pasa_por_la_puerta_del_almacen() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let almacen = Almacen::nuevo(Some(DEL_SINCRONIZADOR), Some(pid_inexistente())).await;

        let respuesta = almacen
            .pedir_secreto_de(ITEM_COMUN, Some(DE_UN_IMPOSTOR))
            .await
            .expect("una contraseña común se le entrega a cualquier proceso de la sesión");
        let (secreto,): (SecretStruct,) = respuesta
            .body()
            .deserialize()
            .expect("la respuesta de `GetSecret` no se entiende");
        assert!(secreto.value == b"la contrasena del navegador");

        assert!(
            almacen.preguntados().await.is_empty(),
            "para un ítem que no es del almacén no hay que preguntarle al bus quién tiene \
             {NOMBRE_DEL_SINCRONIZADOR}"
        );
    }

    /// Lo mismo por `GetSecrets`: una lista de contraseñas comunes no pregunta
    /// por el sincronizador, y una que incluye la clave del almacén sí.
    #[tokio::test]
    async fn get_secrets_consulta_la_puerta_solo_si_hay_un_item_del_almacen() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let almacen = Almacen::nuevo(Some(DEL_SINCRONIZADOR), Some(pid_inexistente())).await;
        let sesion = OwnedObjectPath::try_from(SESION).expect("la sesión de la prueba");

        let pedir = |items: Vec<&str>| {
            let items: Vec<OwnedObjectPath> = items
                .into_iter()
                .map(|i| OwnedObjectPath::try_from(i).expect("ruta del ítem"))
                .collect();
            test_bus::armar(
                SERVICIO,
                IFACE_SERVICIO,
                "GetSecrets",
                Some(DE_UN_IMPOSTOR),
                &(items, &sesion),
            )
        };

        let mut salientes = zbus::MessageStream::from(&almacen.cliente);
        let comunes = pedir(vec![ITEM_COMUN]);
        let serial = comunes.header().primary().serial_num();
        almacen
            .cliente
            .send(&comunes)
            .await
            .expect("mandar GetSecrets");
        let respuesta = test_bus::primera_respuesta(&mut salientes, serial).await;
        let secretos: HashMap<OwnedObjectPath, SecretStruct> = respuesta
            .body()
            .deserialize()
            .expect("la respuesta de GetSecrets");
        assert_eq!(secretos.len(), 1, "la contraseña común se entrega");
        assert!(
            almacen.preguntados().await.is_empty(),
            "sin ítems del almacén en la lista no hay que preguntar por {NOMBRE_DEL_SINCRONIZADOR}"
        );

        let con_el_almacen = pedir(vec![ITEM_COMUN, ITEM]);
        let serial = con_el_almacen.header().primary().serial_num();
        almacen
            .cliente
            .send(&con_el_almacen)
            .await
            .expect("mandar GetSecrets");
        let respuesta = test_bus::primera_respuesta(&mut salientes, serial).await;
        let secretos: HashMap<OwnedObjectPath, SecretStruct> = respuesta
            .body()
            .deserialize()
            .expect("la respuesta de GetSecrets");
        assert_eq!(
            secretos.len(),
            1,
            "a un impostor se le entrega la común y se le omite la del almacén"
        );
        assert!(
            !almacen.preguntados().await.is_empty(),
            "con un ítem del almacén en la lista la puerta se consulta"
        );
    }

    /// La regla que `Collection.Delete` vuelve a mirar con el candado tomado:
    /// una colección es del almacén si tiene **algún** ítem con su esquema, y
    /// deja de serlo cuando ya no tiene ninguno.
    #[test]
    fn una_coleccion_es_del_almacen_si_guarda_algun_item_suyo() {
        let item = |protegido: bool| ItemInfo {
            label: "x".into(),
            attributes: if protegido {
                HashMap::from([(ATRIBUTO_ESQUEMA.to_string(), ESQUEMA_PROTEGIDO.to_string())])
            } else {
                HashMap::new()
            },
            secret: Vec::new(),
            content_type: "text/plain".into(),
            created: 0,
            modified: 0,
        };
        let mut state = KeyringState::new();
        state.collections.insert(
            "/c".into(),
            CollectionInfo {
                label: "c".into(),
                locked: false,
                items: vec!["/c/items/0".into()],
                created: 0,
                modified: 0,
            },
        );
        state.items.insert("/c/items/0".into(), item(false));
        assert!(!coleccion_protegida(&state, "/c"));
        assert!(!coleccion_protegida(&state, "/no-existe"));

        // El sincronizador guarda su clave mientras la puerta iba al bus.
        state.items.insert("/c/items/1".into(), item(true));
        state
            .collections
            .get_mut("/c")
            .expect("la colección")
            .items
            .push("/c/items/1".into());
        assert!(coleccion_protegida(&state, "/c"));
    }

    /// Las pruebas no escriben nunca en el llavero de quien las corre.
    ///
    /// Una prueba de escritura que deja pasar lo que no debe —una puerta rota,
    /// o saboteada a propósito para ver que la prueba falla— llega a `save_db`.
    /// Si eso apunta al llavero real, la prueba lo reescribe con sus ítems y su
    /// contraseña. Pasó una vez; ver `keyring_path`.
    #[test]
    fn las_pruebas_no_apuntan_al_llavero_real() {
        let ruta = keyring_path().expect("en las pruebas siempre hay ruta");
        assert!(
            ruta.starts_with(std::env::temp_dir()),
            "en las pruebas la base tiene que ir a un directorio temporal, y va a {}",
            ruta.display()
        );
        if let Some(real) = keyring_path_under(dirs::data_dir()) {
            assert_ne!(
                ruta, real,
                "la ruta de las pruebas no puede ser la del llavero real"
            );
        }
    }

    // ── Lo que rodea a la clave: escribirla, borrarla, encontrarla ──
    //
    // `GetSecret` estaba cerrado desde #24, pero lo demás no: con `CreateItem`
    // y `replace`, `SetSecret` o los borrados, un proceso cualquiera **elegía**
    // la clave con la que se abre la base (#29), y con `SearchItems` y
    // `Attributes` encontraba el ítem para hacerlo (#30).
    //
    // Las escrituras que la puerta deja pasar se prueban con la sesión
    // **cerrada**: el autorizado recibe `IsLocked` —pasó la puerta y no escribió
    // nada— y el que no, `AccessDenied`. Con la sesión abierta, una escritura
    // que pasa iría a la base de quien corre la prueba.

    /// Las propiedades de un ítem que alguien pide crear, con el esquema del
    /// almacén o sin él.
    fn propiedades(protegido: bool) -> HashMap<String, Value<'static>> {
        let mut atributos = HashMap::from([("account_id".to_string(), "abc".to_string())]);
        if protegido {
            atributos.insert(ATRIBUTO_ESQUEMA.to_string(), ESQUEMA_PROTEGIDO.to_string());
        }
        HashMap::from([
            (
                "org.freedesktop.Secret.Item.Label".to_string(),
                Value::from("elegida por quien llama"),
            ),
            (
                "org.freedesktop.Secret.Item.Attributes".to_string(),
                Value::from(atributos),
            ),
        ])
    }

    /// Un secreto en claro, en la sesión de la prueba.
    fn secreto(valor: &str) -> SecretStruct {
        SecretStruct {
            session: OwnedObjectPath::try_from(SESION).expect("la sesión de la prueba"),
            parameters: Vec::new(),
            value: valor.as_bytes().to_vec(),
            content_type: "text/plain".into(),
        }
    }

    /// Lo que devuelve `GetSecret` del ítem del almacén al sincronizador: la
    /// forma de ver, después de un intento, que la clave sigue siendo la de
    /// antes.
    async fn clave_del_almacen(almacen: &Almacen) -> Vec<u8> {
        let respuesta = almacen
            .pedir_secreto(Some(DEL_SINCRONIZADOR))
            .await
            .expect("el sincronizador lee su clave");
        let (secreto,): (SecretStruct,) = respuesta.body().deserialize().expect("GetSecret");
        secreto.value
    }

    #[tokio::test]
    async fn un_impostor_no_reemplaza_la_clave_con_create_item() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let error = almacen
            .llamar_como(
                DE_UN_IMPOSTOR,
                COLECCION_DEL_LOGIN,
                IFACE_COLECCION,
                "CreateItem",
                &(propiedades(true), secreto(&"a".repeat(64)), true),
            )
            .await
            .expect_err("un proceso cualquiera no crea ítems con el esquema del almacén");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.DBus.Error.AccessDenied"
        );

        assert!(
            clave_del_almacen(&almacen).await == b"la clave del almacen",
            "la clave tiene que seguir siendo la de antes"
        );
    }

    #[tokio::test]
    async fn un_impostor_tampoco_planta_una_clave_sin_replace() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _cerrada = sesion_cerrada();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let error = almacen
            .llamar_como(
                DE_UN_IMPOSTOR,
                COLECCION_DEL_LOGIN,
                IFACE_COLECCION,
                "CreateItem",
                &(propiedades(true), secreto(&"a".repeat(64)), false),
            )
            .await
            .expect_err("sin replace tampoco: el sincronizador podría encontrar ése primero");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.DBus.Error.AccessDenied"
        );
    }

    #[tokio::test]
    async fn el_sincronizador_si_crea_su_clave() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _cerrada = sesion_cerrada();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let error = almacen
            .llamar_como(
                DEL_SINCRONIZADOR,
                COLECCION_DEL_LOGIN,
                IFACE_COLECCION,
                "CreateItem",
                &(propiedades(true), secreto(&"a".repeat(64)), true),
            )
            .await
            .expect_err("con la sesión cerrada no se escribe");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.Secret.Error.IsLocked",
            "el sincronizador pasa la puerta: lo único que lo frena es que el llavero está cerrado"
        );
    }

    #[tokio::test]
    async fn crear_un_item_comun_no_pasa_por_la_puerta() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _cerrada = sesion_cerrada();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let error = almacen
            .llamar_como(
                DE_UN_IMPOSTOR,
                COLECCION_DEL_LOGIN,
                IFACE_COLECCION,
                "CreateItem",
                &(propiedades(false), secreto("la del navegador"), true),
            )
            .await
            .expect_err("con la sesión cerrada no se escribe");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.Secret.Error.IsLocked"
        );
        assert!(
            almacen.preguntados().await.is_empty(),
            "un ítem sin el esquema del almacén no le pregunta nada al bus"
        );
    }

    #[tokio::test]
    async fn un_impostor_no_cambia_la_clave_con_set_secret() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let error = almacen
            .llamar_como(
                DE_UN_IMPOSTOR,
                ITEM,
                IFACE_ITEM,
                "SetSecret",
                &(secreto(&"a".repeat(64)),),
            )
            .await
            .expect_err("un proceso cualquiera no cambia la clave del almacén");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.DBus.Error.AccessDenied"
        );
        assert!(clave_del_almacen(&almacen).await == b"la clave del almacen");
    }

    #[tokio::test]
    async fn el_sincronizador_si_pasa_la_puerta_de_set_secret() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _cerrada = sesion_cerrada();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let error = almacen
            .llamar_como(
                DEL_SINCRONIZADOR,
                ITEM,
                IFACE_ITEM,
                "SetSecret",
                &(secreto(&"a".repeat(64)),),
            )
            .await
            .expect_err("con la sesión cerrada no se escribe");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.Secret.Error.IsLocked"
        );
    }

    #[tokio::test]
    async fn un_impostor_no_borra_la_clave() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let error = almacen
            .llamar_como(DE_UN_IMPOSTOR, ITEM, IFACE_ITEM, "Delete", &())
            .await
            .expect_err("un proceso cualquiera no borra la clave del almacén");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.DBus.Error.AccessDenied"
        );
        assert!(clave_del_almacen(&almacen).await == b"la clave del almacen");
    }

    #[tokio::test]
    async fn un_impostor_no_borra_la_coleccion_que_guarda_la_clave() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let error = almacen
            .llamar_como(
                DE_UN_IMPOSTOR,
                COLECCION_DEL_LOGIN,
                IFACE_COLECCION,
                "Delete",
                &(),
            )
            .await
            .expect_err("borrar la colección se llevaría la clave");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.DBus.Error.AccessDenied"
        );
        assert!(clave_del_almacen(&almacen).await == b"la clave del almacen");
    }

    /// `SearchItems` de la colección y del servicio, con `{}`: el impostor ve
    /// la contraseña común y no el ítem del almacén; el sincronizador, los dos.
    #[tokio::test]
    async fn search_items_no_le_muestra_el_almacen_a_un_impostor() {
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;
        let todos: HashMap<String, String> = HashMap::new();

        for (emisor, espera_el_almacen) in [(DE_UN_IMPOSTOR, false), (DEL_SINCRONIZADOR, true)] {
            let respuesta = almacen
                .llamar_como(
                    emisor,
                    COLECCION_DEL_LOGIN,
                    IFACE_COLECCION,
                    "SearchItems",
                    &(&todos,),
                )
                .await
                .expect("Collection.SearchItems");
            let rutas: Vec<OwnedObjectPath> = respuesta.body().deserialize().expect("rutas");
            let rutas: Vec<&str> = rutas.iter().map(|r| r.as_str()).collect();
            assert!(
                rutas.contains(&ITEM_COMUN),
                "{emisor} ve la contraseña común"
            );
            assert_eq!(
                rutas.contains(&ITEM),
                espera_el_almacen,
                "Collection.SearchItems de {emisor}: {rutas:?}"
            );

            let respuesta = almacen
                .llamar_como(emisor, SERVICIO, IFACE_SERVICIO, "SearchItems", &(&todos,))
                .await
                .expect("Service.SearchItems");
            let (abiertos, cerrados): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
                respuesta.body().deserialize().expect("rutas");
            let rutas: Vec<&str> = abiertos
                .iter()
                .chain(cerrados.iter())
                .map(|r| r.as_str())
                .collect();
            assert!(rutas.contains(&ITEM_COMUN));
            assert_eq!(
                rutas.contains(&ITEM),
                espera_el_almacen,
                "Service.SearchItems de {emisor}: {rutas:?}"
            );
        }
    }

    #[tokio::test]
    async fn buscar_contrasenas_comunes_no_pasa_por_la_puerta() {
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;
        // Nada del almacén tiene un `account_id` que no exista.
        let ninguno = HashMap::from([("url".to_string(), "https://ejemplo".to_string())]);

        almacen
            .llamar_como(
                DE_UN_IMPOSTOR,
                SERVICIO,
                IFACE_SERVICIO,
                "SearchItems",
                &(&ninguno,),
            )
            .await
            .expect("Service.SearchItems");
        assert!(almacen.preguntados().await.is_empty());
    }

    /// `Attributes` y `Label` del ítem del almacén, por `Properties.Get`: al
    /// impostor, no; al sincronizador, sí; y los de una contraseña común, a
    /// cualquiera. `GetAll` pasa por los mismos getters.
    #[tokio::test]
    async fn las_propiedades_del_almacen_se_describen_solo_al_sincronizador() {
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        for propiedad in ["Attributes", "Label"] {
            let error = almacen
                .llamar_como(
                    DE_UN_IMPOSTOR,
                    ITEM,
                    IFACE_PROPIEDADES,
                    "Get",
                    &(IFACE_ITEM, propiedad),
                )
                .await
                .expect_err("al impostor no se le describe el ítem del almacén");
            assert_eq!(
                nombre_del_error(&error),
                "org.freedesktop.DBus.Error.AccessDenied",
                "{propiedad}"
            );

            almacen
                .llamar_como(
                    DEL_SINCRONIZADOR,
                    ITEM,
                    IFACE_PROPIEDADES,
                    "Get",
                    &(IFACE_ITEM, propiedad),
                )
                .await
                .unwrap_or_else(|e| panic!("al sincronizador sí ({propiedad}): {e}"));

            almacen
                .llamar_como(
                    DE_UN_IMPOSTOR,
                    ITEM_COMUN,
                    IFACE_PROPIEDADES,
                    "Get",
                    &(IFACE_ITEM, propiedad),
                )
                .await
                .unwrap_or_else(|e| panic!("una contraseña común a cualquiera ({propiedad}): {e}"));
        }

        // `GetAll` no falla entero: zbus deja afuera las propiedades cuyo getter
        // da error. Lo que importa es que al impostor no le lleguen esas dos.
        for (emisor, las_ve) in [(DE_UN_IMPOSTOR, false), (DEL_SINCRONIZADOR, true)] {
            let respuesta = almacen
                .llamar_como(emisor, ITEM, IFACE_PROPIEDADES, "GetAll", &(IFACE_ITEM,))
                .await
                .expect("GetAll");
            let todas: HashMap<String, OwnedValue> =
                respuesta.body().deserialize().expect("GetAll");
            for propiedad in ["Attributes", "Label"] {
                assert_eq!(
                    todas.contains_key(propiedad),
                    las_ve,
                    "GetAll de {emisor}: {propiedad}"
                );
            }
        }
    }

    /// Un pedido sin emisor en la cabecera se rechaza, por el camino real.
    #[tokio::test]
    async fn sin_emisor_en_la_cabecera_no_recibe_el_secreto_por_dbus() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let almacen = Almacen::con_el_sincronizador_propio(Some(DEL_SINCRONIZADOR)).await;

        let error = almacen
            .pedir_secreto(None)
            .await
            .expect_err("un pedido sin emisor no puede leer el ítem");

        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.DBus.Error.AccessDenied"
        );
    }

    // ── El llavero entero, del otro lado de una conexión punto a punto ──────
    //
    // Sin `dbus-daemon`: dos puntas de un `UnixStream::pair()`, una con el
    // demonio y la otra con el cliente. Lo que se prueba es el servicio de
    // verdad, con los mismos mensajes que viajan por el bus de sesión —el
    // nombre del error y la señal, no una función de Rust que los devuelve.
    //
    // El estado se arma a mano y no con `register_default_collection`, que lee
    // la base del disco: una prueba no puede escribir en el llavero real de
    // quien la corre.

    const SERVICIO: &str = "/org/freedesktop/secrets";
    const IFACE_SERVICIO: &str = "org.freedesktop.Secret.Service";
    const IFACE_COLECCION: &str = "org.freedesktop.Secret.Collection";
    const IFACE_ITEM: &str = "org.freedesktop.Secret.Item";
    const IFACE_PROPIEDADES: &str = "org.freedesktop.DBus.Properties";
    const ITEM: &str = "/org/freedesktop/secrets/collection/login/items/0";
    /// El ítem de la colección que no depende del control de acceso, en el
    /// llavero de la prueba protegida.
    const ITEM_COMUN: &str = "/org/freedesktop/secrets/collection/login/items/1";
    const SESION: &str = "/org/freedesktop/secrets/session/s0";
    const ESPERA: std::time::Duration = std::time::Duration::from_secs(5);

    /// El llavero de la prueba: el demonio de un lado, el cliente del otro, y
    /// el estado con una colección abierta, un ítem y una sesión `plain`.
    ///
    /// Las dos conexiones se devuelven y se quedan vivas en la prueba: si se
    /// suelta la del demonio, el bus de la otra punta se corta y los avisos no
    /// llegan.
    async fn llavero() -> (zbus::Connection, zbus::Connection) {
        let state = Arc::new(Mutex::new(KeyringState::new()));
        {
            let mut s = state.lock().await;
            s.collections.insert(
                COLECCION_DEL_LOGIN.to_string(),
                CollectionInfo {
                    label: "Default collection".into(),
                    locked: false,
                    items: vec![ITEM.to_string()],
                    created: 1700,
                    modified: 1700,
                },
            );
            s.aliases
                .insert("default".into(), COLECCION_DEL_LOGIN.to_string());
            s.items.insert(
                ITEM.to_string(),
                ItemInfo {
                    label: "el de la prueba".into(),
                    attributes: HashMap::new(),
                    secret: b"el secreto".to_vec(),
                    content_type: "text/plain".into(),
                    created: 1700,
                    modified: 1700,
                },
            );
            s.sessions.insert(
                SESION.to_string(),
                SessionInfo {
                    algorithm: "plain".into(),
                    shared_key: None,
                    created: 1700,
                },
            );
        }

        let (extremo_del_demonio, extremo_del_cliente) = tokio::net::UnixStream::pair().unwrap();
        let demonio = zbus::connection::Builder::unix_stream(extremo_del_demonio)
            .server(zbus::Guid::generate())
            .unwrap()
            .p2p()
            .build();
        let cliente = zbus::connection::Builder::unix_stream(extremo_del_cliente)
            .p2p()
            .build();
        let (demonio, cliente) = tokio::join!(demonio, cliente);
        let demonio = demonio.expect("no se pudo levantar el bus de la prueba");
        let cliente = cliente.expect("no se pudo levantar el cliente de la prueba");

        demonio
            .object_server()
            .at(
                SERVICIO,
                ServiceInterface::new(demonio.clone(), Arc::clone(&state)),
            )
            .await
            .expect("no se pudo publicar el servicio");
        demonio
            .object_server()
            .at(
                COLECCION_DEL_LOGIN,
                CollectionInterface {
                    state: Arc::clone(&state),
                    conn: demonio.clone(),
                    path: COLECCION_DEL_LOGIN.to_string(),
                    alias: "login".into(),
                },
            )
            .await
            .expect("no se pudo publicar la colección");
        demonio
            .object_server()
            .at(
                ITEM,
                ItemInterface {
                    state: Arc::clone(&state),
                    conn: demonio.clone(),
                    path: ITEM.to_string(),
                },
            )
            .await
            .expect("no se pudo publicar el ítem");

        (demonio, cliente)
    }

    /// El mismo llavero de la prueba, con el ítem marcado como protegido.
    ///
    /// Va aparte de `llavero()` en vez de darle un parámetro: el caso normal y el
    /// protegido se leen distinto de un vistazo, y un `llavero(true)` esconde
    /// justo el dato que cada prueba viene a mirar. La segunda entrada es la que
    /// no depende de este control, y está para comprobar que el filtro es por
    /// ítem y no una negación general —si el control tapara el servicio entero,
    /// las contraseñas de los navegadores se dejarían de guardar y ni una prueba
    /// que mire sólo el ítem protegido lo notaría—.
    ///
    /// El bus falso se publica aparte, con [`llavero_con_item_protegido_y_bus`], y
    /// no con un parámetro acá: la puerta del almacén **siempre** pregunta al bus,
    /// así que un llavero sin bus detrás sólo sirve para las pruebas que no la
    /// usan, y para ésas se lee mejor que el bus no esté.
    async fn llavero_con_item_protegido() -> (zbus::Connection, zbus::Connection) {
        construir_llavero_con_item_protegido(EJECUTABLE_AUTORIZADO).await
    }

    /// El mismo llavero, y además un bus falso del otro lado del cliente.
    ///
    /// Hace falta porque la puerta del almacén **siempre** le pregunta al bus quién
    /// tiene `ar.net.vasak.os.AccountsSync`, y sobre una conexión punto a punto no
    /// hay bus al que preguntarle: las dos puntas se ven y nada más. Sin el bus
    /// falso, `GetSecret` sobre el ítem protegido cortaría en la pregunta, que es
    /// un caso de rechazo pero no el que se quiere comprobar.
    ///
    /// Lo que devuelve de más es el registro de los nombres preguntados, porque
    /// hay que poder afirmar que se preguntó **por el nombre del sincronizador** y
    /// no por otro, y eso no se ve en el resultado de la llamada.
    async fn llavero_con_item_protegido_y_bus(
        bus: Option<BusFalso>,
        esperado: &str,
    ) -> (zbus::Connection, zbus::Connection, Arc<Mutex<Vec<String>>>) {
        let (demonio, cliente) = construir_llavero_con_item_protegido(esperado).await;

        let preguntados = match bus {
            Some(bus) => {
                let preguntados = bus.registro();
                test_bus::publicar(&cliente, bus).await;
                // Recién construida la conexión, el primer mensaje se pierde. La
                // puerta pregunta por el nombre antes que nada, y sin el viaje de
                // calentamiento esa pregunta sería la que se pierde: la prueba
                // rechazaría por un motivo de `p2p` y no por el que quiere ver.
                test_bus::calentar(&demonio).await;
                preguntados
            }
            None => Arc::new(Mutex::new(Vec::new())),
        };

        (demonio, cliente, preguntados)
    }

    /// El estado del llavero, y nada del bus.
    ///
    /// Aparte porque es lo único que tienen en común [`llavero`] y las dos
    /// variantes del llavero protegido: el que arma el estado no tiene por qué
    /// saber si quien va a preguntar es el demonio, el cliente o un bus falso.
    async fn construir_llavero_con_item_protegido(
        esperado: &str,
    ) -> (zbus::Connection, zbus::Connection) {
        let state = Arc::new(Mutex::new(KeyringState::new()));
        {
            let mut s = state.lock().await;
            s.ejecutable_del_sincronizador = esperado.to_owned();
            s.collections.insert(
                COLECCION_DEL_LOGIN.to_string(),
                CollectionInfo {
                    label: "Default collection".into(),
                    locked: false,
                    items: vec![ITEM.to_string(), ITEM_COMUN.to_string()],
                    created: 1700,
                    modified: 1700,
                },
            );
            s.aliases
                .insert("default".into(), COLECCION_DEL_LOGIN.to_string());
            s.items.insert(
                ITEM.to_string(),
                ItemInfo {
                    label: "la clave del almacen".into(),
                    attributes: HashMap::from([(
                        ATRIBUTO_ESQUEMA.to_string(),
                        ESQUEMA_PROTEGIDO.to_string(),
                    )]),
                    secret: b"la clave del almacen".to_vec(),
                    content_type: "text/plain".into(),
                    created: 1700,
                    modified: 1700,
                },
            );
            s.items.insert(
                ITEM_COMUN.to_string(),
                ItemInfo {
                    label: "la del navegador".into(),
                    attributes: HashMap::new(),
                    secret: b"la contrasena del navegador".to_vec(),
                    content_type: "text/plain".into(),
                    created: 1700,
                    modified: 1700,
                },
            );
            s.sessions.insert(
                SESION.to_string(),
                SessionInfo {
                    algorithm: "plain".into(),
                    shared_key: None,
                    created: 1700,
                },
            );
        }

        let (extremo_del_demonio, extremo_del_cliente) = tokio::net::UnixStream::pair().unwrap();
        let demonio = zbus::connection::Builder::unix_stream(extremo_del_demonio)
            .server(zbus::Guid::generate())
            .unwrap()
            .p2p()
            .build();
        let cliente = zbus::connection::Builder::unix_stream(extremo_del_cliente)
            .p2p()
            .build();
        let (demonio, cliente) = tokio::join!(demonio, cliente);
        let demonio = demonio.expect("no se pudo levantar el bus de la prueba");
        let cliente = cliente.expect("no se pudo levantar el cliente de la prueba");

        demonio
            .object_server()
            .at(
                SERVICIO,
                ServiceInterface::new(demonio.clone(), Arc::clone(&state)),
            )
            .await
            .expect("no se pudo publicar el servicio");
        demonio
            .object_server()
            .at(
                COLECCION_DEL_LOGIN,
                CollectionInterface {
                    state: Arc::clone(&state),
                    conn: demonio.clone(),
                    path: COLECCION_DEL_LOGIN.to_string(),
                    alias: "default".to_string(),
                },
            )
            .await
            .expect("no se pudo publicar la colección");
        for ruta in [ITEM, ITEM_COMUN] {
            demonio
                .object_server()
                .at(
                    ruta,
                    ItemInterface {
                        state: Arc::clone(&state),
                        conn: demonio.clone(),
                        path: ruta.to_string(),
                    },
                )
                .await
                .expect("no se pudo publicar el ítem");
        }

        (demonio, cliente)
    }

    /// Una llamada al demonio por nombre de método.
    ///
    /// Sin destino, que en una conexión punto a punto es la otra punta: es lo
    /// único que hay. Devuelve el mensaje entero, para que cada prueba mire la
    /// parte que le importa —el cuerpo, o el nombre del error— y no una
    /// función de Rust que la traduzca.
    async fn llamar<B>(
        cliente: &zbus::Connection,
        ruta: &str,
        iface: &str,
        metodo: &str,
        cuerpo: &B,
    ) -> zbus::Result<zbus::Message>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        cliente
            .call_method(
                None::<&str>,
                ruta.to_string(),
                Some(iface.to_string()),
                metodo.to_string(),
                cuerpo,
            )
            .await
    }

    /// El nombre del error con el que contestó el demonio.
    fn nombre_del_error(e: &zbus::Error) -> String {
        match e {
            zbus::Error::MethodError(nombre, _, _) => nombre.to_string(),
            otro => panic!("se esperaba un error de método del demonio y llegó {otro:?}"),
        }
    }

    /// `Service.Lock` sobre la colección del login.
    async fn bloquear(cliente: &zbus::Connection) -> Vec<OwnedObjectPath> {
        let respuesta = llamar(
            cliente,
            SERVICIO,
            IFACE_SERVICIO,
            "Lock",
            &(vec![OwnedObjectPath::try_from(COLECCION_DEL_LOGIN).unwrap()],),
        )
        .await
        .expect("bloquear una colección abierta no puede fallar");
        let (bloqueadas, dialogo): (Vec<OwnedObjectPath>, OwnedObjectPath) = respuesta
            .body()
            .deserialize()
            .expect("la respuesta de `Lock` no se entiende");
        assert_eq!(
            dialogo.as_str(),
            "/",
            "bloquear no puede abrir un diálogo de desbloqueo"
        );
        bloqueadas
    }

    /// Los `PropertiesChanged` de una ruta, en el orden en que llegan.
    async fn cambios_de(cliente: &zbus::Connection, ruta: &'static str) -> zbus::MessageStream {
        let regla = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .path(ruta)
            .and_then(|r| r.interface(IFACE_PROPIEDADES))
            .and_then(|r| r.member("PropertiesChanged"))
            .expect("no se pudo armar el filtro")
            .build();
        zbus::MessageStream::for_match_rule(regla, cliente, None)
            .await
            .expect("no se pudo escuchar la ruta")
    }

    /// El primer aviso que habla de `Locked`, o `None` si la espera se venció.
    ///
    /// `None` es exactamente lo que devuelve un `lock()` que no avisa: por eso
    /// el mensaje del fallo tiene que decir que no llegó nada, y no inventar un
    /// motivo.
    async fn primer_aviso(cambios: &mut zbus::MessageStream) -> Option<Option<bool>> {
        use futures_util::StreamExt;
        let mensaje = match tokio::time::timeout(ESPERA, cambios.next()).await {
            Ok(Some(Ok(mensaje))) => mensaje,
            _ => return None,
        };
        let (iface, cambiadas, _): (String, HashMap<String, OwnedValue>, Vec<String>) = mensaje
            .body()
            .deserialize()
            .expect("un `PropertiesChanged` que no se entiende");
        if iface != IFACE_COLECCION && iface != IFACE_ITEM {
            return None;
        }
        Some(
            cambiadas
                .get("Locked")
                .cloned()
                .and_then(|v| bool::try_from(v).ok()),
        )
    }

    /// Deja la contraseña maestra de la sesión como la quiere la prueba, y
    /// vuelve a dejarla como estaba.
    ///
    /// Sin esto ninguna prueba puede confiar en el estado: `master_password()` es
    /// del proceso entero, y las pruebas de escritura de la base —que llaman a
    /// `adopt_password`— **dejan una contraseña puesta** para la que corra
    /// después. Una prueba que necesita «sin contraseña en memoria» y no lo
    /// impone se entera tarde, y de la peor manera: con la contraseña puesta,
    /// `CreateItem` no se rechaza y guarda de verdad.
    ///
    /// La prueba toma [`estado_de_la_sesion`] mientras dura, que es lo que
    /// serializa esto con las otras que tocan el mismo estado.
    struct Sesion(Option<Zeroizing<String>>);

    impl Drop for Sesion {
        fn drop(&mut self) {
            if let Ok(mut guard) = master_store().lock() {
                *guard = self.0.take();
            }
        }
    }

    /// Sin `effectively_locked` da `true` siempre, y no se puede probar ni que el
    /// bloqueo *cambie* algo ni que un método que no lee un secreto siga
    /// contestando.
    fn sesion_abierta() -> Sesion {
        sesion(Some("la-de-la-prueba"))
    }

    /// Una sesión nueva, o una que se reinició: la contraseña todavía no llegó.
    fn sesion_cerrada() -> Sesion {
        sesion(None)
    }

    fn sesion(clave: Option<&str>) -> Sesion {
        let antes = master_store().lock().ok().and_then(|g| g.clone());
        if let Some(clave) = clave {
            set_master_password(clave);
        } else if let Ok(mut guard) = master_store().lock() {
            *guard = None;
        }
        Sesion(antes)
    }

    /// Deja el bloqueo de escritura como estaba, y lo vuelve a dejar al
    /// terminar.
    ///
    /// El estado es del proceso entero: una prueba que se lo deja puesto hace
    /// fallar a la que corra después —que es la que comprueba que un arranque
    /// sin contraseña no le bloquea el llavero a nadie—.
    struct EscrituraComoEstaba(Option<String>);

    impl EscrituraComoEstaba {
        fn nuevo() -> Self {
            Self(writes_blocked())
        }
    }

    impl Drop for EscrituraComoEstaba {
        fn drop(&mut self) {
            if let Ok(mut bloqueo) = write_block().lock() {
                *bloqueo = self.0.take();
            }
        }
    }

    /// El aviso que el sincronizador de `vasak-accounts` espera al bloquear, y
    /// que hoy no llega: sin él, la clave de una base cifrada sigue en memoria
    /// hasta la próxima revisión del servicio, que es cada **300 segundos**.
    ///
    /// Sin el fix, `Service.Lock` cambia la bandera y sale sin emitir nada, así
    /// que la espera se vence y el mensaje del fallo dice que el aviso no llegó.
    #[tokio::test]
    async fn bloquear_avisa_que_cambio_locked() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let (demonio, cliente) = llavero().await;

        let mut de_la_coleccion = cambios_de(&cliente, COLECCION_DEL_LOGIN).await;
        let mut del_item = cambios_de(&cliente, ITEM).await;

        assert_eq!(
            bloquear(&cliente).await,
            vec![OwnedObjectPath::try_from(COLECCION_DEL_LOGIN).unwrap()],
            "la colección bloqueada es la que se devuelve"
        );

        assert_eq!(
            primer_aviso(&mut de_la_coleccion).await,
            Some(Some(true)),
            "bloquear tiene que avisar en la colección que cambió `Locked`, y a `true`: el aviso \
             no llegó"
        );
        assert_eq!(
            primer_aviso(&mut del_item).await,
            Some(Some(true)),
            "y en el ítem, que es donde cada aplicación mira su propio `Locked`: el aviso no llegó"
        );

        // La propiedad releída dice lo mismo que el aviso: por eso el aviso
        // alcanza con «puede haber cambiado» y el cliente tiene que leerla.
        let respuesta = llamar(
            &cliente,
            COLECCION_DEL_LOGIN,
            IFACE_PROPIEDADES,
            "Get",
            &(IFACE_COLECCION, "Locked"),
        )
        .await
        .expect("la propiedad tiene que contestar");
        let valor: OwnedValue = respuesta
            .body()
            .deserialize()
            .expect("respuesta del demonio");
        assert_eq!(
            bool::try_from(valor).ok(),
            Some(true),
            "la propiedad y el aviso tienen que decir lo mismo"
        );
        drop(demonio);
    }

    /// El otro sentido también avisa. `Service.Unlock` es el camino por el que un
    /// cliente levanta el bloqueo de una colección, y si no dijera nada, el que
    /// oyó «se bloqueó» se quedaría creyendo que el llavero sigue bloqueado
    /// después del desbloqueo: el aviso de un sentido sin el del otro es peor que
    /// no avisar.
    ///
    /// Sin el fix, `Unlock` levanta la bandera y sale en silencio, así que la
    /// espera se vence.
    #[tokio::test]
    async fn desbloquear_tambien_avisa_que_cambio_locked() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let (demonio, cliente) = llavero().await;

        let mut de_la_coleccion = cambios_de(&cliente, COLECCION_DEL_LOGIN).await;
        let mut del_item = cambios_de(&cliente, ITEM).await;

        let _ = bloquear(&cliente).await;
        assert_eq!(
            primer_aviso(&mut de_la_coleccion).await,
            Some(Some(true)),
            "el aviso del bloqueo es el que prepara la prueba"
        );
        let _ = primer_aviso(&mut del_item).await;

        // Y ahora el desbloqueo, que también tiene que avisar.
        let respuesta = llamar(
            &cliente,
            SERVICIO,
            IFACE_SERVICIO,
            "Unlock",
            &(vec![OwnedObjectPath::try_from(COLECCION_DEL_LOGIN).unwrap()],),
        )
        .await
        .expect("desbloquear una colección con la contraseña en memoria no puede fallar");
        let (desbloqueadas, dialogo): (Vec<OwnedObjectPath>, OwnedObjectPath) = respuesta
            .body()
            .deserialize()
            .expect("la respuesta de `Unlock` no se entiende");
        assert_eq!(dialogo.as_str(), "/", "desbloquear no abre ningún diálogo");
        assert_eq!(
            desbloqueadas.len(),
            1,
            "la colección del login se desbloqueó"
        );

        assert_eq!(
            primer_aviso(&mut de_la_coleccion).await,
            Some(Some(false)),
            "desbloquear también tiene que avisar, y a `false`: el aviso no llegó"
        );
        assert_eq!(
            primer_aviso(&mut del_item).await,
            Some(Some(false)),
            "y en el ítem, que es donde cada aplicación mira su propio `Locked`: el aviso no llegó"
        );
        drop(demonio);
    }

    /// Leer un secreto con el llavero bloqueado se avisa con el nombre del
    /// estándar, `org.freedesktop.Secret.Error.IsLocked`, y no con un `Failed` y
    /// un texto: es lo que le dice al cliente que tiene que desbloquear y
    /// reintentar.
    ///
    /// La misma llamada con la colección abierta tiene que servir el secreto, o
    /// el error no probaría que lo causa el bloqueo.
    #[tokio::test]
    async fn leer_un_secreto_con_el_llavero_bloqueado_responde_is_locked() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _abierta = sesion_abierta();
        let (demonio, cliente) = llavero().await;
        let sesion = OwnedObjectPath::try_from(SESION).unwrap();

        // Abierta: el secreto sale.
        let respuesta = llamar(&cliente, ITEM, IFACE_ITEM, "GetSecret", &(&sesion,))
            .await
            .expect("con el llavero abierto el secreto se lee");
        let (secreto,): (SecretStruct,) = respuesta.body().deserialize().expect("respuesta");
        assert_eq!(secreto.value, b"el secreto");

        // Bloqueada: el mismo camino, y ahora el nombre del estándar.
        let _ = bloquear(&cliente).await;
        let error = llamar(&cliente, ITEM, IFACE_ITEM, "GetSecret", &(&sesion,))
            .await
            .expect_err("con la colección bloqueada el secreto no puede salir");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.Secret.Error.IsLocked",
            "leer un secreto bloqueado se avisa con el nombre del estándar, no con el texto de un \
             `Failed` que el cliente tiene que adivinar"
        );
        drop(demonio);
    }

    /// Guardar con el llavero bloqueado también lleva el nombre del estándar, y
    /// por el motivo que dejó de lado al consumidor: el que guarda tiene que
    /// poder separar «desbloqueá y volvé a intentar» de «falló», sin leer el
    /// texto.
    ///
    /// El caso es **sin contraseña maestra en memoria**, que es como arranca una
    /// sesión nueva y como queda una que se reinició. Con la contraseña puesta
    /// y la colección marcada con `Service.Lock` la escritura sigue: ese
    /// bloqueo es por colección y no toca la base, que es justo lo que
    /// `ensure_unlocked` decide —y lo que `vasak-keyring#24` va a revisar.
    #[tokio::test]
    async fn guardar_con_el_llavero_bloqueado_responde_is_locked() {
        let _sesion = estado_de_la_sesion().lock().await;
        let _cerrada = sesion_cerrada();
        let (demonio, cliente) = llavero().await;

        let error = llamar(
            &cliente,
            COLECCION_DEL_LOGIN,
            IFACE_COLECCION,
            "CreateItem",
            &(
                HashMap::from([(
                    "org.freedesktop.Secret.Item.Label".to_string(),
                    Value::from("el nuevo"),
                )]),
                SecretStruct {
                    session: OwnedObjectPath::try_from(SESION).unwrap(),
                    parameters: Vec::new(),
                    value: "0".repeat(64).into_bytes(),
                    content_type: "text/plain".into(),
                },
                true,
            ),
        )
        .await
        .expect_err("con el llavero bloqueado no se puede guardar");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.Secret.Error.IsLocked",
            "guardar con el llavero bloqueado se avisa con el nombre del estándar"
        );
        drop(demonio);
    }

    /// **`IsLocked` donde no corresponde es tan confuso como el `Failed` que
    /// estaba antes.** Un `IsLocked` manda al cliente a un camino de desbloqueo
    /// que no va a funcionar, así que lo que no lee un secreto tiene que seguir
    /// contestando lo de siempre:
    ///
    /// - `SearchItems` devuelve vacío —que es lo que el estándar dice para una
    ///   colección bloqueada— y no un error;
    /// - `ReadAlias` contesta la ruta de la colección, bloqueada o no;
    /// - `CreateItem` con la base del disco sin descifrar **no** es un bloqueo de
    ///   la colección: la colección puede estar abierta y consultable, lo que no
    ///   se puede es escribir un archivo que ya hay. Eso sigue siendo `Failed`,
    ///   con el texto entero que dice qué hacer.
    #[tokio::test]
    async fn con_el_llavero_bloqueado_solo_lo_que_lee_un_secreto_responde_is_locked() {
        let _sesion = estado_de_la_sesion().lock().await;
        // Hay una base en el disco que esta sesión no abre: la escritura queda
        // bloqueada con un motivo que **no** es la falta de contraseña maestra.
        let _escritura = EscrituraComoEstaba::nuevo();
        let dir = DirDePrueba::nuevo("bloqueo-por-coherencia");
        let ruta = dir.ruta().join("keyring.db");
        base_con_una_entrada(&ruta, "la-buena").await;
        let carga = items_from_disk(&ruta, Some("la-mala"))
            .await
            .expect("no poder descifrar todavía no es un fallo");
        assert!(carga.undecrypted);
        seed_items(carga);
        assert!(writes_blocked().is_some(), "arrancó sin poder escribir");

        // Con la contraseña maestra puesta, la colección **no** está bloqueada:
        // se puede leer. Lo que no se puede es guardar.
        let _abierta = sesion_abierta();
        let (demonio, cliente) = llavero().await;
        let sesion = OwnedObjectPath::try_from(SESION).unwrap();

        let leido = llamar(&cliente, ITEM, IFACE_ITEM, "GetSecret", &(&sesion,)).await;
        assert!(
            leido.is_ok(),
            "con la contraseña maestra el secreto se lee: una base sin descifrar en el disco no \
             bloquea la lectura"
        );

        // Ahora sí, bloqueada: `SearchItems` vacío y `ReadAlias` con la ruta.
        let bloqueadas = bloquear(&cliente).await;
        assert_eq!(bloqueadas.len(), 1, "la colección del login se bloqueó");

        let respuesta = llamar(
            &cliente,
            COLECCION_DEL_LOGIN,
            IFACE_COLECCION,
            "SearchItems",
            &(HashMap::<String, String>::new(),),
        )
        .await
        .expect(
            "una búsqueda no lee un secreto, y con la colección bloqueada tampoco se avisa \
                  con un `IsLocked`: contesta las rutas y cada cliente mira el `Locked` de lo que \
                  encuentra",
        );
        let encontrados: Vec<OwnedObjectPath> = respuesta.body().deserialize().expect("respuesta");
        assert_eq!(
            encontrados,
            vec![OwnedObjectPath::try_from(ITEM).unwrap()],
            "la búsqueda de una colección devuelve sus ítems, esté bloqueada o no"
        );

        let respuesta = llamar(
            &cliente,
            SERVICIO,
            IFACE_SERVICIO,
            "ReadAlias",
            &("default",),
        )
        .await
        .expect("leer un alias no toca un secreto");
        let alias: OwnedObjectPath = respuesta.body().deserialize().expect("respuesta");
        assert_eq!(
            alias.as_str(),
            COLECCION_DEL_LOGIN,
            "`ReadAlias` contesta la ruta también con la colección bloqueada"
        );

        // Y guardar con la base del disco sin descifrar no es `IsLocked`.
        let error = llamar(
            &cliente,
            COLECCION_DEL_LOGIN,
            IFACE_COLECCION,
            "CreateItem",
            &(
                HashMap::from([(
                    "org.freedesktop.Secret.Item.Label".to_string(),
                    Value::from("el nuevo"),
                )]),
                SecretStruct {
                    session: sesion,
                    parameters: Vec::new(),
                    value: "0".repeat(64).into_bytes(),
                    content_type: "text/plain".into(),
                },
                true,
            ),
        )
        .await
        .expect_err("no se puede guardar sobre una base sin descifrar");
        assert_eq!(
            nombre_del_error(&error),
            "org.freedesktop.DBus.Error.Failed",
            "«la base del disco no está descifrada» no es un bloqueo de la colección: mandar a \
             desbloquear no la abre, así que no puede ser `IsLocked`"
        );
        drop(demonio);
    }

    /// Un `Failed` cualquiera no es un bloqueo, y el texto no cambia el nombre:
    /// el nombre lo decide el estado del llavero.
    #[test]
    fn el_nombre_del_error_lo_decide_el_variante_y_no_el_texto() {
        use zbus::DBusError as _;

        let bloqueado = SecretError::IsLocked("cualquier cosa".into());
        assert_eq!(
            bloqueado.name().as_str(),
            "org.freedesktop.Secret.Error.IsLocked"
        );
        for texto in [
            "el llavero está bloqueado",
            "collection is locked",
            "",
            "no se pudo leer el secreto",
        ] {
            assert_eq!(
                SecretError::IsLocked(texto.into()).name().as_str(),
                "org.freedesktop.Secret.Error.IsLocked",
                "el texto {texto:?} no puede cambiar el nombre"
            );
        }

        assert_eq!(
            SecretError::Plain(dbus_err("la base del disco está sin descifrar"))
                .name()
                .as_str(),
            "org.freedesktop.DBus.Error.Failed",
            "todo lo que no es un bloqueo conserva el nombre que ya tenía"
        );
    }
}
