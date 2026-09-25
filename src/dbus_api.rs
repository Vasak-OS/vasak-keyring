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
use crate::session_crypto;

fn dbus_err(msg: impl Into<String>) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(msg.into())
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
    keyring_path_under(dirs::data_dir())
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

/// Checked before a write mutates anything, so a rejected store leaves no
/// half-created item behind that a later lookup would find.
///
/// `String` y no `zbus::fdo::Error` porque no todos los que preguntan están
/// hablando por el bus: el backend del portal necesita el texto para el diario.
fn ensure_unlocked() -> Result<(), String> {
    // El bloqueo va antes que la contraseña, y no después: tener una en memoria
    // no dice que haya abierto la base, y una que no la abre es precisamente el
    // caso que hay que parar.
    if let Some(motivo) = writes_blocked() {
        return Err(motivo);
    }
    match master_password() {
        Some(_) => Ok(()),
        None => Err(LOCKED_MESSAGE.to_string()),
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
        }
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
    #[zbus(property)]
    async fn label(&self) -> Result<String, zbus::fdo::Error> {
        self.state
            .lock()
            .await
            .items
            .get(&self.path)
            .map(|i| i.label.clone())
            .ok_or_else(|| dbus_err("item not found"))
    }

    #[zbus(property)]
    async fn attributes(&self) -> Result<HashMap<String, String>, zbus::fdo::Error> {
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
        for col in state.collections.values() {
            if col.items.contains(&self.path) {
                return Ok(effectively_locked(col.locked));
            }
        }
        Ok(effectively_locked(false))
    }

    #[zbus(property)]
    async fn created(&self) -> Result<u64, zbus::fdo::Error> {
        self.state
            .lock()
            .await
            .items
            .get(&self.path)
            .map(|i| i.created)
            .ok_or_else(|| dbus_err("item not found"))
    }

    #[zbus(property)]
    async fn modified(&self) -> Result<u64, zbus::fdo::Error> {
        self.state
            .lock()
            .await
            .items
            .get(&self.path)
            .map(|i| i.modified)
            .ok_or_else(|| dbus_err("item not found"))
    }

    /// Returns the secret as a single struct argument.
    ///
    /// The one-element tuple is load-bearing: returning `SecretStruct` bare
    /// made zbus flatten it into four separate out-arguments (`oayays`), and
    /// libsecret rejected every reply as a signature mismatch against the
    /// `((oayays))` the spec declares.
    async fn get_secret(
        &self,
        session: OwnedObjectPath,
    ) -> Result<(SecretStruct,), zbus::fdo::Error> {
        let state = self.state.lock().await;
        // Never release a secret from a locked collection.
        if state
            .collections
            .values()
            .any(|c| effectively_locked(c.locked) && c.items.contains(&self.path))
        {
            return Err(dbus_err("collection is locked"));
        }
        let item = state
            .items
            .get(&self.path)
            .ok_or_else(|| dbus_err("item not found"))?;
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

    async fn set_secret(&mut self, secret: SecretStruct) -> Result<(), zbus::fdo::Error> {
        ensure_unlocked().map_err(dbus_err)?;

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
                None => return Err(dbus_err("item not found")),
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

    async fn delete(&mut self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
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

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        let state = self.state.lock().await;
        state
            .collections
            .get(&self.path)
            .map(|c| {
                c.items
                    .iter()
                    .filter_map(|ip| owned_path_try(ip).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    // Per the Secret Service spec, Collection.SearchItems returns a single
    // array of matching items (unlike Service.SearchItems, which splits them
    // into unlocked/locked).
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        let state = self.state.lock().await;
        let mut results = Vec::new();

        if let Some(col) = state.collections.get(&self.path) {
            for ip in &col.items {
                if let Some(item) = state.items.get(ip) {
                    if attributes
                        .iter()
                        .all(|(k, v)| item.attributes.get(k) == Some(v))
                    {
                        results.push(owned_path_try(ip).unwrap_or_else(|_| owned_path("/")));
                    }
                }
            }
        }
        Ok(results)
    }

    async fn create_item(
        &mut self,
        properties: HashMap<String, Value<'_>>,
        secret: SecretStruct,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), zbus::fdo::Error> {
        ensure_unlocked().map_err(dbus_err)?;

        let label = properties
            .get("org.freedesktop.Secret.Item.Label")
            .and_then(value_to_string)
            .unwrap_or_else(|| "Unnamed".to_string());

        let attributes = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .and_then(value_to_attrmap)
            .unwrap_or_default();

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
                        state
                            .items
                            .get(*ip)
                            .is_some_and(|item| item.attributes == attributes)
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

    async fn delete(&mut self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        let orphaned_aliases: Vec<String>;
        let removed_items: Vec<String>;
        {
            let mut state = self.state.lock().await;
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

        // Register item interfaces
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

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), zbus::fdo::Error> {
        let state = self.state.lock().await;
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();

        for col in state.collections.values() {
            for ip in &col.items {
                if let Some(item) = state.items.get(ip) {
                    if attributes
                        .iter()
                        .all(|(k, v)| item.attributes.get(k) == Some(v))
                    {
                        let o = owned_path_try(ip).unwrap_or_else(|_| owned_path("/"));
                        if effectively_locked(col.locked) {
                            locked.push(o)
                        } else {
                            unlocked.push(o)
                        }
                    }
                }
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

        let mut state = self.state.lock().await;
        let mut out = Vec::new();
        for obj in &objects {
            let s = obj.as_str().to_string();
            if let Some(col) = state.collections.get_mut(&s) {
                col.locked = false;
                out.push(obj.clone());
            }
        }
        Ok((out, owned_path("/")))
    }

    async fn lock(
        &mut self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), zbus::fdo::Error> {
        let mut state = self.state.lock().await;
        let mut out = Vec::new();
        for obj in &objects {
            let s = obj.as_str().to_string();
            if let Some(col) = state.collections.get_mut(&s) {
                col.locked = true;
                out.push(obj.clone());
            }
        }
        Ok((out, owned_path("/")))
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        // Keyed by object path, not string: the spec declares `a{o(oayays)}`
        // and libsecret refuses the `a{s(oayays)}` a String key produces.
    ) -> Result<HashMap<OwnedObjectPath, SecretStruct>, zbus::fdo::Error> {
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

    /// Emits `PropertiesChanged` for every `Locked` property that just flipped.
    /// Lives outside the `#[interface]` block on purpose: it is an internal
    /// helper, not something to expose on the bus. Failures are ignored because
    /// the keyring is already usable by then, and a client that misses the
    /// signal still gets the right answer next time it reads the property.
    async fn announce_unlocked(&self, coll_path: &str, item_paths: &[String]) {
        let server = self.conn.object_server();

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
        self.announce_unlocked(&coll_path, &item_paths).await;

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

/// Atributo con el que se marcan estos secretos, por convención de freedesktop.
pub const ESQUEMA_PORTAL: &str = "org.freedesktop.portal.Secret";

/// Cuántos bytes tiene el secreto maestro que se le da a una aplicación.
///
/// Es una clave, no una contraseña: no la escribe nadie, así que conviene que
/// sea larga. 64 bytes es lo que usan las otras implementaciones del portal.
const LARGO_SECRETO_PORTAL: usize = 64;

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
fn candado_de_creacion() -> &'static Mutex<()> {
    static CANDADO: OnceLock<Mutex<()>> = OnceLock::new();
    CANDADO.get_or_init(|| Mutex::new(()))
}

/// El secreto maestro de una aplicación, creándolo la primera vez.
///
/// La especificación del portal pide que sea **único por aplicación y estable
/// mientras esté instalada**, así que no se deriva de nada: se genera al azar la
/// primera vez y queda guardado en el llavero como cualquier otro secreto. Si se
/// derivara de la contraseña maestra, cambiar la contraseña de la cuenta
/// cambiaría el secreto de todas las aplicaciones a la vez, y lo que cada una
/// hubiera cifrado con él dejaría de abrirse.
///
/// Queda visible en el Secret Service como una entrada más, a propósito: es un
/// secreto que el escritorio guarda en nombre de la persona, y tiene que poder
/// verlo y borrarlo como cualquier otro.
pub async fn secreto_maestro_de_app(
    state: &Arc<Mutex<KeyringState>>,
    conn: &Connection,
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

    let atributos: HashMap<String, String> = HashMap::from([
        ("xdg:schema".to_string(), ESQUEMA_PORTAL.to_string()),
        ("app_id".to_string(), app_id.to_string()),
    ]);

    // Todo el «buscar, y si no está crear» va bajo un mismo candado: si dos
    // pedidos simultáneos pasaran los dos por la búsqueda, crearían dos secretos
    // distintos para la misma aplicación. Ver `candado_de_creacion`.
    let _guardia = candado_de_creacion().lock().await;

    if let Some(existente) = buscar_secreto(state, &atributos).await {
        return Ok(existente);
    }

    use rand::RngCore;
    let mut secreto = vec![0u8; LARGO_SECRETO_PORTAL];
    rand::thread_rng().fill_bytes(&mut secreto);

    let coleccion = "/org/freedesktop/secrets/collection/login";
    let ruta = {
        let mut estado = state.lock().await;
        let ruta = format!("{coleccion}/items/{}", estado.take_item_id());

        estado.items.insert(
            ruta.clone(),
            ItemInfo {
                label: format!("Secreto de {app_id}"),
                attributes: atributos,
                secret: secreto.clone(),
                content_type: "application/octet-stream".into(),
                created: now(),
                modified: now(),
            },
        );
        if let Some(col) = estado.collections.get_mut(coleccion) {
            col.items.push(ruta.clone());
            col.modified = now();
        }
        ruta
    };

    // Se guarda **antes** de publicarlo y antes de devolverlo. Si el disco falla,
    // la aplicación no debe recibir un secreto que en el próximo arranque no va a
    // existir: cifraría sus datos con una clave que se pierde.
    let items: Vec<ItemInfo> = {
        let estado = state.lock().await;
        estado.items.values().cloned().collect()
    };
    if let Err(e) = save_db(&items) {
        // Y si falló, el secreto se deshace. Dejándolo en memoria, el próximo
        // pedido lo encontraría y lo devolvería sin volver a intentar escribir:
        // un error transitorio de disco alcanzaría para que la aplicación cifre
        // con una clave que desaparece al reiniciar.
        let mut estado = state.lock().await;
        estado.items.remove(&ruta);
        if let Some(col) = estado.collections.get_mut(coleccion) {
            col.items.retain(|p| p != &ruta);
        }
        return Err(e);
    }

    // Recién ahora se publica en el bus, con el secreto ya en disco.
    let iface = ItemInterface {
        state: state.clone(),
        conn: conn.clone(),
        path: ruta.clone(),
    };
    if let Err(e) = conn.object_server().at(ruta.clone(), iface).await {
        // No es fatal: el secreto existe y está guardado. Lo único que se pierde
        // es que aparezca como entrada del Secret Service hasta el próximo
        // arranque, donde se registra al cargar la base.
        eprintln!("vasak-keyring: no se pudo publicar {ruta}: {e}");
    }

    Ok(secreto)
}

/// Busca un secreto ya guardado por sus atributos.
async fn buscar_secreto(
    state: &Arc<Mutex<KeyringState>>,
    atributos: &HashMap<String, String>,
) -> Option<Vec<u8>> {
    let estado = state.lock().await;
    estado
        .items
        .values()
        .find(|item| &item.attributes == atributos)
        .map(|item| item.secret.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
