use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{Mutex as StdMutex, OnceLock};
use tokio::sync::Mutex;
use zeroize::Zeroizing;
use zbus::{interface, Connection};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{self, OwnedObjectPath, OwnedValue, Value, Type};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::crypto;
use crate::session_crypto;

fn dbus_err(msg: impl Into<String>) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(msg.into())
}

fn owned_path(s: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(s).unwrap()
}

fn owned_path_try(s: &str) -> Result<OwnedObjectPath, zbus::fdo::Error> {
    zvariant::ObjectPath::try_from(s)
        .map(Into::into)
        .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("{e}")))
}

// ── helpers ───────────────────────────────────────────────

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

fn keyring_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let data = std::env::var("XDG_DATA_HOME")
        .unwrap_or_else(|_| format!("{home}/.local/share"));
    Some(std::path::PathBuf::from(data).join("vasak-keyring").join("keyring.db"))
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
/// Falls back to the `VASAK_KEYRING_PASSWORD` environment variable for
/// headless/testing scenarios only. The old plaintext
/// `~/.config/vasak-keyring/master.key` file is deliberately NOT read: keeping
/// the key next to the encrypted database defeats the encryption entirely.
fn master_password() -> Option<Zeroizing<String>> {
    if let Ok(guard) = master_store().lock() {
        if let Some(pw) = guard.as_ref() {
            return Some(pw.clone());
        }
    }
    std::env::var("VASAK_KEYRING_PASSWORD").ok().map(Zeroizing::new)
}

/// Message shown when the keyring cannot be written because it was never
/// unlocked. Checked before a write mutates anything, so a rejected store
/// leaves no half-created item behind that a later lookup would find.
const LOCKED_MESSAGE: &str = "el llavero está bloqueado: no hay contraseña maestra en memoria. \
     Se establece al iniciar sesión mediante pam_vasak_keyring; \
     si el demonio se reinició, hay que volver a iniciar sesión.";

fn ensure_unlocked() -> Result<(), zbus::fdo::Error> {
    match master_password() {
        Some(_) => Ok(()),
        None => Err(dbus_err(LOCKED_MESSAGE)),
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

    write_atomically(&path, &data)
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
        self.state.lock().await
            .items.get(&self.path)
            .map(|i| i.label.clone())
            .ok_or_else(|| dbus_err("item not found"))
    }

    #[zbus(property)]
    async fn attributes(&self) -> Result<HashMap<String, String>, zbus::fdo::Error> {
        self.state.lock().await
            .items.get(&self.path)
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
        self.state.lock().await
            .items.get(&self.path)
            .map(|i| i.created)
            .ok_or_else(|| dbus_err("item not found"))
    }

    #[zbus(property)]
    async fn modified(&self) -> Result<u64, zbus::fdo::Error> {
        self.state.lock().await
            .items.get(&self.path)
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
        if state.collections.values().any(|c| effectively_locked(c.locked) && c.items.contains(&self.path)) {
            return Err(dbus_err("collection is locked"));
        }
        let item = state.items.get(&self.path)
            .ok_or_else(|| dbus_err("item not found"))?;
        let ses = state.sessions.get(session.as_str())
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
        ensure_unlocked()?;

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
            state.collections.iter()
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
        self.state.lock().await
            .collections.get(&self.path)
            .map(|c| c.label.clone())
            .ok_or_else(|| dbus_err("collection not found"))
    }

    #[zbus(property)]
    async fn locked(&self) -> Result<bool, zbus::fdo::Error> {
        self.state.lock().await
            .collections.get(&self.path)
            .map(|c| effectively_locked(c.locked))
            .ok_or_else(|| dbus_err("collection not found"))
    }

    #[zbus(property)]
    async fn created(&self) -> Result<u64, zbus::fdo::Error> {
        self.state.lock().await
            .collections.get(&self.path)
            .map(|c| c.created)
            .ok_or_else(|| dbus_err("collection not found"))
    }

    #[zbus(property)]
    async fn modified(&self) -> Result<u64, zbus::fdo::Error> {
        self.state.lock().await
            .collections.get(&self.path)
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
                    if attributes.iter().all(|(k, v)| item.attributes.get(k) == Some(v)) {
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
        ensure_unlocked()?;

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
                let col = state.collections.get(&self.path)
                    .ok_or_else(|| dbus_err("collection not found"))?;
                col.items
                    .iter()
                    .filter(|ip| {
                        state.items.get(*ip).is_some_and(|item| {
                            item.attributes == attributes
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
        self.conn.object_server().at(item_path.clone(), iface).await
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
        self.spawn_collection("/org/freedesktop/secrets/collection/login",
            "login", "Default collection").await
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
    async fn publish_alias(&self, alias: &str, collection_path: &str)
        -> Result<(), zbus::fdo::Error>
    {
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

    async fn spawn_collection(&self, path: &str, alias: &str, label: &str)
        -> Result<(), zbus::fdo::Error>
    {
        let mut loaded: Vec<ItemInfo> = Vec::new();
        if let Some(db_path) = keyring_path() {
            if db_path.exists() {
                if let Ok(raw) = std::fs::read(&db_path) {
                    if let Some(pwd) = master_password() {
                        match crypto::decrypt_database(&raw, pwd.as_str()) {
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
                            }
                            Err(e) => {
                                eprintln!("[vasak-keyring] cannot decrypt keyring.db: {e}");
                            }
                        }
                    } else {
                        eprintln!("[vasak-keyring] no master password available");
                    }
                }
            }
        }

        let mut state = self.state.lock().await;
        let col_info = CollectionInfo {
            label: label.to_string(),
            locked: false,
            items: vec![],
            created: now(),
            modified: now(),
        };
        state.collections.insert(path.to_string(), col_info);
        state.aliases.insert(alias.to_string(), path.to_string());
        // The login collection is the default keyring; libsecret resolves the
        // "default" alias when storing/looking up passwords.
        if alias == "login" {
            state.aliases.insert("default".to_string(), path.to_string());
        }

        let mut item_paths = Vec::new();
        for si in loaded {
            let ip = format!("{path}/items/{}", state.take_item_id());
            state.items.insert(ip.clone(), si);
            item_paths.push(ip);
        }

        let col = state.collections.get_mut(path).unwrap();
        col.items = item_paths.clone();

        // Register item interfaces
        for ip in &item_paths {
            let iface = ItemInterface {
                state: self.state.clone(),
                conn: self.conn.clone(),
                path: ip.clone(),
            };
            self.conn.object_server().at(ip.clone(), iface).await
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
        self.conn.object_server().at(path.to_string(), iface).await
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
    async fn collection_created(emitter: &SignalEmitter<'_>, collection: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_deleted(emitter: &SignalEmitter<'_>, collection: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_changed(emitter: &SignalEmitter<'_>, collection: OwnedObjectPath) -> zbus::Result<()>;

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
        self.conn.object_server().at(path.clone(), iface).await
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
                    if attributes.iter().all(|(k, v)| item.attributes.get(k) == Some(v)) {
                        let o = owned_path_try(ip).unwrap_or_else(|_| owned_path("/"));
                        if effectively_locked(col.locked) { locked.push(o) } else { unlocked.push(o) }
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
                state.aliases.insert(alias.to_string(), collection.as_str().to_string());
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
            if state.collections.values().any(|c| effectively_locked(c.locked) && c.items.iter().any(|p| p == ip_str)) {
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
            .args(["--user", "--wait", "--collect", "--quiet", "--pipe", PROMPTER])
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
            let _ = iface.get().await.locked_changed(iface.signal_emitter()).await;
        }

        for ip in item_paths {
            if let Ok(iface) = server.interface::<_, ItemInterface>(ip.as_str()).await {
                let _ = iface.get().await.locked_changed(iface.signal_emitter()).await;
            }
        }
    }
}

#[interface(name = "org.vasak.Keyring")]
impl PamUnlockInterface {
    async fn unlock(&mut self, password: &str) -> Result<bool, zbus::fdo::Error> {
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

        // Decrypt the existing DB, or start empty on a fresh system. In both
        // cases the login password becomes the in-memory master, so the first
        // stored secret can create/persist the database. A wrong password for
        // an existing DB is rejected and NOT adopted.
        let db = if path.exists() {
            let raw = std::fs::read(&path).map_err(|e| dbus_err(format!("{e}")))?;
            match crypto::decrypt_database(&raw, password) {
                Ok(db) => db,
                Err(_) => {
                    note_failed_unlock();
                    return Ok(false);
                }
            }
        } else {
            crypto::KeyringDatabase { items: vec![] }
        };

        set_master_password(password);
        note_successful_unlock();

        let coll_path = "/org/freedesktop/secrets/collection/login".to_string();
        let item_paths: Vec<String>;
        let stale_paths: Vec<String>;

        {
            let mut state = self.state.lock().await;

            if !state.collections.contains_key(&coll_path) {
                state.collections.insert(coll_path.clone(), CollectionInfo {
                    label: "Default collection".into(),
                    locked: false,
                    items: vec![],
                    created: now(),
                    modified: now(),
                });
            }

            // Unlocking reloads the collection from disk, so whatever it held
            // before is replaced. Item ids are never reused now, so the old
            // paths have to be dropped explicitly or they linger on the bus as
            // duplicates that no longer belong to any collection.
            stale_paths = state
                .collections
                .get(&coll_path)
                .map(|col| col.items.clone())
                .unwrap_or_default();
            for ip in &stale_paths {
                state.items.remove(ip);
            }

            let mut paths = Vec::new();
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
                paths.push(ip);
            }

            if let Some(col) = state.collections.get_mut(&coll_path) {
                col.items = paths.clone();
            }
            item_paths = paths;
        }

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
            self.conn.object_server().at(ip.clone(), iface).await
                .map(|_| ())
                .map_err(|e| dbus_err(format!("{e}")))?;
        }

        let iface = CollectionInterface {
            state: self.state.clone(),
            conn: self.conn.clone(),
            path: coll_path.clone(),
            alias: "login".into(),
        };
        self.conn.object_server().at(coll_path.clone(), iface).await
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
