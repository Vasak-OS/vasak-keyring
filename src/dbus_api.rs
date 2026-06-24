use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use zbus::{interface, Connection};
use zbus::zvariant::{self, OwnedObjectPath, OwnedValue, Value, Type};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::crypto;

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

fn master_password() -> Option<String> {
    if let Ok(pwd) = std::env::var("VASAK_KEYRING_PASSWORD") {
        return Some(pwd);
    }
    let home = std::env::var("HOME").ok()?;
    let cfg = std::env::var("XDG_CONFIG_HOME")
        .unwrap_or_else(|_| format!("{home}/.config"));
    let key_file = std::path::PathBuf::from(cfg).join("vasak-keyring").join("master.key");
    if key_file.exists() {
        return std::fs::read_to_string(&key_file).ok();
    }
    None
}

fn save_db(items: &[ItemInfo]) {
    let path = match keyring_path() { Some(p) => p, None => return };
    let pwd = match master_password() { Some(p) => p, None => return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
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
    match crypto::encrypt_database(&db, &pwd) {
        Ok(data) => {
            if let Err(e) = std::fs::write(&path, &data) {
                eprintln!("[vasak-keyring] write keyring.db failed: {e}");
            }
        }
        Err(e) => eprintln!("[vasak-keyring] encrypt failed: {e}"),
    }
}

// ── DH 1024 (Oakley Group 2, RFC 2409) ────────────────────

const DH_1024_PRIME: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
];

// ── shared state ──────────────────────────────────────────

struct SessionInfo {
    algorithm: String,
    shared_key: Option<Vec<u8>>,
    created: u64,
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

struct KeyringState {
    sessions: HashMap<String, SessionInfo>,
    collections: HashMap<String, CollectionInfo>,
    items: HashMap<String, ItemInfo>,
    next_session: u64,
    next_collection: u64,
    next_item: u64,
}

impl KeyringState {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            collections: HashMap::new(),
            items: HashMap::new(),
            next_session: 0,
            next_collection: 0,
            next_item: 0,
        }
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

#[interface(name = "org.freedesktop.Secrets.Session")]
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

#[interface(name = "org.freedesktop.Secrets.Item")]
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
                return Ok(col.locked);
            }
        }
        Ok(false)
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

    async fn get_secret(&self, session: OwnedObjectPath) -> Result<SecretStruct, zbus::fdo::Error> {
        let state = self.state.lock().await;
        let item = state.items.get(&self.path)
            .ok_or_else(|| dbus_err("item not found"))?;
        let ses = state.sessions.get(session.as_str())
            .ok_or_else(|| dbus_err("session not found"))?;

        match ses.algorithm.as_str() {
            "plain" => Ok(SecretStruct {
                session: session.clone(),
                parameters: vec![],
                value: item.secret.clone(),
                content_type: item.content_type.clone(),
            }),
            "dh-ietf1024-sha256" => {
                let key = ses.shared_key.as_deref()
                    .ok_or_else(|| dbus_err("session has no key"))?;
                let mut key32 = [0u8; 32];
                let len = key.len().min(32);
                key32[..len].copy_from_slice(&key[..len]);

                let mut nonce = [0u8; 12];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

                use aes_gcm::aead::{Aead, KeyInit};
                let cipher = aes_gcm::Aes256Gcm::new(
                    aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key32),
                );
                let ctxt = cipher
                    .encrypt(aes_gcm::Nonce::from_slice(&nonce), item.secret.as_ref())
                    .map_err(|_| dbus_err("encryption failed"))?;

                Ok(SecretStruct {
                    session: session.clone(),
                    parameters: nonce.to_vec(),
                    value: ctxt,
                    content_type: item.content_type.clone(),
                })
            }
            a => Err(dbus_err(format!("unknown algorithm: {a}"))),
        }
    }

    async fn set_secret(&mut self, secret: SecretStruct) -> Result<(), zbus::fdo::Error> {
        let mut state = self.state.lock().await;
        if let Some(item) = state.items.get_mut(&self.path) {
            item.secret = secret.value;
            item.content_type = secret.content_type;
            item.modified = now();
            Ok(())
        } else {
            Err(dbus_err("item not found"))
        }
    }

    async fn delete(&mut self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        let mut state = self.state.lock().await;
        state.items.remove(&self.path);
        for col in state.collections.values_mut() {
            col.items.retain(|p| p != &self.path);
        }
        Ok(owned_path("/"))
    }
}

// ── Collection interface ──────────────────────────────────

struct CollectionInterface {
    state: Arc<Mutex<KeyringState>>,
    conn: Connection,
    path: String,
    alias: String,
}

#[interface(name = "org.freedesktop.Secrets.Collection")]
impl CollectionInterface {
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
            .map(|c| c.locked)
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

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), zbus::fdo::Error> {
        let state = self.state.lock().await;
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();

        if let Some(col) = state.collections.get(&self.path) {
            for ip in &col.items {
                if let Some(item) = state.items.get(ip) {
                    if attributes.iter().all(|(k, v)| item.attributes.get(k) == Some(v)) {
                        let o = owned_path_try(ip).unwrap_or_else(|_| owned_path("/"));
                        if col.locked { locked.push(o) } else { unlocked.push(o) }
                    }
                }
            }
        }
        Ok((unlocked, locked))
    }

    async fn create_item(
        &mut self,
        properties: HashMap<String, Value<'_>>,
        secret: SecretStruct,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), zbus::fdo::Error> {
        let label = properties
            .get("org.freedesktop.Secrets.Item.Label")
            .and_then(value_to_string)
            .unwrap_or_else(|| "Unnamed".to_string());

        let attributes = properties
            .get("org.freedesktop.Secrets.Item.Attributes")
            .and_then(value_to_attrmap)
            .unwrap_or_default();

        let mut state = self.state.lock().await;

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

        let id = state.next_item;
        state.next_item += 1;
        let item_path = format!("{}/items/{id}", self.path);

        let info = ItemInfo {
            label,
            attributes,
            secret: secret.value,
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

        self.persist().await;

        Ok((owned, owned_path("/")))
    }

    async fn delete(&mut self) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        let mut state = self.state.lock().await;
        if let Some(col) = state.collections.remove(&self.path) {
            for ip in &col.items {
                state.items.remove(ip);
            }
        }
        Ok(owned_path("/"))
    }
}

impl CollectionInterface {
    async fn persist(&self) {
        let state = self.state.lock().await;
        let mut all = Vec::new();
        if let Some(col) = state.collections.get(&self.path) {
            for ip in &col.items {
                if let Some(info) = state.items.get(ip) {
                    all.push(info.clone());
                }
            }
        }
        drop(state);
        save_db(&all);
    }
}

// ── Service (root) interface ───────────────────────────────

pub struct ServiceInterface {
    state: Arc<Mutex<KeyringState>>,
    conn: Connection,
}

impl ServiceInterface {
    pub fn new(conn: Connection) -> Self {
        Self {
            state: Arc::new(Mutex::new(KeyringState::new())),
            conn,
        }
    }

    pub async fn register_default_collection(&self) -> Result<(), zbus::fdo::Error> {
        self.spawn_collection("/org/freedesktop/secrets/collection/login",
            "login", "Default collection").await
    }

    async fn spawn_collection(&self, path: &str, alias: &str, label: &str)
        -> Result<(), zbus::fdo::Error>
    {
        let mut loaded: Vec<ItemInfo> = Vec::new();
        if let Some(db_path) = keyring_path() {
            if db_path.exists() {
                if let Ok(raw) = std::fs::read(&db_path) {
                    if let Some(pwd) = master_password() {
                        match crypto::decrypt_database(&raw, &pwd) {
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

        let mut item_paths = Vec::new();
        for (i, si) in loaded.into_iter().enumerate() {
            let ip = format!("{path}/items/{i}");
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
            .map_err(|e| dbus_err(format!("{e}")))
    }
}

#[interface(name = "org.freedesktop.Secrets")]
impl ServiceInterface {
    async fn open_session(
        &mut self,
        algorithm: &str,
        input: Value<'_>,
    ) -> Result<(OwnedValue, OwnedObjectPath), zbus::fdo::Error> {
        match algorithm {
            "plain" => {
                let mut state = self.state.lock().await;
                let id = state.next_session;
                state.next_session += 1;
                let path = format!("/org/freedesktop/secrets/session/s{id}");

                state.sessions.insert(path.clone(), SessionInfo {
                    algorithm: "plain".into(),
                    shared_key: None,
                    created: now(),
                });
                drop(state);

                let iface = SessionInterface {
                    state: self.state.clone(),
                    path: path.clone(),
                };
                self.conn.object_server().at(path.clone(), iface).await
                    .map(|_| ())
                    .map_err(|e| dbus_err(format!("{e}")))?;

                let owned_path = owned_path_try(&path)?;
                Ok((u8_array_value(vec![]), owned_path))
            }

            "dh-ietf1024-sha256" => {
                let client_pub = extract_bytes(&input)?;

                let p = num_bigint::BigUint::from_bytes_be(&DH_1024_PRIME);
                let g = num_bigint::BigUint::from(2u64);
                let client_val = num_bigint::BigUint::from_bytes_be(&client_pub);

                let mut priv_bytes = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut priv_bytes);
                let server_priv = num_bigint::BigUint::from_bytes_be(&priv_bytes);

                let server_pub = g.modpow(&server_priv, &p);
                let shared = client_val.modpow(&server_priv, &p);

                let session_key = {
                    let raw = shared.to_bytes_be();
                    use sha2::Digest;
                    let mut h = sha2::Sha256::new();
                    h.update(&raw);
                    h.finalize().to_vec()
                };

                let mut state = self.state.lock().await;
                let id = state.next_session;
                state.next_session += 1;
                let path = format!("/org/freedesktop/secrets/session/s{id}");

                state.sessions.insert(path.clone(), SessionInfo {
                    algorithm: "dh-ietf1024-sha256".into(),
                    shared_key: Some(session_key),
                    created: now(),
                });
                drop(state);

                let iface = SessionInterface {
                    state: self.state.clone(),
                    path: path.clone(),
                };
                self.conn.object_server().at(path.clone(), iface).await
                    .map(|_| ())
                    .map_err(|e| dbus_err(format!("{e}")))?;

                let owned_path = owned_path_try(&path)?;
                Ok((u8_array_value(server_pub.to_bytes_be()), owned_path))
            }

            other => Err(dbus_err(format!("unsupported algorithm: {other}"))),
        }
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
            .get("org.freedesktop.Secrets.Collection.Label")
            .and_then(value_to_string)
            .unwrap_or_else(|| alias.to_string());

        let path = format!("/org/freedesktop/secrets/collection/{alias}");
        self.spawn_collection(&path, alias, &label).await?;

        let owned = owned_path_try(&path)?;
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
                        if col.locked { locked.push(o) } else { unlocked.push(o) }
                    }
                }
            }
        }
        Ok((unlocked, locked))
    }

    async fn read_alias(&self, alias: &str) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        let state = self.state.lock().await;
        let p = format!("/org/freedesktop/secrets/collection/{alias}");
        if state.collections.contains_key(&p) {
            owned_path_try(&p)
        } else {
            Ok(owned_path("/"))
        }
    }

    async fn set_alias(
        &mut self,
        _alias: &str,
        collection: OwnedObjectPath,
    ) -> Result<OwnedObjectPath, zbus::fdo::Error> {
        if collection.as_str() == "/" {
            return Ok(owned_path("/"));
        }
        let state = self.state.lock().await;
        if state.collections.contains_key(collection.as_str()) {
            Ok(owned_path("/"))
        } else {
            Err(dbus_err("collection not found"))
        }
    }

    async fn unlock(
        &mut self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), zbus::fdo::Error> {
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
    ) -> Result<HashMap<String, SecretStruct>, zbus::fdo::Error> {
        let state = self.state.lock().await;
        let mut result = HashMap::new();
        for ip in &items {
            if let Some(item) = state.items.get(ip.as_str()) {
                if let Some(ses) = state.sessions.get(session.as_str()) {
                    let secret = match ses.algorithm.as_str() {
                        "plain" => SecretStruct {
                            session: session.clone(),
                            parameters: vec![],
                            value: item.secret.clone(),
                            content_type: item.content_type.clone(),
                        },
                        _ => continue,
                    };
                    result.insert(ip.as_str().to_string(), secret);
                }
            }
        }
        Ok(result)
    }
}
