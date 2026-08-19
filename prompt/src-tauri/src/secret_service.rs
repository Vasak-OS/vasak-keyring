//! Talking to the keyring as a client.
//!
//! The daemon in this repository is the other end of this conversation, but
//! nothing here assumes that: it is the plain Secret Service protocol, so the
//! passphrase we store is the same item gcr's ssh-agent would have stored and
//! looks the same to anything else that reads the keyring.
//!
//! That interoperability is the reason for the attribute names below. GNOME's
//! ssh agent files a key's passphrase under `unique = ssh-store:<path>`, and
//! using anything else would mean the same passphrase saved twice, once per
//! desktop, with no way to tell which one is current.

use std::collections::HashMap;

use futures_util::StreamExt;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

const SERVICE: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
const PROMPT_IFACE: &str = "org.freedesktop.Secret.Prompt";
const LOGIN_COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
/// Cuánto se espera a que alguien conteste el diálogo del llavero. Del otro
/// lado hay un ssh detenido, así que la espera no puede ser eterna.
const PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// El llavero de la sesión, que es el que abre PAM al iniciar sesión.
const DEFAULT_COLLECTION: &str = "/org/freedesktop/secrets/aliases/default";

/// Cómo archiva gcr la frase de una clave SSH, y por lo tanto cómo la
/// archivamos nosotros.
fn attributes(key_path: &str) -> HashMap<String, String> {
    HashMap::from([
        ("unique".to_string(), format!("ssh-store:{key_path}")),
        (
            "xdg:schema".to_string(),
            "org.freedesktop.Secret.Generic".to_string(),
        ),
    ])
}

/// A conversation with the keyring, with its session already open.
pub struct Keyring {
    connection: zbus::Connection,
    session: OwnedObjectPath,
}

impl Keyring {
    pub async fn open() -> Result<Self, String> {
        let connection = zbus::Connection::session()
            .await
            .map_err(|e| format!("no hay bus de sesión: {e}"))?;

        // «plain»: el secreto viaja por el bus tal cual. Es el mismo bus de la
        // sesión, al que sólo llega quien ya es esta persona; cifrarlo con una
        // clave negociada por el mismo canal no agregaría nada acá.
        let empty = Value::new("");
        let reply = connection
            .call_method(
                Some(SERVICE),
                SERVICE_PATH,
                Some(SERVICE_IFACE),
                "OpenSession",
                &("plain", &empty),
            )
            .await
            .map_err(|e| format!("el llavero no abrió la sesión: {e}"))?;

        let (_output, session): (OwnedValue, OwnedObjectPath) = reply
            .body()
            .deserialize()
            .map_err(|e| format!("respuesta inesperada del llavero: {e}"))?;

        Ok(Self {
            connection,
            session,
        })
    }

    /// The stored passphrase for a key, if there is one.
    pub async fn passphrase_for(&self, key_path: &str) -> Result<Option<Zeroizing<String>>, String> {
        let reply = self
            .connection
            .call_method(
                Some(SERVICE),
                SERVICE_PATH,
                Some(SERVICE_IFACE),
                "SearchItems",
                &(attributes(key_path),),
            )
            .await
            .map_err(|e| format!("la búsqueda falló: {e}"))?;

        let (unlocked, _locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = reply
            .body()
            .deserialize()
            .map_err(|e| format!("respuesta inesperada de la búsqueda: {e}"))?;

        // Si la frase está pero el llavero está cerrado, lo que corresponde es
        // abrirlo: pedir de nuevo una frase que ya está guardada es justamente
        // lo que esto vino a evitar. El diálogo lo muestra el llavero.
        let item = match unlocked.first() {
            Some(item) => item.clone(),
            None => {
                let Some(locked) = _locked.first() else {
                    return Ok(None);
                };
                if !self.unlock().await? {
                    return Ok(None);
                }
                locked.clone()
            }
        };
        let item = &item;

        let reply = self
            .connection
            .call_method(
                Some(SERVICE),
                item.as_ref(),
                Some(ITEM_IFACE),
                "GetSecret",
                &(&self.session,),
            )
            .await
            .map_err(|e| format!("no se pudo leer el secreto: {e}"))?;

        let (_session, _parameters, value, _content_type): (
            OwnedObjectPath,
            Vec<u8>,
            Vec<u8>,
            String,
        ) = reply
            .body()
            .deserialize()
            .map_err(|e| format!("respuesta inesperada del secreto: {e}"))?;

        let passphrase = Zeroizing::new(
            String::from_utf8(value).map_err(|_| "el secreto guardado no es texto".to_string())?,
        );

        Ok(Some(passphrase))
    }

    /// Opens the keyring, asking whoever is there if it has to be asked.
    ///
    /// Normally PAM hands the password over at login and this does nothing. It
    /// earns its keep when it did not: a keyring nobody can open is a keyring
    /// that silently forgets everything it is told, which is worse than not
    /// offering to remember at all.
    pub async fn unlock(&self) -> Result<bool, String> {
        let collection = OwnedObjectPath::try_from(LOGIN_COLLECTION)
            .map_err(|e| format!("ruta de la colección inválida: {e}"))?;

        let reply = self
            .connection
            .call_method(
                Some(SERVICE),
                SERVICE_PATH,
                Some(SERVICE_IFACE),
                "Unlock",
                &(vec![collection],),
            )
            .await
            .map_err(|e| format!("no se pudo pedir el desbloqueo: {e}"))?;

        let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = reply
            .body()
            .deserialize()
            .map_err(|e| format!("respuesta inesperada del desbloqueo: {e}"))?;

        if !unlocked.is_empty() {
            return Ok(true);
        }
        if prompt.as_str() == "/" {
            return Ok(false);
        }

        // La señal se escucha antes de pedir el diálogo: al revés, una respuesta
        // rápida llega antes de que haya quien la escuche y la espera se cuelga
        // hasta el tiempo límite.
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface(PROMPT_IFACE)
            .map_err(|e| format!("{e}"))?
            .member("Completed")
            .map_err(|e| format!("{e}"))?
            .path(prompt.clone())
            .map_err(|e| format!("{e}"))?
            .build();

        let mut completed = zbus::MessageStream::for_match_rule(rule, &self.connection, Some(4))
            .await
            .map_err(|e| format!("no se pudo escuchar el diálogo: {e}"))?;

        self.connection
            .call_method(Some(SERVICE), prompt.as_ref(), Some(PROMPT_IFACE), "Prompt", &(""))
            .await
            .map_err(|e| format!("no se pudo abrir el diálogo: {e}"))?;

        let answer = tokio::time::timeout(PROMPT_TIMEOUT, completed.next())
            .await
            .map_err(|_| "el diálogo del llavero no fue contestado".to_string())?
            .ok_or_else(|| "el llavero cerró el diálogo sin contestar".to_string())?
            .map_err(|e| format!("error escuchando el diálogo: {e}"))?;

        let (dismissed, _result): (bool, OwnedValue) = answer
            .body()
            .deserialize()
            .map_err(|e| format!("respuesta inesperada del diálogo: {e}"))?;

        Ok(!dismissed)
    }

    /// Files a passphrase so it is not asked for again.
    pub async fn remember(&self, key_path: &str, passphrase: &str, label: &str) -> Result<(), String> {
        // Un llavero cerrado acepta el pedido y no guarda nada, así que se abre
        // antes de prometer que la frase queda recordada.
        self.unlock().await?;

        let mut properties: HashMap<&str, Value> = HashMap::new();
        properties.insert("org.freedesktop.Secret.Item.Label", Value::new(label));
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::new(attributes(key_path)),
        );

        let secret = (
            &self.session,
            Vec::<u8>::new(),
            passphrase.as_bytes().to_vec(),
            "text/plain",
        );

        self.connection
            .call_method(
                Some(SERVICE),
                DEFAULT_COLLECTION,
                Some(COLLECTION_IFACE),
                "CreateItem",
                // replace: la frase de una clave es una sola; guardar otra
                // copia dejaría dos y ninguna forma de saber cuál vale.
                &(properties, secret, true),
            )
            .await
            .map_err(|e| format!("no se pudo guardar en el llavero: {e}"))?;

        Ok(())
    }
}
