use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretItem {
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secret: Vec<u8>,
}

/// `Debug` a propósito, y no el que sale de derivarlo.
///
/// Esta estructura guarda los secretos en claro —en memoria, hasta que la base
/// entera se cifra— y el `Debug` derivado los imprime completos en cuanto
/// alguien escriba un `{:?}` al lado. No hace falta que hoy exista ese `{:?}`:
/// basta con un `unwrap()`, un `expect` o un `assert_eq!` de una prueba nueva
/// para que el diario del demonio —o la salida de la prueba— contenga todas las
/// contraseñas guardadas de la persona que está mirando.
///
/// Acá van la etiqueta y los atributos, que es lo que uno lee para diagnosticar
/// («¿qué ítem es el que no descifra?»), y el secreto no aparece: ni como texto,
/// ni en hexadecimal, ni como bytes sueltos.
///
/// Y `Zeroize` no alcanza para esto, porque limpia la memoria cuando el valor
/// cae, mientras que esto es lo que se imprime **antes** de que eso pase.
impl std::fmt::Debug for SecretItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretItem")
            .field("label", &self.label)
            .field("attributes", &self.attributes)
            .field("secret", &"<oculto>")
            .finish()
    }
}

impl Zeroize for SecretItem {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.label.zeroize();
        for (mut k, mut v) in self.attributes.drain() {
            k.zeroize();
            v.zeroize();
        }
    }
}

impl Drop for SecretItem {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyringDatabase {
    pub items: Vec<SecretItem>,
}

impl Zeroize for KeyringDatabase {
    fn zeroize(&mut self) {
        for item in &mut self.items {
            item.zeroize();
        }
        self.items.clear();
    }
}

impl Drop for KeyringDatabase {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;
    Ok(key)
}

pub fn encrypt_database(db: &KeyringDatabase, master_password: &str) -> Result<Vec<u8>, String> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(db).map_err(|e| format!("Serialization failed: {}", e))?);

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(master_password, &salt)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| "Encryption failed".to_string())?;

    let mut output = Vec::with_capacity(16 + 12 + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

pub fn decrypt_database(
    encrypted_data: &[u8],
    master_password: &str,
) -> Result<KeyringDatabase, String> {
    if encrypted_data.len() < 28 {
        return Err("Invalid encrypted data: too short".to_string());
    }

    let (salt, rest) = encrypted_data.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let key = derive_key(master_password, salt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed: wrong password or corrupted data".to_string())?,
    );

    let db: KeyringDatabase =
        serde_json::from_slice(&plaintext).map_err(|e| format!("Deserialization failed: {}", e))?;

    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un secreto guardado en claro no puede llegar a una cadena de formato.
    ///
    /// No se prueba que hoy nadie lo imprima —eso lo dice una búsqueda en el
    /// archivo, y las búsquedas se quedan viejas—, sino que la puerta está
    /// cerrada: el `Debug` de un ítem no lleva el secreto, ni como texto ni
    /// desarmado en los bytes de un `Vec<u8>`.
    #[test]
    fn el_secreto_no_aparece_en_el_debug_de_un_item() {
        let item = SecretItem {
            label: "wifi de casa".into(),
            attributes: HashMap::from([(
                "xdg:schema".to_string(),
                "org.freedesktop.Secret.Generic".to_string(),
            )]),
            secret: b"hunter2-secreto".to_vec(),
        };

        let impreso = format!("{item:?}");

        assert!(
            !impreso.contains("hunter2"),
            "el secreto no puede aparecer en el Debug: {impreso}"
        );
        // Los bytes sueltos son el mismo secreto con otra ropa: `Vec<u8>` se
        // imprime como `104, 117, 110, ...` y eso también es la contraseña.
        assert!(
            !impreso.contains("104, 117, 110"),
            "ni los bytes del secreto: {impreso}"
        );
        // Y que no sea un `Debug` inútil: la etiqueta es lo que hace falta para
        // saber de qué ítem se está hablando.
        assert!(
            impreso.contains("wifi de casa"),
            "la etiqueta tiene que estar: {impreso}"
        );
    }

    /// Lo mismo para la base entera, que es la que se acabaría volcando cuando
    /// algo falla más arriba y no se sabe cuál de los ítems es el que no
    /// descifra.
    #[test]
    fn la_base_entera_tampoco_se_imprime() {
        let db = KeyringDatabase {
            items: vec![SecretItem {
                label: "correo".into(),
                attributes: HashMap::new(),
                secret: b"otra-secreta-distinta".to_vec(),
            }],
        };

        let impresa = format!("{db:?}");

        assert!(
            !impresa.contains("otra-secreta-distinta"),
            "el secreto no puede aparecer en el Debug de la base: {impresa}"
        );
        // Con el `Debug` derivado, un `Vec<u8>` se imprime como bytes: el texto
        // de arriba no aparecería nunca y esta prueba seguiría en verde sin
        // mirar nada. Lo que hay que mirar son los bytes.
        assert!(
            !impresa.contains("111, 116, 114, 97"),
            "ni los bytes del secreto: {impresa}"
        );
        assert!(
            impresa.contains("correo"),
            "la etiqueta tiene que estar: {impresa}"
        );
    }
}
