use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretItem {
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secret: Vec<u8>,
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
    let plaintext = Zeroizing::new(
        serde_json::to_vec(db).map_err(|e| format!("Serialization failed: {}", e))?
    );

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

pub fn decrypt_database(encrypted_data: &[u8], master_password: &str) -> Result<KeyringDatabase, String> {
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
            .map_err(|_| "Decryption failed: wrong password or corrupted data".to_string())?
    );

    let db: KeyringDatabase = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Deserialization failed: {}", e))?;

    Ok(db)
}
