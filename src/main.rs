mod crypto;

use crypto::{decrypt_database, encrypt_database, KeyringDatabase, SecretItem};
use std::collections::HashMap;

fn main() {
    println!("=== VasakOS Keyring - Demo de Cifrado ===\n");

    let mut db = KeyringDatabase {
        items: Vec::new(),
    };

    let mut attrs = HashMap::new();
    attrs.insert("service".into(), "github.com".into());
    attrs.insert("username".into(), "vasak-user".into());

    let item = SecretItem {
        label: "GitHub Token".into(),
        attributes: attrs,
        secret: b"ghp_fakeToken12345abcdefghijklmnopqrstuv".to_vec(),
    };

    db.items.push(item);

    println!("[+] Llavero creado con {} secreto(s).", db.items.len());
    println!("    label ..: {}", db.items[0].label);
    println!("    secret .: ({} bytes protegidos)\n", db.items[0].secret.len());

    let password = "MiClaveMaestraSuperSegura2026!";
    let encrypted = encrypt_database(&db, password).expect("Error al cifrar");

    println!("[+] Cifrado exitoso ({} bytes en disco).\n", encrypted.len());

    let decrypted = decrypt_database(&encrypted, password).expect("Error al descifrar");

    println!("[+] Descifrado con contraseña CORRECTA:");
    println!("    label .: {}", decrypted.items[0].label);
    println!("    secret : {} (hex)", hex::encode(&decrypted.items[0].secret));

    drop(decrypted);

    println!();

    match decrypt_database(&encrypted, "ContraseñaIncorrecta") {
        Ok(_) => println!("[-] ERROR: descifrado con contraseña incorrecta"),
        Err(e) => println!("[+] Fallo esperado con contraseña incorrecta: {}", e),
    }

    println!("\n=== Fin de la demostración ===");
}
