# vasak-keyring

Llavero nativo de VasakOS. Reemplazo de `gnome-keyring` con cifrado AES-256-GCM y derivación de clave Argon2id.

## Uso

```rust
use crypto::{KeyringDatabase, SecretItem, encrypt_database, decrypt_database};

let mut db = KeyringDatabase { items: vec![] };
db.items.push(SecretItem {
    label: "mi-secreto".into(),
    attributes: [("servicio".into(), "api".into())].into(),
    secret: b"token".to_vec(),
});

let cifrado = encrypt_database(&db, "contraseña-maestra").unwrap();
let descifrado = decrypt_database(&cifrado, "contraseña-maestra").unwrap();
```

## Dependencias

- `aes-gcm` — cifrado simétrico AES-256-GCM
- `argon2` — derivación de clave (Argon2id)
- `zeroize` — limpieza de memoria sensible en RAM
- `serde` / `serde_json` — serialización de la base de datos
