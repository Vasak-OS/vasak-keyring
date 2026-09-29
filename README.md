# vasak-keyring

Llavero nativo de VasakOS. Reemplazo de `gnome-keyring` con cifrado AES-256-GCM y derivación de clave Argon2id.

## Qué no abre

Como todo Secret Service estándar, este llavero entrega los secretos a
cualquier proceso que corra como la persona. El cifrado protege **en reposo**:
un disco robado, una copia de seguridad, la computadora de otra persona. No
protege contra un programa que corre en la misma sesión.

Para lo que sí hace falta una frontera —la clave del almacén cifrado de
`vasak-accounts`— hay un control por ítem. Los ítems marcados con
`xdg:schema = "ar.net.vasak.os.AccountsStore"` sólo se entregan a
`/usr/bin/vasak-accounts-sync`, identificado por el ejecutable del proceso que
pregunta y no por el nombre de la conexión, que es lo único que el llamador no
puede firmar. A los demás les responde `org.freedesktop.DBus.Error.AccessDenied`.

El control es **por ítem**: el resto de los secretos se sigue entregando
normalmente, que es lo que necesitan el navegador, el cliente de correo y el
resto del escritorio.

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
