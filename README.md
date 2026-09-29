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
`/usr/bin/vasak-accounts-sync`. A los demás les responde
`org.freedesktop.DBus.Error.AccessDenied`.

La identidad sale de `/proc/<pid>/exe`, del PID que el **demonio del bus**
asoció a la conexión del remitente. No del nombre de la conexión, que se lo
elige el llamador y por lo tanto no prueba nada. El PID tampoco lo manda el
cliente: el demonio lo saca de `SO_PEERCRED` al autenticar, y ese vínculo queda
fijado durante toda la vida de la conexión.

El control es **por ítem**: el resto de los secretos se sigue entregando
normalmente, que es lo que necesitan el navegador, el cliente de correo y el
resto del escritorio.

### Qué no garantiza

El control autentica **el binario, no a la persona que lo ejecuta**. Por lo
tanto:

- **Un proceso del mismo UID puede quedarse con una conexión D-Bus heredada**
  del sincronizador —por ejemplo, si el código del sincronizador se la pasa a
  otro proceso— y usarla. El PID que devuelve el bus sigue siendo el del
  proceso que abrió la conexión, no el del que escribe el mensaje.
- **Código inyectado dentro del propio sincronizador** —`LD_PRELOAD`, un
  `ptrace`, un binario troyanizado— pasa el control, porque para entonces ya
  corre dentro del proceso autorizado.

Nada de esto se arregla con más comprobaciones sobre `/proc`: para cerrarlas
hace falta que el sincronizador corra bajo un **UID propio** o dentro de un
**namespace o sandbox** del que no pueda salir código del resto de la sesión.
Mientras no sea así, esto es un control contra los programas de la sesión —un
navegador, un script, un `.desktop` mal puesto—, y no contra alguien que ya
consiga ejecutar código como el sincronizador. Lo mismo que en
`vasak-permissions`, y que ya pasaba con el control del portal.

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
