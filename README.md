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
asoció a la conexión del remitente. El PID no lo manda el cliente: el demonio lo
saca de `SO_PEERCRED` al autenticar, y ese vínculo queda fijado durante toda la
vida de la conexión.

Además, la conexión que pide tiene que ser la dueña de
`ar.net.vasak.os.AccountsSync` en el bus. Eso solo no prueba nada —un nombre
lo toma cualquiera que llegue primero, y con el servicio `disabled` casi siempre
está libre—, así que se exigen las dos cosas: el nombre y el ejecutable. El
control del portal (`RetrieveSecret`) funciona igual, con
`org.freedesktop.portal.Desktop` y `/usr/lib/xdg-desktop-portal`.

Para leer `/proc/<pid>/exe` de otro proceso de la sesión, el demonio **no puede
correr en un namespace de usuario propio**, y en una unidad de usuario de
systemd lo crea cualquiera de `PrivateTmp`, `PrivateDevices`, `ProtectSystem`,
`ProtectHome`, `ProtectHostname`, `ProtectClock`, `ProtectControlGroups` o los
`ProtectKernel*` (medido con systemd 261: `systemd-run --user -p <opción>=yes
readlink /proc/<pid>/exe` da `EACCES` con cada una, y `/proc/self/ns/user` sale
distinto del de la sesión). Desde el 3/09 la unidad tenía varias: la lectura daba
`EACCES`, y tanto este control como el del portal rechazaban a todo el mundo,
también al sincronizador y al portal de verdad. Por eso `vasak-keyring.service`
no las tiene, y una prueba (`la_unidad_deja_leer_quien_pide`) falla si vuelven.
El aislamiento que queda —sin red, `NoNewPrivileges`, filtro de llamadas al
sistema, `MemoryDenyWriteExecute`, `RestrictNamespaces`— no crea namespaces.

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
