# vasak-keyring

Llavero nativo de VasakOS. Reemplazo de `gnome-keyring` con cifrado AES-256-GCM y derivación de clave Argon2id.

## Qué no abre

Como todo Secret Service estándar, este llavero entrega los secretos a
cualquier proceso que corra como la persona. El cifrado protege **en reposo**:
un disco robado, una copia de seguridad, la computadora de otra persona. No
protege contra un programa que corre en la misma sesión.

Para lo que sí hace falta una frontera —la clave del almacén cifrado de
`vasak-accounts`— hay un control por ítem. Los ítems marcados con
`xdg:schema = "ar.net.vasak.os.AccountsStore"` sólo los toca
`/usr/bin/vasak-accounts-sync`: leer su secreto, reemplazarlo (`SetSecret`, o
`CreateItem` con `replace`), crear otro con ese esquema, borrarlo o borrar la
colección que lo tiene, y hasta describirlo (`Attributes`, `Label`). A los demás
les responde `org.freedesktop.DBus.Error.AccessDenied`, y `SearchItems` no se
los muestra. Proteger sólo la lectura no alcanzaba: con las escrituras, un
proceso cualquiera **elegía** la clave con la que se abre la base.

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

### Los secretos del portal

El secreto maestro que el backend del portal (`org.freedesktop.impl.portal.Secret`)
le da a cada aplicación vive en la colección del login con
`xdg:schema = "org.freedesktop.portal.Secret"`. Ese esquema es del demonio: el
backend corre adentro y lee el estado directo, así que **desde el bus no lo toca
nadie**, sin excepción —tampoco el sincronizador—. Un `CreateItem` con ese
esquema (con `replace` o sin él), `SetSecret`, `GetSecret`, `Delete`, y leer
`Label`, `Attributes`, `Created`, `Modified` o `Locked` responden
`AccessDenied`; borrar una colección que tenga alguno, también. Y para el bus
esos ítems no existen: no se publican como objetos, no aparecen en `Items` ni en
`SearchItems`, y `GetSecrets` los omite. Antes (hasta 0.7.8) cualquier proceso
podía plantar el secreto de una aplicación antes de que lo pidiera, cambiárselo
o leerlo.

La reserva compara sólo letras y dígitos, sin mayúsculas: `XDG:Schema`,
`Org.Freedesktop.Portal.Secret`, un espacio o un carácter invisible en el medio
siguen siendo el esquema del portal, y tampoco se puede crear nada con el
atributo `vasak-keyring:origin`. La búsqueda del backend, en cambio, es exacta,
así que la reserva siempre cubre todo lo que el backend puede encontrar.

**Los secretos de antes de 0.7.9 no se entregan.** Mientras el esquema estuvo
abierto, uno plantado no se distingue de uno legítimo. Desde 0.7.9 el demonio
marca los que crea con `vasak-keyring:origin = portal-backend`, que ningún
cliente del bus puede poner, y sólo entrega ésos. La marca sola no alcanza —un
demonio de antes no la reservaba, así que también se pudo plantar—, y por eso la
base lleva un campo `format`: la que escribe 0.7.9 o posterior dice `1`, y en
una sin el campo (la de un demonio de antes, o una que un demonio de antes volvió
a guardar después de un retroceso de versión) la marca se quita al cargar. Una
aplicación que tenía un
secreto de antes recibe uno nuevo la próxima vez que lo pide —y deja de abrir lo
que hubiera cifrado con el anterior—, y el diario lo dice. El de antes queda en
la base sin usarse. En VasakOS el portal Secret lo usan sólo las aplicaciones en
sandbox, que el sistema no trae, así que en la práctica no hay nada que perder.

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
