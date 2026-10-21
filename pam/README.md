# Auto-desbloqueo por PAM

El demonio arranca bloqueado: la contraseña maestra nunca se guarda en disco, se
carga en memoria al iniciar sesión. Quien la entrega es `pam_vasak_keyring.so`,
y para eso el stack de PAM del inicio de sesión tiene que cargarlo.

**Sin esta configuración el llavero no funciona.** El servicio corre, reclama
`org.freedesktop.secrets` y responde, pero toda operación falla porque no tiene
con qué descifrar la base.

## Qué agregar

Desde 0.3.0 **el paquete lo hace solo** al instalarse, y sólo si
`/etc/pam.d/system-login` es el archivo que espera; si no, no lo toca y explica
qué falta. Esto es lo que agrega, y lo que hay que poner a mano en ese caso:

```
auth       optional   pam_vasak_keyring.so     ← después del "auth include system-auth"
password   optional   pam_vasak_keyring.so     ← después del "password include system-auth"
session    optional   pam_vasak_keyring.so     ← al final, después de pam_systemd
```

`system-login` es el stack que comparten greetd (a través de
`system-local-login`) y los inicios por consola, o sea todas las formas de
entrar al sistema.

## Por qué las tres líneas

Hacen falta las tres y en ese orden:

- `auth` corre durante la autenticación y toma con `pam_get_authtok` la
  contraseña que el usuario acaba de escribir, guardándola en el contexto de PAM.
  Va después de `system-auth` porque para entonces la contraseña ya se pidió.
- `password` corre al cambiar la contraseña de la cuenta y re-cifra la base del
  llavero con la nueva, por un segundo socket,
  `/run/user/<uid>/vasak-keyring/rekey.sock`, así el próximo inicio de sesión la
  abre solo y no hay que abrir el llavero con la anterior (vasak-keyring#38). Va
  después de `password include system-auth`, para que corra con la contraseña ya
  cambiada. Lo hace de forma no destructiva: si la base no abre con la anterior,
  no toca nada, y queda para el flujo de recuperación del diálogo. Si el demonio
  del usuario no corre en ese momento, tampoco; no se pierde nada.
- `session` corre al abrir la sesión, recupera esa contraseña del contexto y se
  la pasa al demonio por un socket unix propio,
  `/run/user/<uid>/vasak-keyring/unlock.sock`. Va **al final**, después de
  `pam_systemd`: ese es el módulo que crea `/run/user/<uid>`, y ahí adentro vive
  el socket. Antes de él no hay dónde entregarla.

## Por qué un socket propio y no D-Bus

Esto se hacía por el bus de sesión y **nunca funcionó ni una vez**. El módulo
corre como root, y `dbus-broker` acepta conexiones del dueño del bus y rechaza al
resto —root incluido— durante la autenticación, antes de que exista mensaje
alguno. El módulo veía un error de conexión, lo tomaba por «el demonio todavía no
arrancó», reintentaba tres segundos y se rendía; el mensaje que dejaba en el
diario nombraba dos causas posibles sin distinguirlas, y una de ellas era
imposible.

El socket vive dentro de `/run/user/<uid>`, que es 0700 del usuario, y root entra
igual porque no está sujeto a los permisos. El demonio verifica con `SO_PEERCRED`
que quien entrega sea root: el propio usuario no, porque cualquier programa de
la sesión corre con su uid y, sin base todavía, elegiría la maestra de la nueva.
El usuario desbloquea por D-Bus, desde el diálogo. De paso la contraseña ya no
atraviesa el proceso del broker, y el módulo dejó de cargar zbus y tokio dentro
del gestor de inicio de sesión.

## Lo que viaja no es la contraseña de la cuenta

Ese directorio es **del usuario**, y ahí está el problema: cualquier código
corriendo con su cuenta puede reemplazar por un enlace simbólico el directorio
donde vive el socket y quedarse con lo que root entregue. Con la contraseña en
texto plano eso sería escalada a root —esa contraseña es la de `sudo`—, y por un
proceso sin privilegios.

Así que no se manda la contraseña: se manda `Argon2id(contraseña, sal)`, con la
sal derivada de `/etc/machine-id`. Quien intercepte se lleva la maestra del
llavero y no la contraseña de la cuenta. Eso no le da nada nuevo —cualquier
proceso del usuario ya puede pedirle todos los secretos al Secret Service, que es
para lo que existe— pero deja de poder escalar.

La derivación vive en el crate `vasak-keyring-derivacion` y no copiada en cada
lado, porque hay **dos** caminos que entregan la maestra: el módulo de PAM al
iniciar sesión y el diálogo gráfico cuando la pide a mano. Si derivaran distinto,
la base creada por uno no la abriría el otro, y sin ningún error: la contraseña
simplemente «no sería la correcta». Hay un test con vector fijo para que la
derivación no pueda cambiar sin que se note.

Como defensa adicional, el módulo comprueba antes de conectar que ningún
componente de la ruta sea un enlace (`O_NOFOLLOW`) y que el dueño sea el usuario
del inicio de sesión. Queda una carrera de microsegundos que no se puede cerrar
con esta topología, y por eso no es la defensa principal.

Con `session` sola el módulo no encuentra nada guardado y no hace nada: el
llavero queda bloqueado igual que si no estuviera configurado.

`optional` es deliberado: si el módulo falla, el inicio de sesión sigue. Un error
acá no debe dejar a nadie afuera del sistema.

## Al configurarlo por primera vez

La primera vez que se desbloquea, **la contraseña que reciba el demonio pasa a
ser la contraseña maestra** de una base nueva. De ahí en más tiene que coincidir
en cada inicio de sesión.

Si se cambia la contraseña **con** la línea `password` puesta, el llavero se
re-cifra en el momento y sigue andando. Si se cambia **por fuera de PAM** —o con
el demonio del usuario sin correr— la base queda cifrada con la anterior; el
próximo inicio de sesión lo detecta y el diálogo pide la contraseña anterior
para migrarla (ver vasak-keyring#38). Cambiar `/etc/machine-id` cambia la sal y
también deja la base sin abrir; eso todavía no se cubre.

## Verificación

Después de reiniciar sesión:

```
secret-tool store --label=prueba app prueba   # pide el secreto por stdin
secret-tool lookup app prueba
```

Si devuelve el secreto, el auto-desbloqueo está andando. Si responde que el
llavero está bloqueado, el módulo no se está cargando: revisá el orden de las
líneas y `journalctl --user -u vasak-keyring`.
