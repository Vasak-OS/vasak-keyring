# Auto-desbloqueo por PAM

El demonio arranca bloqueado: la contraseña maestra nunca se guarda en disco, se
carga en memoria al iniciar sesión. Quien la entrega es `pam_vasak_keyring.so`,
y para eso el stack de PAM del inicio de sesión tiene que cargarlo.

**Sin esta configuración el llavero no funciona.** El servicio corre, reclama
`org.freedesktop.secrets` y responde, pero toda operación falla porque no tiene
con qué descifrar la base.

## Qué agregar

En `/etc/pam.d/system-login`, que es el stack que comparten greetd y los inicios
por consola, **después** de los `include system-auth`:

```
auth       optional   pam_vasak_keyring.so
session    optional   pam_vasak_keyring.so
```

## Por qué las dos líneas

Hacen falta ambas y en ese orden:

- `auth` corre durante la autenticación y toma con `pam_get_authtok` la
  contraseña que el usuario acaba de escribir, guardándola en el contexto de PAM.
  Va después de `system-auth` porque para entonces la contraseña ya se pidió.
- `session` corre al abrir la sesión, recupera esa contraseña del contexto y se
  la pasa al demonio por D-Bus.

Con `session` sola el módulo no encuentra nada guardado y no hace nada: el
llavero queda bloqueado igual que si no estuviera configurado.

`optional` es deliberado: si el módulo falla, el inicio de sesión sigue. Un error
acá no debe dejar a nadie afuera del sistema.

## Al configurarlo por primera vez

La primera vez que se desbloquea, **la contraseña que reciba el demonio pasa a
ser la contraseña maestra** de una base nueva. De ahí en más tiene que coincidir
en cada inicio de sesión, así que si se cambia la contraseña del usuario por
fuera de PAM la base anterior deja de abrirse.

## Verificación

Después de reiniciar sesión:

```
secret-tool store --label=prueba app prueba   # pide el secreto por stdin
secret-tool lookup app prueba
```

Si devuelve el secreto, el auto-desbloqueo está andando. Si responde que el
llavero está bloqueado, el módulo no se está cargando: revisá el orden de las
líneas y `journalctl --user -u vasak-keyring`.
