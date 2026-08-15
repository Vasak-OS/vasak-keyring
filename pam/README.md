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
session    optional   pam_vasak_keyring.so     ← al final, después de pam_systemd
```

`system-login` es el stack que comparten greetd (a través de
`system-local-login`) y los inicios por consola, o sea todas las formas de
entrar al sistema.

## Por qué las dos líneas

Hacen falta ambas y en ese orden:

- `auth` corre durante la autenticación y toma con `pam_get_authtok` la
  contraseña que el usuario acaba de escribir, guardándola en el contexto de PAM.
  Va después de `system-auth` porque para entonces la contraseña ya se pidió.
- `session` corre al abrir la sesión, recupera esa contraseña del contexto y se
  la pasa al demonio por D-Bus. Va **al final**, después de `pam_systemd`: ese es
  el módulo que crea `/run/user/<uid>`, y ahí adentro vive el socket del bus por
  donde se entrega la contraseña. Antes de él no hay dónde entregarla.

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
