//! El canal por el que llega la contraseña al iniciar sesión.
//!
//! # Por qué no es D-Bus
//!
//! El módulo de PAM corre **como root, dentro del proceso del gestor de inicio
//! de sesión**, y tiene que entregarle la contraseña a un demonio que corre como
//! el usuario. Eso se intentó por el bus de sesión y no funciona: `dbus-broker`
//! acepta conexiones del dueño del bus y rechaza al resto —root incluido— en la
//! autenticación, antes de que exista cualquier mensaje. El módulo veía un error
//! de conexión, lo confundía con «el demonio todavía no arrancó», reintentaba
//! tres segundos y se rendía.
//!
//! No era una carrera de arranque: en el diario de la máquina donde se
//! diagnosticó había **tres intentos y ningún desbloqueo**, nunca, en ningún
//! arranque. El llavero quedaba cerrado toda la sesión y, como la base se crea
//! al abrirla por primera vez, ni siquiera llegaba a existir.
//!
//! Un socket unix propio sí cruza ese límite: vive dentro de `/run/user/<uid>`,
//! que es 0700 del usuario, y root pasa igual porque root no está sujeto a los
//! permisos. De paso la contraseña deja de atravesar el proceso del broker.
//!
//! # Por qué la ruta se deriva del uid
//!
//! Sin usar `XDG_RUNTIME_DIR`, aunque el demonio la tenga. El módulo de PAM no
//! puede leer el entorno del usuario —todavía no hay sesión— así que sólo puede
//! armar la ruta a partir del uid. Si cada lado la resolviera a su manera,
//! bastaría una variable distinta para que la entrega fallara en silencio.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use zeroize::Zeroize;

use crate::dbus_api::{KeyringState, PamUnlockInterface};

/// Tope de lo que se lee de una conexión.
///
/// Una contraseña no llega ni cerca; el límite está para que nadie pueda hacer
/// crecer la memoria del demonio del llavero mandando bytes para siempre.
const MAXIMO_PETICION: u64 = 1024;

/// Cuánto se espera a que el cliente termine de escribir.
///
/// Sin esto una conexión que abre y no dice nada deja una tarea esperando para
/// siempre, y quien puede abrir el socket puede abrir muchas.
const PLAZO_LECTURA: std::time::Duration = std::time::Duration::from_secs(5);

/// La ruta del socket para un uid, la misma que arma el módulo de PAM.
pub fn ruta_del_socket(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/run/user/{uid}/vasak-keyring"))
        .join("unlock.sock")
}

/// Quién puede entregar una contraseña por este socket.
///
/// Root, porque es quien acaba de autenticar a la persona y tiene la contraseña
/// que escribió. Y el propio usuario, porque es el dueño del llavero y de todos
/// modos ya puede leer la base cifrada. Nadie más: aunque el directorio de
/// `/run/user` ya los deja afuera, el chequeo del par no depende de que los
/// permisos de un directorio sigan siendo los que se esperan.
pub fn par_autorizado(uid_del_par: u32, uid_propio: u32) -> bool {
    uid_del_par == 0 || uid_del_par == uid_propio
}

/// Interpreta lo que llegó por el socket.
///
/// Se acepta un `\n` final y se lo saca: así la entrega se puede reproducir a
/// mano para diagnosticar, sin que el salto de línea termine formando parte de
/// la contraseña y abriendo una base que después nada vuelve a abrir.
pub fn interpretar_peticion(bytes: &[u8]) -> Result<String, &'static str> {
    if bytes.is_empty() {
        return Err("no llegó ninguna contraseña");
    }
    let sin_salto = match bytes.strip_suffix(b"\n") {
        Some(resto) => resto,
        None => bytes,
    };
    if sin_salto.is_empty() {
        return Err("la contraseña llegó vacía");
    }
    std::str::from_utf8(sin_salto)
        .map(|s| s.to_string())
        .map_err(|_| "la contraseña no es UTF-8 válido")
}

/// Deja el socket escuchando y devuelve la tarea que lo atiende.
///
/// Se llama **después** de reclamar el nombre de D-Bus: recién ahí se sabe que
/// este proceso es el único demonio, y por lo tanto que un socket que haya
/// quedado de un arranque anterior es basura y se puede borrar. Al revés, dos
/// demonios peleando se robarían las entregas.
pub async fn escuchar(
    state: Arc<Mutex<KeyringState>>,
    conn: zbus::Connection,
) -> std::io::Result<()> {
    let uid_propio = unsafe { libc::geteuid() };
    let ruta = ruta_del_socket(uid_propio);

    if let Some(padre) = ruta.parent() {
        std::fs::create_dir_all(padre)?;
        std::fs::set_permissions(padre, PermissionsExt::from_mode(0o700))?;
    }
    // El socket de un demonio anterior hace fallar el bind con EADDRINUSE.
    let _ = std::fs::remove_file(&ruta);

    let listener = UnixListener::bind(&ruta)?;
    // 0600 después del bind, no antes: el archivo lo crea el bind.
    std::fs::set_permissions(&ruta, PermissionsExt::from_mode(0o600))?;

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(par) => par,
                // Un accept que falla no es motivo para dejar de escuchar el
                // resto de la sesión: sin este socket no hay desbloqueo.
                Err(e) => {
                    eprintln!("vasak-keyring: accept falló en el socket de desbloqueo: {e}");
                    continue;
                }
            };

            let state = state.clone();
            let conn = conn.clone();
            tokio::spawn(async move {
                atender(stream, uid_propio, state, conn).await;
            });
        }
    });

    Ok(())
}

/// Una entrega: verifica quién llama, lee la contraseña, contesta si abrió.
async fn atender(
    mut stream: UnixStream,
    uid_propio: u32,
    state: Arc<Mutex<KeyringState>>,
    conn: zbus::Connection,
) {
    match stream.peer_cred() {
        Ok(cred) if par_autorizado(cred.uid(), uid_propio) => {}
        Ok(cred) => {
            eprintln!(
                "vasak-keyring: se rechaza una entrega del uid {} en el socket de desbloqueo",
                cred.uid()
            );
            return;
        }
        Err(e) => {
            eprintln!("vasak-keyring: no se pudo identificar al par del socket: {e}");
            return;
        }
    }

    let mut buffer = Vec::new();
    let leido = tokio::time::timeout(
        PLAZO_LECTURA,
        (&mut stream).take(MAXIMO_PETICION).read_to_end(&mut buffer),
    )
    .await;

    let resultado = match leido {
        Ok(Ok(_)) => match interpretar_peticion(&buffer) {
            Ok(mut password) => {
                let unlock = PamUnlockInterface::new(state, conn);
                let abierto = unlock.aplicar(&password).await;
                password.zeroize();
                match abierto {
                    Ok(true) => {
                        println!("vasak-keyring: llavero desbloqueado al iniciar sesión");
                        true
                    }
                    Ok(false) => {
                        eprintln!(
                            "vasak-keyring: la contraseña recibida no abre la base existente"
                        );
                        false
                    }
                    Err(e) => {
                        eprintln!("vasak-keyring: falló el desbloqueo: {e}");
                        false
                    }
                }
            }
            Err(motivo) => {
                eprintln!("vasak-keyring: entrega descartada: {motivo}");
                false
            }
        },
        Ok(Err(e)) => {
            eprintln!("vasak-keyring: error leyendo del socket de desbloqueo: {e}");
            false
        }
        Err(_) => {
            eprintln!("vasak-keyring: el cliente del socket no mandó nada en el plazo");
            false
        }
    };

    buffer.zeroize();

    // La respuesta es un byte y no un cierre a secas: el módulo de PAM tiene que
    // poder distinguir «la contraseña no abre la base» de «no llegué a hablar
    // con nadie», que es exactamente lo que antes no podía y por eso el mensaje
    // del diario nombraba las dos causas sin saber cuál.
    let byte = if resultado { b"1" } else { b"0" };
    let _ = stream.write_all(byte).await;
    let _ = stream.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_ruta_se_deriva_del_uid_y_no_del_entorno() {
        assert_eq!(
            ruta_del_socket(1000),
            std::path::PathBuf::from("/run/user/1000/vasak-keyring/unlock.sock")
        );
        // El módulo de PAM arma esta misma cadena sin poder leer el entorno del
        // usuario, así que el formato es parte del contrato entre los dos.
        assert!(ruta_del_socket(0).starts_with("/run/user/0"));
    }

    #[test]
    fn solo_root_y_el_dueno_pueden_entregar() {
        assert!(par_autorizado(0, 1000), "root autentica el inicio de sesión");
        assert!(par_autorizado(1000, 1000), "el dueño del llavero");
        assert!(!par_autorizado(1001, 1000), "otra persona de la máquina");
        assert!(!par_autorizado(999, 1000), "una cuenta de servicio");
    }

    #[test]
    fn el_salto_de_linea_final_no_es_parte_de_la_contrasena() {
        // Si se colara, crearía una base con una contraseña que después el
        // inicio de sesión nunca vuelve a formar.
        assert_eq!(interpretar_peticion(b"secreta\n").unwrap(), "secreta");
        assert_eq!(interpretar_peticion(b"secreta").unwrap(), "secreta");
        // Sólo uno: una contraseña que de verdad termina en salto conserva el resto.
        assert_eq!(interpretar_peticion(b"secreta\n\n").unwrap(), "secreta\n");
    }

    #[test]
    fn una_entrega_sin_contrasena_se_descarta() {
        assert!(interpretar_peticion(b"").is_err());
        assert!(interpretar_peticion(b"\n").is_err());
    }

    #[test]
    fn una_contrasena_con_acentos_sobrevive_el_viaje() {
        assert_eq!(interpretar_peticion("contraseña ñandú".as_bytes()).unwrap(), "contraseña ñandú");
        assert!(interpretar_peticion(&[0xff, 0xfe]).is_err());
    }
}
