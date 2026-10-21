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
///
/// Se lee **uno más** que el tope para poder distinguir «entró justo» de «no
/// entró»: `take()` corta y `read_to_end` devuelve `Ok`, así que sin ese byte de
/// más una entrega más larga se tomaría por completa y el prefijo cortado
/// pasaría por contraseña. Y si todavía no hay base, ese prefijo se convertiría
/// en la contraseña maestra de una base nueva que ningún inicio de sesión vuelve
/// a abrir — porque el diálogo gráfico, que va por D-Bus, no corta nada.
const MAXIMO_PETICION: u64 = 1024;

/// Cuánto se espera a que el cliente termine de escribir.
///
/// Sin esto una conexión que abre y no dice nada deja una tarea esperando para
/// siempre, y quien puede abrir el socket puede abrir muchas.
const PLAZO_LECTURA: std::time::Duration = std::time::Duration::from_secs(5);

/// Cuánto esperar antes de volver a intentar un `accept` que falló.
const REPOSO_TRAS_FALLO: std::time::Duration = std::time::Duration::from_millis(200);

/// La ruta del socket para un uid, la misma que arma el módulo de PAM.
pub fn ruta_del_socket(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/run/user/{uid}/vasak-keyring")).join("unlock.sock")
}

/// Tope de cada secreto del marco de rekey. Una maestra derivada son 64 dígitos
/// hex; 256 deja margen sin dejar que nadie infle la memoria del demonio.
const MAXIMO_SECRETO: usize = 256;
/// Tope del marco de rekey entero: dos largos de 4 bytes y dos secretos.
const MAXIMO_REKEY: u64 = (4 + MAXIMO_SECRETO + 4 + MAXIMO_SECRETO) as u64;

/// La ruta del socket de rekey para un uid, al lado del de desbloqueo. La misma
/// que arma el módulo de PAM.
pub fn ruta_del_socket_rekey(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/run/user/{uid}/vasak-keyring")).join("rekey.sock")
}

/// Interpreta un marco de rekey: dos secretos largo-prefijados (u32 LE), la
/// maestra **vieja** y la **nueva**, en ese orden.
///
/// Largo-prefijado y no delimitado por un byte, al revés que el socket de
/// desbloqueo: ahí el payload entero es una sola contraseña y un `\n` final se
/// recorta; acá hay **dos** secretos y cualquiera podría contener cualquier byte,
/// así que un separador se confundiría con contenido. El largo no deja ambigüedad.
pub fn interpretar_rekey(bytes: &[u8]) -> Result<(String, String), &'static str> {
    fn tomar(resto: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
        let (largo, resto) = resto
            .split_first_chunk::<4>()
            .ok_or("marco incompleto: falta el largo de un secreto")?;
        let largo = u32::from_le_bytes(*largo) as usize;
        if largo == 0 {
            return Err("un secreto del marco llegó vacío");
        }
        if largo > MAXIMO_SECRETO {
            return Err("un secreto del marco es demasiado largo");
        }
        if resto.len() < largo {
            return Err("marco incompleto: faltan bytes de un secreto");
        }
        Ok(resto.split_at(largo))
    }

    let (vieja, resto) = tomar(bytes)?;
    let (nueva, resto) = tomar(resto)?;
    if !resto.is_empty() {
        return Err("sobran bytes después del marco de rekey");
    }
    let vieja = std::str::from_utf8(vieja).map_err(|_| "la maestra vieja no es UTF-8 válido")?;
    let nueva = std::str::from_utf8(nueva).map_err(|_| "la maestra nueva no es UTF-8 válido")?;
    Ok((vieja.to_string(), nueva.to_string()))
}

/// Quién puede entregar una contraseña por este socket: sólo root.
///
/// Root, porque es quien acaba de autenticar a la persona y tiene la contraseña
/// que escribió: el módulo de PAM corre dentro del gestor de inicio de sesión.
///
/// El propio usuario **no**, aunque es el dueño del llavero. Cualquier programa
/// de la sesión corre con ese uid —un AppImage confinado incluido, al que
/// AppArmor le niega la base pero no los sockets—, y con una base todavía sin
/// crear la contraseña que entregara sería la maestra de la base nueva. El
/// usuario ya tiene su camino, que es `Unlock` por D-Bus desde el diálogo.
///
/// `uid_propio` queda en la firma para que la regla se lea contra el dueño: aunque
/// el directorio de `/run/user` ya deja afuera a los demás, el chequeo del par no
/// depende de que los permisos de un directorio sigan siendo los que se esperan.
pub fn par_autorizado(uid_del_par: u32, uid_propio: u32) -> bool {
    let _ = uid_propio;
    uid_del_par == 0
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
        .map(str::to_string)
        .map_err(|_| "la contraseña no es UTF-8 válido")
}

/// Fija los permisos de `ruta`.
///
/// `tokio::fs::set_permissions` es el mismo `chmod` de siempre, ejecutado en el
/// pool de bloqueo del runtime sin ocupar un worker con una tarea esperando.
///
/// Los modos no son negociables —0700 en el directorio, 0600 en el socket—, y
/// por eso el modo se pasa explícito y no se deja el que venga: `umask` decide
/// sobre lo que se crea, y `umask` no es una garantía.
async fn fijar_permisos(ruta: &std::path::Path, modo: u32) -> std::io::Result<()> {
    tokio::fs::set_permissions(ruta, PermissionsExt::from_mode(modo)).await
}

/// Deja el directorio del socket listo y corre el socket de un arranque anterior.
///
/// Va antes del `bind` y en este orden, que es el único que sirve: el
/// directorio tiene que existir y estar cerrado **antes** de que se cree el
/// socket adentro, y el socket viejo tiene que estar fuera antes de que el
/// `bind` intente tomar esa ruta. El 0600 del socket queda afuera, en
/// `escuchar`, porque el archivo todavía no existe hasta que el `bind` lo crea.
async fn preparar_ruta(ruta: &std::path::Path) -> std::io::Result<()> {
    if let Some(padre) = ruta.parent() {
        tokio::fs::create_dir_all(padre).await?;
        fijar_permisos(padre, 0o700).await?;
    }
    // El socket de un demonio anterior hace fallar el bind con EADDRINUSE.
    let _ = tokio::fs::remove_file(ruta).await;
    Ok(())
}

/// Deja un socket listo para escuchar: prepara el directorio, hace el `bind` y
/// fija el 0600. El 0600 va después del `bind`, que es quien crea el archivo.
async fn abrir_socket(ruta: &std::path::Path) -> std::io::Result<UnixListener> {
    preparar_ruta(ruta).await?;
    let listener = UnixListener::bind(ruta)?;
    fijar_permisos(ruta, 0o600).await?;
    Ok(listener)
}

/// Deja los sockets escuchando y devuelve las tareas que los atienden.
///
/// Son dos, en el mismo directorio `/run/user/<uid>/vasak-keyring`: el de
/// desbloqueo (la contraseña al iniciar sesión) y el de rekey (re-cifrar la base
/// al cambiar la contraseña de la cuenta, vasak-keyring#38).
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

    // El de desbloqueo es crítico: sin él el llavero no se abre en toda la sesión.
    let desbloqueo = abrir_socket(&ruta_del_socket(uid_propio)).await?;

    // El de rekey no lo es: si no se puede abrir, el re-cifrado al cambiar la
    // contraseña queda deshabilitado, pero el desbloqueo —que es lo que mantiene el
    // llavero usable— no puede caerse con él. Antes un `?` acá se llevaba puesto el
    // socket de desbloqueo cuando fallaba el de rekey (vasak-keyring#60).
    let rekey = match abrir_socket(&ruta_del_socket_rekey(uid_propio)).await {
        Ok(listener) => Some(listener),
        Err(e) => {
            eprintln!(
                "vasak-keyring: no se pudo abrir el socket de rekey ({e}); el re-cifrado al \
                 cambiar la contraseña queda deshabilitado, pero el desbloqueo sigue"
            );
            None
        }
    };

    tokio::spawn(async move {
        loop {
            let (stream, _) = match desbloqueo.accept().await {
                Ok(par) => par,
                // Un accept que falla no es motivo para dejar de escuchar el
                // resto de la sesión: sin este socket no hay desbloqueo.
                Err(e) => {
                    eprintln!("vasak-keyring: accept falló en el socket de desbloqueo: {e}");
                    // Y una pausa antes de reintentar. Hay errores que no se
                    // arreglan solos —EMFILE o ENFILE, sin descriptores libres—
                    // y sin esto el bucle gira a toda velocidad inundando el
                    // diario hasta que alguno se libere.
                    tokio::time::sleep(REPOSO_TRAS_FALLO).await;
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

    if let Some(rekey) = rekey {
        tokio::spawn(async move {
            loop {
                let (stream, _) = match rekey.accept().await {
                    Ok(par) => par,
                    Err(e) => {
                        eprintln!("vasak-keyring: accept falló en el socket de rekey: {e}");
                        tokio::time::sleep(REPOSO_TRAS_FALLO).await;
                        continue;
                    }
                };

                tokio::spawn(async move {
                    atender_rekey(stream, uid_propio).await;
                });
            }
        });
    }

    Ok(())
}

/// Un rekey: verifica que llame root, lee el marco, re-cifra, contesta un byte.
///
/// Sólo root, por lo mismo que el socket de desbloqueo: quien cambió la
/// contraseña y validó las dos es `pam_sm_chauthtok`, que corre como root. Un
/// proceso de la sesión no puede usar esto para elegir con qué maestra se cifra.
async fn atender_rekey(mut stream: UnixStream, uid_propio: u32) {
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == 0 => {}
        Ok(cred) if par_autorizado(cred.uid(), uid_propio) => {
            // El dueño del llavero pasa `par_autorizado`, pero un rekey no: sólo
            // root acaba de validar las dos contraseñas contra la cuenta.
            eprintln!(
                "vasak-keyring: se rechaza un rekey del uid {} (sólo root)",
                cred.uid()
            );
            return;
        }
        Ok(cred) => {
            eprintln!(
                "vasak-keyring: se rechaza un rekey del uid {} en el socket de rekey",
                cred.uid()
            );
            return;
        }
        Err(e) => {
            eprintln!("vasak-keyring: no se pudo identificar al par del socket de rekey: {e}");
            return;
        }
    }

    let mut buffer = Vec::new();
    let leido = tokio::time::timeout(
        PLAZO_LECTURA,
        (&mut stream)
            .take(MAXIMO_REKEY + 1)
            .read_to_end(&mut buffer),
    )
    .await;

    let ok = match leido {
        Ok(Ok(leidos)) if leidos as u64 > MAXIMO_REKEY => {
            eprintln!("vasak-keyring: el marco de rekey supera {MAXIMO_REKEY} bytes; se descarta");
            false
        }
        Ok(Ok(_)) => procesar_marco_de_rekey(&buffer).await,
        Ok(Err(e)) => {
            eprintln!("vasak-keyring: error leyendo del socket de rekey: {e}");
            false
        }
        Err(_) => {
            eprintln!("vasak-keyring: el cliente del socket de rekey no mandó nada en el plazo");
            false
        }
    };

    buffer.zeroize();

    let byte = if ok { b"1" } else { b"0" };
    let _ = stream.write_all(byte).await;
    let _ = stream.flush().await;
}

/// Interpreta un marco de rekey ya leído, re-cifra, y devuelve si quedó
/// re-cifrado (el byte que `atender_rekey` le contesta a PAM).
///
/// Separado de `atender_rekey` —que además verifica al par y habla por el
/// socket— para poder probar el camino entero (interpretar → re-cifrar → mapear
/// el resultado) sin ser root ni levantar un socket.
async fn procesar_marco_de_rekey(buffer: &[u8]) -> bool {
    let (mut vieja, mut nueva) = match interpretar_rekey(buffer) {
        Ok(par) => par,
        Err(motivo) => {
            eprintln!("vasak-keyring: marco de rekey descartado: {motivo}");
            return false;
        }
    };

    let resultado = crate::dbus_api::rekey_contrasena(&vieja, &nueva).await;
    vieja.zeroize();
    nueva.zeroize();

    match resultado {
        crate::dbus_api::RekeyResultado::Hecho => {
            println!("vasak-keyring: el llavero se re-cifró con la contraseña nueva de la cuenta");
            true
        }
        crate::dbus_api::RekeyResultado::NoAbre => {
            // No es un error: la base está cifrada con otra. Lo recupera el flujo
            // del próximo inicio de sesión.
            eprintln!(
                "vasak-keyring: la contraseña anterior no abre la base; no se re-cifra \
                 (se recupera en el próximo inicio de sesión)"
            );
            false
        }
        crate::dbus_api::RekeyResultado::Error(e) => {
            eprintln!("vasak-keyring: no se pudo re-cifrar el llavero: {e}");
            false
        }
    }
}

/// Una entrega: verifica quién llama, lee la contraseña, contesta si abrió.
async fn atender(
    mut stream: UnixStream,
    uid_propio: u32,
    state: Arc<Mutex<KeyringState>>,
    conn: zbus::Connection,
) {
    // Hoy sólo root pasa `par_autorizado`, pero quién entregó se sigue pasando:
    // sólo la entrega de root cuenta como «la contraseña del inicio de sesión»
    // (ver `aplicar_desde_el_login`), y esa regla no puede depender de que el
    // filtro del par no se vuelva a abrir.
    let desde_root = match stream.peer_cred() {
        Ok(cred) if par_autorizado(cred.uid(), uid_propio) => cred.uid() == 0,
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
    };

    let mut buffer = Vec::new();
    let leido = tokio::time::timeout(
        PLAZO_LECTURA,
        (&mut stream)
            .take(MAXIMO_PETICION + 1)
            .read_to_end(&mut buffer),
    )
    .await;

    let resultado = match leido {
        Ok(Ok(leidos)) if leidos as u64 > MAXIMO_PETICION => {
            eprintln!(
                "vasak-keyring: la entrega supera {MAXIMO_PETICION} bytes; se descarta \
                 en lugar de usar el pedazo que entró"
            );
            false
        }
        Ok(Ok(_)) => match interpretar_peticion(&buffer) {
            Ok(mut password) => {
                let unlock = PamUnlockInterface::new(state, conn);
                let abierto = unlock.aplicar_desde_el_login(&password, desde_root).await;
                password.zeroize();
                match abierto {
                    Ok(true) => {
                        println!("vasak-keyring: llavero desbloqueado al iniciar sesión");
                        true
                    }
                    Ok(false) if desde_root => {
                        // PAM ya validó esta contraseña contra la cuenta: si no
                        // abre, la base se cifró con otra (vasak-keyring#38).
                        eprintln!(
                            "vasak-keyring: la contraseña del inicio de sesión no abre la base \
                             existente: está cifrada con otra, casi siempre la anterior de la \
                             cuenta. Abrila una vez con esa en el diálogo de desbloqueo y queda \
                             cifrada con la de ahora."
                        );
                        false
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

    /// Un directorio propio para cada prueba, que se borra al terminar.
    ///
    /// No hay `tempfile` entre las dependencias y no compensa agregar una por
    /// dos directorios: el pid más un contador alcanzan, porque las pruebas de
    /// un mismo binario corren como hilos de un mismo proceso.
    struct DirDePrueba(std::path::PathBuf);

    impl DirDePrueba {
        fn nuevo(nombre: &str) -> Self {
            static SIGUIENTE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = SIGUIENTE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("vasak-keyring-{nombre}-{}-{n}", std::process::id()));
            // Por si una corrida anterior murió sin llegar al `Drop`.
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("no se pudo crear el directorio de la prueba");
            DirDePrueba(dir)
        }

        fn ruta(&self) -> &std::path::Path {
            &self.0
        }
    }

    // El borrado va en `Drop` y no al final de cada prueba para que también
    // corra cuando la prueba falla: el pánico desenrolla, y el `Drop` también.
    impl Drop for DirDePrueba {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn modo(ruta: &std::path::Path) -> u32 {
        std::fs::metadata(ruta)
            .expect("no se pudieron leer los permisos")
            .permissions()
            .mode()
            & 0o777
    }

    #[tokio::test]
    async fn el_directorio_del_socket_queda_cerrado_a_otros() {
        // El 0700 es lo que impide que otra cuenta de la máquina liste el
        // directorio donde vive el socket. Lo que se comprueba acá es que el modo
        // llegue al disco: nadie va a notar que sobre en papel y desaparezca
        // cuando alguien lo mira.
        let dir = DirDePrueba::nuevo("permisos");

        fijar_permisos(dir.ruta(), 0o700)
            .await
            .expect("no se pudieron fijar permisos");

        assert_eq!(
            modo(dir.ruta()),
            0o700,
            "el directorio tiene que quedar en 0700"
        );
    }

    #[tokio::test]
    async fn un_socket_inexistente_no_revienta_el_demonio() {
        // El error tiene que volver como `io::Error` y no como un pánico: quien
        // llama decide qué hacer con él.
        let dir = DirDePrueba::nuevo("permisos-faltantes");
        let ruta = dir.ruta().join("no-existe.sock");

        let error = fijar_permisos(&ruta, 0o600)
            .await
            .expect_err("fijar permisos sobre una ruta inexistente tiene que fallar");

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn preparar_deja_el_directorio_cerrado_y_barre_el_socket_viejo() {
        // El orden importa: el 0700 tiene que estar puesto antes de que se cree
        // el socket adentro, y el socket de un demonio anterior tiene que estar
        // fuera antes de que otro `bind` intente tomar esa ruta. Con el
        // `bind` y el 0600 del socket adentro —que no se pueden probar sin
        // `/run/user/<uid>`—, esto es la parte del arranque que sí se comprueba.
        let dir = DirDePrueba::nuevo("preparar");
        let ruta = dir.ruta().join("vasak-keyring").join("unlock.sock");
        let padre = ruta.parent().unwrap();
        tokio::fs::create_dir_all(padre).await.unwrap();
        tokio::fs::write(&ruta, b"socket de un demonio anterior")
            .await
            .unwrap();
        // 0777 a propósito: `preparar_ruta` tiene que dejar el directorio en
        // 0700 aunque venga más abierto. Se usa el mismo `fijar_permisos` que
        // usa el demonio, así que la prueba no se puede pasar mientras el
        // código real esté roto.
        fijar_permisos(padre, 0o777).await.unwrap();

        preparar_ruta(&ruta)
            .await
            .expect("no se pudo preparar la ruta");

        assert_eq!(
            modo(padre),
            0o700,
            "el directorio padre tiene que quedar en 0700"
        );
        assert!(
            !ruta.exists(),
            "el socket del demonio anterior tiene que estar fuera antes del bind"
        );
    }

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
    fn solo_root_puede_entregar_y_el_dueno_no() {
        assert!(
            par_autorizado(0, 1000),
            "root autentica el inicio de sesión"
        );
        // El dueño no: cualquier programa de la sesión corre con su uid, y sin
        // base todavía la contraseña que entregara sería la maestra de la nueva.
        assert!(
            !par_autorizado(1000, 1000),
            "el dueño del llavero desbloquea por D-Bus, no por el socket"
        );
        assert!(!par_autorizado(1001, 1000), "otra persona de la máquina");
        assert!(!par_autorizado(999, 1000), "una cuenta de servicio");
    }

    /// Un programa de la sesión —mismo uid que el demonio— que se conecta al
    /// socket con un llavero todavía sin base. Antes elegía la maestra: la base
    /// se creaba cifrada con lo que él mandara. Ahora no pasa del par.
    ///
    /// Va contra `atender`, que es lo que corre por cada conexión, y no contra
    /// `escuchar`: `escuchar` arma la ruta desde el uid, en `/run/user/<uid>`, y
    /// probarlo ahí borraría el socket del demonio de verdad. Un par de sockets
    /// conectados tiene las mismas credenciales del par que una conexión real del
    /// propio proceso, que es exactamente el caso a cerrar.
    #[tokio::test]
    async fn un_programa_de_la_sesion_no_elige_la_maestra_de_una_base_nueva() {
        use crate::dbus_api::tests::{
            base_de_las_pruebas, estado_de_la_sesion, maestra_en_memoria, EstadoDelLogin,
        };

        let _sesion = estado_de_la_sesion().lock().await;
        let _estado = EstadoDelLogin::limpio();
        // Sin base es justamente el caso del hueco: con una base, la contraseña
        // del intruso no la abre y no se adopta.
        assert!(
            !base_de_las_pruebas().exists(),
            "la prueba arranca sin base"
        );
        assert!(maestra_en_memoria().is_none(), "y sin maestra");

        let (extremo_del_demonio, extremo_del_bus) = UnixStream::pair().unwrap();
        let demonio = zbus::connection::Builder::unix_stream(extremo_del_demonio)
            .server(zbus::Guid::generate())
            .unwrap()
            .p2p()
            .build();
        let otra_punta = zbus::connection::Builder::unix_stream(extremo_del_bus)
            .p2p()
            .build();
        let (demonio, _otra_punta) = tokio::join!(demonio, otra_punta);
        let demonio = demonio.expect("no se pudo levantar el bus de la prueba");
        let estado = Arc::new(Mutex::new(crate::dbus_api::KeyringState::new()));

        let (servidor, mut intruso) = UnixStream::pair().unwrap();
        assert_ne!(
            servidor.peer_cred().unwrap().uid(),
            0,
            "la prueba tiene que correr sin ser root: el par es el propio usuario"
        );
        let atencion = tokio::spawn(atender(
            servidor,
            unsafe { libc::geteuid() },
            estado,
            demonio,
        ));

        // Si el demonio corta antes de leer, escribir puede dar EPIPE: lo que
        // importa no es si la escritura entró, sino qué hizo el demonio con ella.
        let _ = intruso.write_all(b"la-del-intruso\n").await;
        let _ = intruso.shutdown().await;
        let mut respuesta = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            intruso.read_to_end(&mut respuesta),
        )
        .await
        .expect("el demonio no contestó ni cortó");
        atencion
            .await
            .expect("la atención de la conexión no terminó");

        // La base no se escribe al abrir sino en el primer guardado, y se cifra
        // con la maestra que haya en memoria: que no quede ninguna es lo que
        // impide que la base nueva nazca con la contraseña del intruso.
        assert!(
            maestra_en_memoria().is_none(),
            "la contraseña de un programa de la sesión no puede quedar como maestra"
        );
        assert_ne!(
            respuesta, b"1",
            "el demonio no puede decirle al propio usuario que abrió el llavero"
        );
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
        assert_eq!(
            interpretar_peticion("contraseña ñandú".as_bytes()).unwrap(),
            "contraseña ñandú"
        );
        assert!(interpretar_peticion(&[0xff, 0xfe]).is_err());
    }
    // ── Rekey al cambiar la contraseña de la cuenta (#38) ──

    /// El marco de rekey armado a mano, sin pasar por el módulo de PAM: dos
    /// secretos con su largo `u32` little-endian por delante.
    fn marco(vieja: &[u8], nueva: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for secreto in [vieja, nueva] {
            bytes.extend_from_slice(&(secreto.len() as u32).to_le_bytes());
            bytes.extend_from_slice(secreto);
        }
        bytes
    }

    #[test]
    fn la_ruta_del_socket_de_rekey_esta_al_lado_del_de_desbloqueo() {
        assert_eq!(
            ruta_del_socket_rekey(1000),
            std::path::PathBuf::from("/run/user/1000/vasak-keyring/rekey.sock")
        );
        // El módulo de PAM arma esta misma cadena por su cuenta: el formato es
        // parte del contrato entre los dos.
        assert_eq!(
            ruta_del_socket_rekey(1000).parent(),
            ruta_del_socket(1000).parent(),
            "los dos sockets viven en el mismo directorio 0700"
        );
        assert_ne!(ruta_del_socket_rekey(1000), ruta_del_socket(1000));
    }

    #[test]
    fn el_marco_de_rekey_devuelve_vieja_y_nueva_en_ese_orden() {
        let (vieja, nueva) = interpretar_rekey(&marco(b"maestra-vieja", b"maestra-nueva")).unwrap();

        assert_eq!(vieja, "maestra-vieja");
        assert_eq!(nueva, "maestra-nueva");
    }

    #[test]
    fn un_secreto_con_saltos_de_linea_y_acentos_sobrevive_al_marco() {
        // Por eso el marco va largo-prefijado: cualquier byte es contenido y un
        // separador se confundiría con él.
        let rara = "con\nsalto\0y ñandú";
        let (vieja, nueva) = interpretar_rekey(&marco(rara.as_bytes(), b"\n")).unwrap();

        assert_eq!(vieja, rara);
        assert_eq!(
            nueva, "\n",
            "ni siquiera se recorta un salto de línea final"
        );
    }

    #[test]
    fn un_marco_de_rekey_truncado_se_descarta() {
        let entero = marco(b"vieja", b"nueva");
        // Cortado en cualquier punto antes del final: falta el largo de un
        // secreto o faltan bytes de uno. Nunca puede dar un par.
        for corte in 0..entero.len() {
            assert!(
                interpretar_rekey(&entero[..corte]).is_err(),
                "un marco cortado en {corte} de {} no puede interpretarse",
                entero.len()
            );
        }
    }

    #[test]
    fn un_marco_de_rekey_con_un_secreto_vacio_se_descarta() {
        // Una contraseña vacía no cifra nada: derivaría una maestra para nada.
        assert!(interpretar_rekey(&marco(b"", b"nueva")).is_err());
        assert!(interpretar_rekey(&marco(b"vieja", b"")).is_err());
        assert!(interpretar_rekey(&marco(b"", b"")).is_err());
    }

    #[test]
    fn el_tope_de_un_secreto_de_rekey_es_exacto() {
        let justo = vec![b'a'; MAXIMO_SECRETO];
        let de_mas = vec![b'a'; MAXIMO_SECRETO + 1];

        let (vieja, nueva) = interpretar_rekey(&marco(&justo, &justo)).unwrap();
        assert_eq!((vieja.len(), nueva.len()), (MAXIMO_SECRETO, MAXIMO_SECRETO));
        assert!(
            interpretar_rekey(&marco(&de_mas, b"nueva")).is_err(),
            "una vieja de {} bytes no entra",
            MAXIMO_SECRETO + 1
        );
        assert!(
            interpretar_rekey(&marco(b"vieja", &de_mas)).is_err(),
            "una nueva de {} bytes no entra",
            MAXIMO_SECRETO + 1
        );
    }

    #[test]
    fn el_tope_del_marco_deja_pasar_al_marco_legal_mas_grande() {
        // Si el tope de lectura de `atender_rekey` quedara por debajo de lo que
        // `interpretar_rekey` acepta, un par de maestras legales se cortaría.
        let justo = vec![b'a'; MAXIMO_SECRETO];

        assert!(marco(&justo, &justo).len() as u64 <= MAXIMO_REKEY);
    }

    #[test]
    fn un_largo_declarado_enorme_se_descarta_sin_reservar_memoria() {
        // Un par que declara 4 GiB no puede llevar al demonio a esperar ni a
        // reservar esos bytes: se corta por el largo, antes de mirar el resto.
        let mut bytes = u32::MAX.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"vieja");

        assert!(interpretar_rekey(&bytes).is_err());
    }

    #[test]
    fn un_marco_de_rekey_con_bytes_de_sobra_se_descarta() {
        let mut bytes = marco(b"vieja", b"nueva");
        bytes.push(b'x');

        assert!(
            interpretar_rekey(&bytes).is_err(),
            "un tercer secreto, o basura al final, no es un marco válido"
        );
        // Ni siquiera un tercer secreto bien formado.
        let mut tres = marco(b"vieja", b"nueva");
        tres.extend_from_slice(&marco(b"otra", b"mas")[..8]);
        assert!(interpretar_rekey(&tres).is_err());
    }

    #[test]
    fn un_secreto_de_rekey_que_no_es_utf8_se_descarta() {
        assert!(interpretar_rekey(&marco(&[0xff, 0xfe], b"nueva")).is_err());
        assert!(interpretar_rekey(&marco(b"vieja", &[0xc3, 0x28])).is_err());
    }

    /// Un programa de la sesión —mismo uid que el demonio— que manda un rekey
    /// perfectamente formado. Sólo root puede: quien validó las dos contraseñas
    /// contra la cuenta es `pam_sm_chauthtok`. Si el programa pudiera, elegiría
    /// con qué maestra se cifra la base de la persona, o la dejaría ilegible.
    ///
    /// Va contra `atender_rekey` y no contra `escuchar`, por lo mismo que la
    /// prueba del desbloqueo: `escuchar` arma la ruta en `/run/user/<uid>`.
    #[tokio::test]
    async fn un_programa_de_la_sesion_no_puede_re_cifrar_la_base() {
        use crate::dbus_api::tests::{base_de_las_pruebas, estado_de_la_sesion, EstadoDelLogin};

        let _sesion = estado_de_la_sesion().lock().await;
        let _estado = EstadoDelLogin::limpio();
        let ruta = base_de_las_pruebas();
        std::fs::create_dir_all(ruta.parent().unwrap()).unwrap();
        let db = crate::crypto::KeyringDatabase {
            format: crate::dbus_api::PORTAL_NAMESPACE_FORMAT,
            items: vec![],
        };
        std::fs::write(
            &ruta,
            crate::crypto::encrypt_database(&db, "la-vieja").unwrap(),
        )
        .unwrap();
        let antes = std::fs::read(&ruta).unwrap();

        let (servidor, mut intruso) = UnixStream::pair().unwrap();
        assert_ne!(
            servidor.peer_cred().unwrap().uid(),
            0,
            "la prueba tiene que correr sin ser root: el par es el propio usuario"
        );
        let atencion = tokio::spawn(atender_rekey(servidor, unsafe { libc::geteuid() }));

        let _ = intruso
            .write_all(&marco(b"la-vieja", b"la-del-intruso"))
            .await;
        let _ = intruso.shutdown().await;
        let mut respuesta = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            intruso.read_to_end(&mut respuesta),
        )
        .await
        .expect("el demonio no contestó ni cortó");
        atencion
            .await
            .expect("la atención de la conexión no terminó");

        assert_eq!(
            std::fs::read(&ruta).unwrap(),
            antes,
            "un rekey que no viene de root no puede tocar la base"
        );
        assert_ne!(
            respuesta, b"1",
            "el demonio no puede decirle al propio usuario que re-cifró"
        );
    }
    #[test]
    fn un_marco_de_rekey_armado_por_el_modulo_de_pam_se_interpreta() {
        // Los bytes de `marco_rekey("vieja", "nueva!")` del módulo de PAM, tal
        // como los afirma `el_marco_de_rekey_son_dos_secretos_con_su_largo_u32_
        // little_endian` allá. El módulo es un `cdylib` y el demonio un binario:
        // no se pueden llamar entre sí, así que el contrato es esta cadena de
        // bytes, la misma de los dos lados.
        let de_pam: &[u8] = b"\x05\0\0\0vieja\x06\0\0\0nueva!";

        let (vieja, nueva) = interpretar_rekey(de_pam).unwrap();

        assert_eq!((vieja.as_str(), nueva.as_str()), ("vieja", "nueva!"));
    }

    #[tokio::test]
    async fn abrir_socket_crea_el_socket_en_0600_bajo_un_directorio_en_0700() {
        // El mismo camino que usa `escuchar` para los dos sockets: prepara el
        // directorio, hace el bind y fija los modos. Se prueba fuera de
        // /run/user, con una ruta propia.
        let dir = DirDePrueba::nuevo("abrir");
        let ruta = dir.ruta().join("vasak-keyring").join("x.sock");

        let listener = abrir_socket(&ruta).await.expect("tiene que abrir");
        drop(listener);

        assert_eq!(modo(&ruta), 0o600, "el socket queda en 0600");
        assert_eq!(modo(ruta.parent().unwrap()), 0o700, "el directorio en 0700");
    }

    #[tokio::test]
    async fn un_marco_de_rekey_ilegible_no_re_cifra_nada() {
        // Un marco que `interpretar_rekey` rechaza no llega a tocar la base: la
        // respuesta a PAM es «no». Cubre el camino de descarte de
        // `procesar_marco_de_rekey` sin tocar el disco.
        assert!(!procesar_marco_de_rekey(b"xx").await);
        assert!(!procesar_marco_de_rekey(b"").await);
    }
}
