// PAM module for vasak-keyring
// Captures the login password and sends it to the daemon via D-Bus.

#![allow(non_camel_case_types, non_snake_case)]
// Los puntos de entrada de PAM tienen que ser `pub extern "C"` y recibir el
// `pam_handle_t` como puntero crudo: la firma la fija el ABI de PAM, no nosotros.
// Marcarlos `unsafe` —lo que pide la regla— cambiaría el símbolo exportado y PAM
// no lo encontraría, así que la única salida es decir que acá no aplica. El
// puntero se usa sólo para devolvérselo a las funciones de PAM, y todas las
// desreferencias están dentro de bloques `unsafe`.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use libc::c_int;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::raw::c_char;
use std::os::unix::net::UnixStream;
use zeroize::Zeroizing;

// ── PAM constants ──────────────────────────────────────────

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_AUTHTOK: c_int = 6;
const LOG_AUTH: c_int = 4;

// ── Opaque PAM handle (only accessed through FFI) ──────────

pub enum pam_handle_t {}

// ── FFI declarations ───────────────────────────────────────

extern "C" {
    fn pam_get_authtok(
        pamh: *mut pam_handle_t,
        item: c_int,
        authtok: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;

    fn pam_set_data(
        pamh: *mut pam_handle_t,
        module_data_name: *const c_char,
        data: *mut std::ffi::c_void,
        cleanup: Option<unsafe extern "C" fn(*mut pam_handle_t, *mut std::ffi::c_void, c_int)>,
    ) -> c_int;

    fn pam_get_data(
        pamh: *mut pam_handle_t,
        module_data_name: *const c_char,
        data: *mut *mut std::ffi::c_void,
    ) -> c_int;

    fn pam_syslog(pamh: *mut pam_handle_t, priority: c_int, format: *const c_char, ...) -> c_int;

    fn pam_get_user(
        pamh: *mut pam_handle_t,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
}

// ── Logging helper ─────────────────────────────────────────

fn log(pamh: *mut pam_handle_t, msg: &str) {
    let cmsg = CString::new(msg).unwrap_or_else(|_| c"log error".to_owned());

    // `pam_syslog` es variádica y toma el segundo argumento como **cadena de
    // formato**. Pasando el mensaje ahí, cualquier `%` que contenga se
    // interpreta como especificador y lee de la pila lo que no le corresponde:
    // en un proceso que corre como root dentro del gestor de inicio de sesión,
    // eso es una fuga de memoria ajena o un cierre en falso. Mientras todos los
    // mensajes fueron literales sin `%` no se notó; ahora que también se informa
    // el error del sistema —que puede traer una ruta o un texto ajeno— el
    // formato tiene que ser fijo y el mensaje un argumento.
    unsafe { pam_syslog(pamh, LOG_AUTH, c"%s".as_ptr(), cmsg.as_ptr()); }
}

// ── Cleanup callback (called by PAM when data is released) ─
//     Zeroizes and frees the boxed password string.

unsafe extern "C" fn password_cleanup(
    _pamh: *mut pam_handle_t,
    data: *mut std::ffi::c_void,
    _error_status: c_int,
) {
    if !data.is_null() {
        drop(Box::from_raw(data as *mut Zeroizing<String>));
    }
}

// ── Entrega de la contraseña al demonio ────────────────────

/// Cuánto se sigue intentando mientras el demonio arranca.
///
/// PAM abre la sesión al mismo tiempo que systemd lanza las unidades del
/// usuario, así que el primer intento suele no encontrar el socket todavía. Sólo
/// cuesta tiempo cuando el demonio de verdad no está.
const INTENTOS: u32 = 15;
const ESPERA_ENTRE_INTENTOS: std::time::Duration = std::time::Duration::from_millis(200);

/// Plazo de lectura y escritura sobre el socket.
///
/// Un demonio trabado no puede quedarse con el inicio de sesión: sin plazo, PAM
/// espera para siempre y no se entra a la máquina. Un llavero cerrado es un
/// problema; una sesión que no abre es otra cosa.
const PLAZO: std::time::Duration = std::time::Duration::from_secs(5);

/// Cómo terminó la entrega. Cada variante es un diagnóstico distinto, y eso es
/// el punto: el mensaje que había nombraba dos causas posibles sin distinguir
/// cuál, y una de las dos era imposible en la máquina donde se diagnosticó
/// —decía «la contraseña no corresponde a la base existente» cuando todavía no
/// había ninguna base—. Con eso el problema real quedó tapado durante meses.
enum Entrega {
    Abierto,
    /// El demonio contestó, y dijo que no.
    Rechazada,
    /// No se llegó a hablar con nadie en toda la ventana de espera.
    SinDemonio(std::io::Error),
    /// Se conectó pero la conversación falló.
    Cortada(std::io::Error),
}

/// La ruta del socket, armada igual que del lado del demonio.
///
/// A partir del uid y nada más: acá no hay sesión todavía, así que no hay
/// `XDG_RUNTIME_DIR` del usuario que leer. Los dos lados tienen que formar la
/// misma cadena o la entrega falla sin que nadie sepa por qué.
fn ruta_del_socket(uid: u32) -> String {
    format!("/run/user/{uid}/vasak-keyring/unlock.sock")
}

/// Si un error de conexión significa «todavía no arrancó» y conviene reintentar.
///
/// El socket no existe hasta que el demonio lo crea (`NotFound`), y entre el
/// bind y el accept puede rechazar (`ConnectionRefused`). Todo lo demás
/// —permisos, por ejemplo— no lo va a arreglar esperar.
fn todavia_arrancando(clase: std::io::ErrorKind) -> bool {
    matches!(
        clase,
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::Interrupted
    )
}

/// El uid del inicio de sesión, que no es el que corre este código.
///
/// Los módulos de PAM corren como root, en el proceso del gestor de inicio de
/// sesión, antes de que exista nada de la sesión del usuario.
fn target_uid(pamh: *mut pam_handle_t) -> Option<u32> {
    let mut user: *const c_char = std::ptr::null();

    if unsafe { pam_get_user(pamh, &mut user, std::ptr::null()) } != PAM_SUCCESS || user.is_null() {
        return None;
    }

    let name = unsafe { CStr::from_ptr(user) };
    let name = CString::new(name.to_bytes()).ok()?;
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };

    if entry.is_null() {
        None
    } else {
        Some(unsafe { (*entry).pw_uid })
    }
}

/// Una sola entrega sobre una conexión ya abierta.
fn conversar(mut flujo: UnixStream, password: &str) -> Result<bool, std::io::Error> {
    flujo.set_write_timeout(Some(PLAZO))?;
    flujo.set_read_timeout(Some(PLAZO))?;

    flujo.write_all(password.as_bytes())?;
    // El demonio lee hasta el fin del flujo, así que hay que cerrar este lado o
    // los dos se quedan esperando al otro.
    flujo.shutdown(std::net::Shutdown::Write)?;

    let mut respuesta = [0u8; 1];
    flujo.read_exact(&mut respuesta)?;
    Ok(respuesta[0] == b'1')
}

/// Entrega la contraseña, esperando al demonio si está arrancando.
fn entregar(uid: u32, password: &str) -> Entrega {
    let ruta = ruta_del_socket(uid);
    let mut ultimo = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no se intentó ninguna conexión",
    );

    for intento in 0..INTENTOS {
        match UnixStream::connect(&ruta) {
            Ok(flujo) => {
                return match conversar(flujo, password) {
                    Ok(true) => Entrega::Abierto,
                    Ok(false) => Entrega::Rechazada,
                    Err(e) => Entrega::Cortada(e),
                }
            }
            Err(e) if todavia_arrancando(e.kind()) && intento + 1 < INTENTOS => {
                ultimo = e;
                std::thread::sleep(ESPERA_ENTRE_INTENTOS);
            }
            Err(e) => return Entrega::SinDemonio(e),
        }
    }

    Entrega::SinDemonio(ultimo)
}

// ════════════════════════════════════════════════════════════
//  PAM entry points (required by PAM specification)
// ════════════════════════════════════════════════════════════

/// Called during the authentication phase.
///
/// Extracts the password that the user just entered and stores
/// it in the PAM context so `pam_sm_open_session` can forward
/// it to the vasak-keyring daemon.
#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    let mut authtok: *const c_char = std::ptr::null();
    let ret = unsafe { pam_get_authtok(pamh, PAM_AUTHTOK, &mut authtok, std::ptr::null()) };

    if ret != PAM_SUCCESS || authtok.is_null() {
        log(pamh, "pam_vasak_keyring: pam_get_authtok failed");
        return PAM_IGNORE;
    }

    let password = unsafe { CStr::from_ptr(authtok) };
    let owned = Zeroizing::new(password.to_string_lossy().into_owned());
    let stored = Box::new(owned);

    // Literal `c""`: no hay nada que construir ni desenvolver, y en un módulo
    // PAM un panic se lleva puesto el inicio de sesión.
    let key = c"vasak_keyring_password";
    let ret = unsafe {
        pam_set_data(
            pamh,
            key.as_ptr(),
            Box::into_raw(stored) as *mut std::ffi::c_void,
            Some(password_cleanup),
        )
    };

    if ret != PAM_SUCCESS {
        log(pamh, "pam_vasak_keyring: pam_set_data failed");
        return PAM_IGNORE;
    }

    PAM_SUCCESS
}

/// Called during the session-opening phase.
///
/// Retrieves the password stored by `pam_sm_authenticate`,
/// sends it to the vasak-keyring daemon over D-Bus, then
/// zeroizes the secret.
#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    // Literal `c""`: no hay nada que construir ni desenvolver, y en un módulo
    // PAM un panic se lleva puesto el inicio de sesión.
    let key = c"vasak_keyring_password";
    let mut data: *mut std::ffi::c_void = std::ptr::null_mut();

    let ret = unsafe { pam_get_data(pamh, key.as_ptr(), &mut data) };

    if ret != PAM_SUCCESS || data.is_null() {
        log(pamh, "pam_vasak_keyring: no stored password (already consumed or never set)");
        return PAM_IGNORE;
    }

    let password: Zeroizing<String> = unsafe {
        let bx = &*(data as *mut Zeroizing<String>);
        bx.clone()
    };

    let Some(uid) = target_uid(pamh) else {
        log(pamh, "pam_vasak_keyring: could not resolve the user of this login");
        return PAM_IGNORE;
    };

    if password.is_empty() {
        log(pamh, "pam_vasak_keyring: la contraseña guardada está vacía; no se entrega");
        return PAM_SUCCESS;
    }

    // Se informa **qué** falló y no una lista de lo que pudo haber sido. Cada
    // caso se arregla de una manera distinta, y sin distinguirlos no hay forma
    // de saber cuál está pasando.
    match entregar(uid, &password) {
        Entrega::Abierto => log(pamh, "pam_vasak_keyring: llavero desbloqueado"),
        Entrega::Rechazada => log(
            pamh,
            "pam_vasak_keyring: el demonio rechazó la contraseña; \
             no es la que cifra la base del llavero",
        ),
        Entrega::SinDemonio(e) => log(
            pamh,
            &format!(
                "pam_vasak_keyring: no se pudo conectar a {} en 3 s ({e}); \
                 el llavero queda cerrado y va a pedir la contraseña a mano",
                ruta_del_socket(uid)
            ),
        ),
        Entrega::Cortada(e) => log(
            pamh,
            &format!(
                "pam_vasak_keyring: se conectó al demonio pero la entrega falló ({e})"
            ),
        ),
    }

    // password zeroized automatically on drop (Zeroizing)

    PAM_SUCCESS
}

/// Required by PAM whenever the module appears in an `auth` stack.
///
/// PAM calls this after a successful authentication; a module that does not
/// export it makes the whole stack fail with "symbol not found", which is why
/// this returns success rather than being omitted. There are no credentials to
/// establish here — the password is handed over in `pam_sm_open_session`.
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// Counterpart to `pam_sm_open_session`, required for the same reason.
///
/// Nothing to tear down: the daemon holds the master password for as long as it
/// runs, and it is never written to disk.
#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *mut *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El contrato con el demonio. Los dos lados arman esta cadena por separado
    /// —el módulo no puede leer el entorno del usuario— así que si dejan de
    /// coincidir la entrega falla y nada lo dice.
    #[test]
    fn la_ruta_del_socket_es_la_que_el_demonio_publica() {
        assert_eq!(
            ruta_del_socket(1000),
            "/run/user/1000/vasak-keyring/unlock.sock"
        );
    }

    /// El error que dejaba el llavero cerrado toda la sesión: el demonio arranca
    /// junto con la sesión y su socket todavía no existe. Si eso cuenta como
    /// «no», el llavero nunca se abre —y en una máquina nueva ni siquiera se
    /// crea, porque se crea al abrirlo por primera vez.
    #[test]
    fn un_demonio_que_todavia_no_arranco_no_es_una_negativa() {
        assert!(todavia_arrancando(std::io::ErrorKind::NotFound));
        assert!(todavia_arrancando(std::io::ErrorKind::ConnectionRefused));
    }

    /// Lo que no arregla esperar, no se espera. Un socket con los permisos mal
    /// puestos va a seguir rechazando dentro de tres segundos, y mientras tanto
    /// el inicio de sesión está detenido.
    #[test]
    fn lo_que_no_mejora_esperando_no_se_reintenta() {
        assert!(!todavia_arrancando(std::io::ErrorKind::PermissionDenied));
        assert!(!todavia_arrancando(std::io::ErrorKind::ConnectionReset));
        assert!(!todavia_arrancando(std::io::ErrorKind::InvalidData));
    }

    /// La ventana de espera tiene que seguir siendo la que dice el mensaje del
    /// diario, o el diagnóstico manda a buscar en el lugar equivocado.
    #[test]
    fn la_ventana_de_espera_es_de_tres_segundos() {
        assert_eq!(
            ESPERA_ENTRE_INTENTOS * INTENTOS,
            std::time::Duration::from_secs(3)
        );
    }

    /// El protocolo sobre el socket, contra un servidor de juguete.
    ///
    /// Es la parte que no se puede probar reiniciando la máquina, y la que tiene
    /// el detalle que trabaría el inicio de sesión si faltara: el demonio lee
    /// hasta el fin del flujo, así que sin el `shutdown` los dos lados se
    /// quedan esperando al otro y PAM se cuelga hasta el plazo.
    #[test]
    fn la_entrega_manda_la_contrasena_cierra_su_lado_y_lee_la_respuesta() {
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("pam-vsk-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let ruta = dir.join("prueba.sock");
        let _ = std::fs::remove_file(&ruta);
        let escucha = UnixListener::bind(&ruta).expect("bind");

        let servidor = std::thread::spawn(move || {
            let (mut flujo, _) = escucha.accept().expect("accept");
            let mut recibido = Vec::new();
            // Leer hasta EOF: si el cliente no cerrara su lado, esto no termina.
            flujo.read_to_end(&mut recibido).expect("leer");
            flujo.write_all(b"1").expect("responder");
            recibido
        });

        let flujo = UnixStream::connect(&ruta).expect("connect");
        let abierto = conversar(flujo, "contraseña ñandú").expect("conversar");

        let recibido = servidor.join().expect("hilo del servidor");
        assert_eq!(
            String::from_utf8(recibido).unwrap(),
            "contraseña ñandú",
            "la contraseña llega tal cual, sin salto de línea agregado"
        );
        assert!(abierto, "un «1» del demonio es un desbloqueo");

        let _ = std::fs::remove_file(&ruta);
        let _ = std::fs::remove_dir(&dir);
    }

    /// Y que un «0» no se lea como un sí. Que el byte se interprete al revés
    /// dejaría a PAM informando un desbloqueo que nunca pasó.
    #[test]
    fn un_cero_del_demonio_es_una_negativa() {
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("pam-vsk-no-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let ruta = dir.join("prueba.sock");
        let _ = std::fs::remove_file(&ruta);
        let escucha = UnixListener::bind(&ruta).expect("bind");

        std::thread::spawn(move || {
            let (mut flujo, _) = escucha.accept().expect("accept");
            let mut basura = Vec::new();
            let _ = flujo.read_to_end(&mut basura);
            let _ = flujo.write_all(b"0");
        });

        let flujo = UnixStream::connect(&ruta).expect("connect");
        assert!(!conversar(flujo, "cualquiera").expect("conversar"));

        let _ = std::fs::remove_file(&ruta);
        let _ = std::fs::remove_dir(&dir);
    }

    /// Un mensaje con `%` no debe poder convertirse en un especificador de
    /// formato. No se puede llamar a `pam_syslog` sin un handle real, así que lo
    /// que se comprueba es que el texto sobreviva intacto hasta el `CString`
    /// —que es lo que se le pasa como argumento y no como formato—.
    #[test]
    fn un_mensaje_con_porcentaje_viaja_como_dato() {
        let sospechoso = "no se pudo conectar a /run/user/1000/%s%n%p (roto)";
        let cmsg = CString::new(sospechoso).expect("sin bytes nulos");
        assert_eq!(cmsg.to_str().unwrap(), sospechoso);
    }
}
