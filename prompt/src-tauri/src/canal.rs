//! Apartar la salida estándar antes de que la ensucie una biblioteca.
//!
//! Los tres diálogos de este paquete entregan su respuesta por la salida
//! estándar, y ahí no puede aparecer nada más. GTK y WebKit escriben avisos
//! cuando les parece —una fuente que falta, una propiedad obsoleta— y esa línea
//! se vuelve parte de la contraseña: la autenticación falla por un motivo que
//! nadie podría adivinar mirando el diálogo.
//!
//! Así que al arrancar se guarda el descriptor de verdad y se manda la salida
//! estándar a `/dev/null`. Todo lo que la biblioteca escriba después cae ahí, y
//! la respuesta sale por el que apartamos.
//!
//! `ssh_askpass` hace lo mismo con su propio código, de antes que existiera este
//! módulo; cuando haya que tocarlo, ahí está el lugar donde vive esto ahora.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::OnceLock;

use zeroize::Zeroizing;

/// El descriptor que el padre está leyendo, ya a salvo.
static RESPUESTA: OnceLock<OwnedFd> = OnceLock::new();

/// Pone la salida estándar fuera del alcance de las bibliotecas gráficas.
///
/// Se llama una sola vez y lo antes posible: cualquier cosa que escriba antes
/// ya salió por el canal bueno.
pub fn apartar_salida() {
    unsafe {
        let guardado = libc::dup(libc::STDOUT_FILENO);
        if guardado >= 0 {
            let _ = RESPUESTA.set(OwnedFd::from_raw_fd(guardado));
        }

        let nulo = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if nulo >= 0 {
            libc::dup2(nulo, libc::STDOUT_FILENO);
            libc::close(nulo);
        }
    }
}

/// Entrega la respuesta y termina el proceso.
///
/// No vuelve: la respuesta ya salió por el descriptor que el padre está
/// leyendo, y lo único honesto que queda es dejar de existir.
pub fn responder(texto: &str) -> ! {
    if let Some(fd) = RESPUESTA.get() {
        let linea = Zeroizing::new(format!("{texto}\n"));
        let mut escrito = 0;
        while escrito < linea.len() {
            let n = unsafe {
                libc::write(
                    fd.as_raw_fd(),
                    linea.as_ptr().add(escrito) as *const libc::c_void,
                    linea.len() - escrito,
                )
            };
            if n <= 0 {
                break;
            }
            escrito += n as usize;
        }
    }
    std::process::exit(0)
}

/// Nadie contestó. El padre lo distingue por el código de salida, y de eso
/// depende que el agente sepa que fue una negativa y no una respuesta vacía.
pub fn rendirse() -> ! {
    std::process::exit(1)
}
