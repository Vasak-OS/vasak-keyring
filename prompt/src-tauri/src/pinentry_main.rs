//! El programa que `gpg-agent` lanza cuando necesita una contraseña.
//!
//! # Dos procesos, y por qué
//!
//! La conversación con el agente va por entrada y salida estándar, y ahí no
//! puede aparecer **nada** que no sea protocolo. Un diálogo gráfico no puede
//! prometer eso: GTK y WebKit escriben avisos a la salida estándar cuando les
//! parece, y una línea suelta ahí rompe la conversación de una forma que nadie
//! puede diagnosticar.
//!
//! Así que este proceso no abre ninguna ventana. Cuando hay que preguntar algo
//! se ejecuta a sí mismo con `--dialogo`, que es el modo que sí levanta Tauri,
//! y le lee la respuesta por una tubería. El hijo puede ensuciar su propia
//! salida todo lo que quiera: no es la del protocolo.
//!
//! Es el mismo cuidado que ya tiene `vasak-ssh-askpass` —que aparta la salida
//! estándar al arrancar— resuelto de la única forma que sirve acá, donde la
//! conversación sigue después de la primera respuesta.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use vasak_keyring_prompt_lib::pinentry::{
    interpretar, respuesta_a_confirm, respuesta_a_getpin, saludo, Accion, Pedido,
};
use zeroize::Zeroizing;

/// El argumento que distingue al hijo que muestra la ventana.
const DIALOGO: &str = "--dialogo";

/// Cómo se le pasa el pedido al hijo.
///
/// Por el entorno y no por argumentos: la lista de argumentos de un proceso la
/// puede leer cualquiera con `ps`, y la descripción dice de qué clave se trata.
const ENV_MODO: &str = "VASAK_PINENTRY_MODO";
const ENV_DESC: &str = "VASAK_PINENTRY_DESC";
const ENV_ETIQUETA: &str = "VASAK_PINENTRY_ETIQUETA";
const ENV_TITULO: &str = "VASAK_PINENTRY_TITULO";
const ENV_ERROR: &str = "VASAK_PINENTRY_ERROR";

fn main() {
    if std::env::args().any(|a| a == DIALOGO) {
        vasak_keyring_prompt_lib::run_pinentry_dialog();
        return;
    }
    conversar();
}

/// La conversación con el agente. Termina con `BYE` o cuando se cierra la
/// entrada.
fn conversar() {
    let entrada = std::io::stdin().lock();
    let mut salida = std::io::stdout().lock();
    let mut pedido = Pedido::default();

    // El saludo va primero, sin esperar nada: el agente lo espera apenas lanza
    // el programa y no manda una sola orden hasta leerlo.
    if !decir(&mut salida, &[saludo()]) {
        return;
    }

    for linea in entrada.lines() {
        let Ok(linea) = linea else { break };

        let respuesta = match interpretar(&linea, &mut pedido) {
            Accion::Responder(lineas) => lineas,
            Accion::PedirFrase => {
                let frase = preguntar("frase", &pedido);
                respuesta_a_getpin(frase.as_ref().map(|f| f.as_str()))
            }
            Accion::Confirmar { una_sola_opcion } => {
                let modo = if una_sola_opcion { "aviso" } else { "confirmar" };
                respuesta_a_confirm(preguntar(modo, &pedido).is_some())
            }
            Accion::Mostrar => {
                preguntar("aviso", &pedido);
                vec!["OK".to_string()]
            }
            Accion::Terminar => {
                let _ = decir(&mut salida, &["OK closing connection".to_string()]);
                return;
            }
        };

        if !decir(&mut salida, &respuesta) {
            return;
        }
    }
}

/// Escribe las líneas y vacía el búfer. `false` si el agente cerró el canal.
///
/// Vaciar en cada línea no es opcional: del otro lado hay alguien esperando
/// esta respuesta para mandar la siguiente orden, así que una respuesta que se
/// queda en el búfer es un cuelgue.
fn decir(salida: &mut impl Write, lineas: &[String]) -> bool {
    for linea in lineas {
        if writeln!(salida, "{linea}").is_err() {
            return false;
        }
    }
    salida.flush().is_ok()
}

/// Lanza la ventana y espera lo que conteste.
///
/// `None` es «se arrepintió», y no es lo mismo que una frase vacía: el agente
/// distingue las dos cosas y de eso depende que vuelva a preguntar.
fn preguntar(modo: &str, pedido: &Pedido) -> Option<Zeroizing<String>> {
    let yo = std::env::current_exe().ok()?;

    let hijo = Command::new(yo)
        .arg(DIALOGO)
        .env(ENV_MODO, modo)
        .env(ENV_DESC, &pedido.descripcion)
        .env(ENV_ETIQUETA, &pedido.etiqueta)
        .env(ENV_TITULO, &pedido.titulo)
        .env(ENV_ERROR, &pedido.error)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // El error del hijo va al del padre a propósito: si la ventana no
        // levanta, eso tiene que verse en el diario de la sesión y no
        // desaparecer.
        .stderr(Stdio::inherit())
        .spawn()
        .ok()?;

    // Se lee la primera línea y recién después se espera al hijo. Al revés
    // —esperar y leer— se traba si la respuesta llena la tubería: el hijo no
    // puede terminar de escribir y nosotros no leemos hasta que termine.
    let mut hijo = hijo;
    let salida_del_hijo = hijo.stdout.take()?;
    let mut lector = BufReader::new(salida_del_hijo);
    let mut linea = Zeroizing::new(String::new());
    let leido = lector.read_line(&mut linea).ok();

    let estado = hijo.wait().ok()?;
    if !estado.success() {
        return None;
    }
    leido?;

    // El salto final es del protocolo entre padre e hijo, no de la frase.
    let frase = Zeroizing::new(linea.trim_end_matches(['\r', '\n']).to_string());
    Some(frase)
}
