//! El protocolo que habla `gpg-agent` cuando necesita una contraseña.
//!
//! # Por qué existe esto
//!
//! Cuando GPG necesita la frase de una clave no la pide él: lanza un programa
//! aparte —un *pinentry*— y conversa con él por entrada y salida estándar. El
//! que había era el de GTK o el de curses, según lo que el envoltorio de Arch
//! encontrara, así que el diálogo más delicado del sistema era el único que no
//! se parecía al resto del escritorio. Peor: sin sesión gráfica visible caía a
//! curses y dibujaba el pedido en una terminal que nadie estaba mirando, con lo
//! cual importar una clave privada simplemente no hacía nada.
//!
//! Lo segundo ya está tapado —`/etc/pinentry/preexec`, que le enseña a
//! encontrar la sesión de Wayland— y esto es lo primero.
//!
//! # Por qué es un módulo puro
//!
//! Del otro lado hay un `gpg-agent` esperando una respuesta exacta por la
//! salida estándar. Cualquier cosa de más en ese canal —un aviso de GTK, una
//! línea de depuración— y la conversación se rompe de una forma que nadie
//! puede diagnosticar. Así que acá no se lee, no se escribe y no se abre
//! ninguna ventana: entra una línea, sale una respuesta, y eso se puede probar
//! con cien líneas raras sin lanzar nada.
//!
//! # El formato
//!
//! Está medido contra `pinentry-tty` 1.3.3, que es el que trae Arch:
//!
//! ```text
//! $ printf 'SETDESC hola\nGETINFO version\nBYE\n' | pinentry-tty
//! OK Pleased to meet you, process 1114645
//! OK
//! D 1.3.3
//! OK
//! OK closing connection
//! ```
//!
//! Los textos vienen con **codificación por porcentaje**: `%25` es un `%`,
//! `%0A` un salto de línea. Hay que decodificarlos al entrar y volver a
//! codificarlos al salir, o una frase con un `%` llega distinta de como se
//! escribió.

use zeroize::Zeroizing;

/// El código de «lo canceló la persona», tal como lo espera GPG.
///
/// Es `0x05000063`: la fuente 5 —Pinentry— en el byte alto y el 99
/// —`GPG_ERR_CANCELED`— en el bajo. Va el número y no una palabra porque es lo
/// que `gpg-agent` compara para distinguir «se arrepintió» de «se equivocó», y
/// de eso depende que reintente o no.
pub const CANCELADO: &str = "ERR 83886179 Operation cancelled <Pinentry>";

/// El de «esa orden no la conozco».
///
/// Medido: es lo que contesta `pinentry-tty` a una orden inventada, y la fuente
/// no es Pinentry sino libassuan —`0x20000000 | 275`—, porque la genera su
/// despachador antes de llegar al programa. Se copia tal cual en vez de armar
/// una con nuestra fuente: es la línea que todos los pinentry devuelven y con
/// la que `gpg-agent` está probado.
pub const ORDEN_DESCONOCIDA: &str = "ERR 536871187 Unknown IPC command <User defined source 1>";

/// El de «esa orden la conozco, pero ese argumento no».
///
/// `0x05000118`, con el 280 —`GPG_ERR_ASS_PARAMETER`—. También medido: es lo
/// que contesta a un `GETINFO` de algo que no sabe.
pub const PARAMETRO_DESCONOCIDO: &str = "ERR 83886360 IPC parameter error <Pinentry>";

/// El de «no confirmó», para los diálogos de sí o no.
///
/// `0x05000072`, con el 114 —`GPG_ERR_NOT_CONFIRMED`—. Medido contra
/// `pinentry-tty`, que contesta exactamente `ERR 83886194 Not confirmed
/// <Pinentry>`.
pub const NO_CONFIRMADO: &str = "ERR 83886194 Not confirmed <Pinentry>";

/// Lo que hay que hacer con una línea del agente.
#[derive(Debug, PartialEq, Eq)]
pub enum Accion {
    /// Contestar esto y seguir escuchando.
    Responder(Vec<String>),
    /// Preguntarle la frase a la persona. La respuesta se contesta con
    /// [`respuesta_a_getpin`].
    PedirFrase,
    /// Preguntar sí o no. `una_sola_opcion` es el `--one-button` de Assuan: un
    /// aviso que sólo se puede aceptar.
    Confirmar { una_sola_opcion: bool },
    /// Mostrar un mensaje sin preguntar nada.
    Mostrar,
    /// Se terminó la conversación.
    Terminar,
}

/// Lo que el agente fue contando sobre lo que va a pedir.
///
/// Se acumula entre líneas: primero manda el texto, el título y el error de la
/// vez anterior, y recién después pide la frase.
#[derive(Debug, Default, Clone)]
pub struct Pedido {
    /// La explicación larga: de qué clave se trata.
    pub descripcion: String,
    /// La etiqueta corta del campo, «PIN» o «Frase».
    pub etiqueta: String,
    /// El título de la ventana.
    pub titulo: String,
    /// Por qué falló el intento anterior, si hubo uno.
    pub error: String,
    /// Qué clave es, tal como la nombra el agente. Sirve para recordar la
    /// frase; no se le muestra a nadie.
    pub clave: String,
}

impl Pedido {
    /// Deja el pedido como recién empezado.
    ///
    /// `RESET` no cierra la conversación: el agente lo usa para preguntar otra
    /// cosa por el mismo canal. Si no se limpiara, el segundo pedido saldría
    /// con el texto del primero — y con su mensaje de error, que es peor:
    /// diría «contraseña incorrecta» sobre algo que nadie intentó todavía.
    pub fn limpiar(&mut self) {
        *self = Self::default();
    }
}

/// Interpreta una línea del agente sobre el pedido que se viene armando.
pub fn interpretar(linea: &str, pedido: &mut Pedido) -> Accion {
    let linea = linea.trim_end_matches(['\r', '\n']);
    let (orden, resto) = match linea.split_once(' ') {
        Some((o, r)) => (o, r.trim()),
        None => (linea, ""),
    };

    match orden.to_ascii_uppercase().as_str() {
        "SETDESC" => {
            pedido.descripcion = decodificar(resto);
            ok()
        }
        "SETPROMPT" => {
            pedido.etiqueta = decodificar(resto);
            ok()
        }
        "SETTITLE" => {
            pedido.titulo = decodificar(resto);
            ok()
        }
        "SETERROR" => {
            pedido.error = decodificar(resto);
            ok()
        }
        "SETKEYINFO" => {
            pedido.clave = decodificar(resto);
            ok()
        }
        "GETPIN" => Accion::PedirFrase,
        "CONFIRM" => Accion::Confirmar {
            una_sola_opcion: resto.split_whitespace().any(|a| a == "--one-button"),
        },
        "MESSAGE" => Accion::Mostrar,
        "GETINFO" => Accion::Responder(match resto {
            "version" => vec![dato(env!("CARGO_PKG_VERSION")), "OK".into()],
            "pid" => vec![dato(&std::process::id().to_string()), "OK".into()],
            "flavor" => vec![dato("vasak"), "OK".into()],
            // Lo que no sabemos contestar se contesta que no se sabe, y no con
            // un dato inventado: el agente usa `ttyinfo` para decidir si puede
            // dibujar en una terminal, y mentirle ahí lo manda a un lugar donde
            // no hay nadie.
            _ => vec![PARAMETRO_DESCONOCIDO.into()],
        }),
        "RESET" => {
            pedido.limpiar();
            ok()
        }
        // Las opciones se aceptan y se ignoran a propósito. Son cosas como el
        // `ttyname`, el `lc-messages` o el `allow-external-password-cache`: un
        // pinentry gráfico no las necesita, y contestar error a una que no
        // entendemos hace que el agente se dé por vencido con todo el diálogo.
        "OPTION" | "NOP" | "HELP" | "SETOK" | "SETNOTOK" | "SETCANCEL" | "SETQUALITYBAR"
        | "SETQUALITYBAR_TT" | "SETTIMEOUT" | "SETREPEAT" | "SETREPEATERROR"
        | "SETGENPIN" | "SETGENPIN_TT" | "CLEARPASSPHRASE" => ok(),
        "BYE" => Accion::Terminar,
        "" => ok(),
        _ => Accion::Responder(vec![ORDEN_DESCONOCIDA.into()]),
    }
}

fn ok() -> Accion {
    Accion::Responder(vec!["OK".into()])
}

fn dato(texto: &str) -> String {
    format!("D {}", codificar(texto))
}

/// El saludo, que va antes de cualquier línea del agente.
///
/// El agente lo espera apenas lanza el programa: sin él, se queda esperando y
/// la operación de GPG no avanza.
pub fn saludo() -> String {
    format!("OK Pleased to meet you, process {}", std::process::id())
}

/// Lo que se contesta a `GETPIN` según lo que haya escrito la persona.
///
/// La frase va codificada: una que lleve un `%` o un salto de línea rompería el
/// protocolo tal cual, y GPG recibiría una distinta de la que se tecleó — que
/// se ve como «contraseña incorrecta» sin ninguna pista de por qué.
///
/// Y vuelve en `Zeroizing`, no en un `String` pelado: la línea que se arma acá
/// **contiene la frase**, y un `String` común queda en la memoria liberada
/// cuando se suelta. Que quien la reciba tenga que sostener el envase es a
/// propósito.
pub fn respuesta_a_getpin(frase: Option<&str>) -> Vec<Zeroizing<String>> {
    match frase {
        Some(frase) => {
            let codificada = codificar(frase);
            vec![
                Zeroizing::new(format!("D {codificada}")),
                Zeroizing::new("OK".to_string()),
            ]
        }
        None => vec![Zeroizing::new(CANCELADO.to_string())],
    }
}

/// Lo que se contesta a `CONFIRM`.
pub fn respuesta_a_confirm(acepto: bool) -> Vec<String> {
    if acepto {
        vec!["OK".into()]
    } else {
        vec![NO_CONFIRMADO.into()]
    }
}

/// Saca la codificación por porcentaje de un texto del agente.
///
/// Lo que no sea una secuencia válida se deja tal cual en vez de descartarse:
/// un `%` suelto en una descripción es texto que alguien escribió, y perderlo
/// deja el diálogo diciendo algo distinto de lo que el agente quiso decir.
pub fn decodificar(texto: &str) -> String {
    let bytes = texto.as_bytes();
    let mut salida = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(valor) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                salida.push(valor);
                i += 3;
                continue;
            }
        }
        salida.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&salida).into_owned()
}

/// Pone la codificación por porcentaje en lo que sale hacia el agente.
///
/// Sólo tres caracteres la necesitan: el `%`, porque es el de escape, y el
/// retorno y el salto de línea, porque terminan la línea del protocolo.
pub fn codificar(texto: &str) -> String {
    let mut salida = String::with_capacity(texto.len());
    for c in texto.chars() {
        match c {
            '%' => salida.push_str("%25"),
            '\r' => salida.push_str("%0D"),
            '\n' => salida.push_str("%0A"),
            otro => salida.push(otro),
        }
    }
    salida
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Las respuestas de `GETPIN` vienen envueltas para que se borren al
    /// soltarse; para compararlas alcanza con mirar el texto.
    fn texto(lineas: &[Zeroizing<String>]) -> Vec<String> {
        lineas.iter().map(|l| l.to_string()).collect()
    }

    fn interpretar_solo(linea: &str) -> Accion {
        let mut pedido = Pedido::default();
        interpretar(linea, &mut pedido)
    }

    /// La conversación que `pinentry-tty` 1.3.3 mantiene de verdad.
    ///
    /// Medida así, y es el contrato: si esto cambia, GPG deja de entendernos.
    ///
    /// ```text
    /// $ printf 'SETDESC hola\nGETINFO version\nBYE\n' | pinentry-tty
    /// OK Pleased to meet you, process 1114645
    /// OK
    /// D 1.3.3
    /// OK
    /// OK closing connection
    /// ```
    #[test]
    fn la_conversacion_tiene_la_forma_que_el_agente_espera() {
        assert!(saludo().starts_with("OK Pleased to meet you, process "));

        let mut pedido = Pedido::default();
        assert_eq!(
            interpretar("SETDESC hola", &mut pedido),
            Accion::Responder(vec!["OK".into()])
        );
        assert_eq!(pedido.descripcion, "hola");

        match interpretar("GETINFO version", &mut pedido) {
            Accion::Responder(lineas) => {
                assert!(lineas[0].starts_with("D "), "{lineas:?}");
                assert_eq!(lineas[1], "OK");
            }
            otra => panic!("{otra:?}"),
        }

        assert_eq!(interpretar("BYE", &mut pedido), Accion::Terminar);
    }

    /// Los códigos de error son números y no palabras, y son **estos**.
    ///
    /// `gpg-agent` los compara para decidir si reintenta o se rinde: si
    /// «canceló» llegara con el número de «no confirmó», volvería a preguntar
    /// una frase que la persona ya decidió no dar.
    #[test]
    fn los_codigos_de_error_son_los_que_gpg_compara() {
        // 0x05000063: fuente 5 (Pinentry), error 99 (GPG_ERR_CANCELED).
        assert_eq!(CANCELADO, "ERR 83886179 Operation cancelled <Pinentry>");
        assert_eq!(0x0500_0063, 83886179);
        // 0x05000072: error 114 (GPG_ERR_NOT_CONFIRMED). Medido contra
        // pinentry-tty, que contesta exactamente esta línea.
        assert_eq!(NO_CONFIRMADO, "ERR 83886194 Not confirmed <Pinentry>");
        assert_eq!(0x0500_0072, 83886194);
    }

    /// Los dos errores de «eso no lo entiendo», también medidos.
    ///
    /// Los tenía cruzados: la orden desconocida contestaba `83886162`, que es
    /// `GPG_ERR_INV_SESSION_KEY` —nada que ver— y el `GETINFO` raro contestaba
    /// el código de «orden desconocida». Lo que devuelve `pinentry-tty` es:
    ///
    /// ```text
    /// $ printf 'BAILAR\nGETINFO cualquiera\nBYE\n' | pinentry-tty
    /// ERR 536871187 Unknown IPC command <User defined source 1>
    /// ERR 83886360 IPC parameter error <Pinentry>
    /// ```
    #[test]
    fn lo_que_no_se_entiende_se_contesta_como_lo_hace_el_de_verdad() {
        // 0x20000000 | 275: la fuente es libassuan, no Pinentry, porque el
        // error lo genera su despachador antes de llegar al programa.
        assert_eq!(0x2000_0000 | 275, 536871187);
        assert_eq!(
            interpretar_solo("BAILAR"),
            Accion::Responder(vec![ORDEN_DESCONOCIDA.into()])
        );

        // 0x05000000 | 280 (GPG_ERR_ASS_PARAMETER), esta sí con fuente Pinentry.
        assert_eq!(0x0500_0000 | 280, 83886360);
        assert_eq!(
            interpretar_solo("GETINFO cualquiera"),
            Accion::Responder(vec![PARAMETRO_DESCONOCIDO.into()])
        );
    }

    #[test]
    fn getpin_pide_la_frase_y_confirm_pregunta_si_o_no() {
        assert_eq!(interpretar_solo("GETPIN"), Accion::PedirFrase);
        assert_eq!(
            interpretar_solo("CONFIRM"),
            Accion::Confirmar { una_sola_opcion: false }
        );
        assert_eq!(
            interpretar_solo("CONFIRM --one-button"),
            Accion::Confirmar { una_sola_opcion: true }
        );
        assert_eq!(interpretar_solo("MESSAGE"), Accion::Mostrar);
    }

    /// Una frase con un `%` o con un salto tiene que llegar igual.
    ///
    /// Sin codificarla, el `%` se leería como el escape de otra cosa y el salto
    /// terminaría la línea: GPG recibiría una frase distinta de la tecleada y
    /// lo único que se vería es «contraseña incorrecta».
    #[test]
    fn la_frase_viaja_codificada() {
        assert_eq!(
            texto(&respuesta_a_getpin(Some("100% seguro"))),
            vec!["D 100%25 seguro".to_string(), "OK".to_string()]
        );
        assert_eq!(
            texto(&respuesta_a_getpin(Some("dos\nlineas"))),
            vec!["D dos%0Alineas".to_string(), "OK".to_string()]
        );
        // Y lo que va y vuelve es lo mismo.
        for frase in ["simple", "100% seguro", "con\nsalto", "con\r\nlos dos", "ñandú €"] {
            assert_eq!(decodificar(&codificar(frase)), frase);
        }
    }

    #[test]
    fn cancelar_no_es_una_frase_vacia() {
        assert_eq!(texto(&respuesta_a_getpin(None)), vec![CANCELADO.to_string()]);
        // Una frase vacía sí es una respuesta, y es distinta de cancelar.
        assert_eq!(
            texto(&respuesta_a_getpin(Some(""))),
            vec!["D ".to_string(), "OK".to_string()]
        );
    }

    #[test]
    fn confirmar_o_no_tienen_respuestas_distintas() {
        assert_eq!(respuesta_a_confirm(true), vec!["OK".to_string()]);
        assert_eq!(respuesta_a_confirm(false), vec![NO_CONFIRMADO.to_string()]);
    }

    /// El texto del agente viene codificado y hay que decodificarlo.
    #[test]
    fn el_texto_del_agente_se_decodifica() {
        let mut pedido = Pedido::default();
        interpretar("SETDESC Clave%20de%20Pato%0A100%25", &mut pedido);
        assert_eq!(pedido.descripcion, "Clave de Pato\n100%");
    }

    /// Un `%` que no abre una secuencia válida se conserva.
    ///
    /// Descartarlo dejaría el diálogo diciendo algo distinto de lo que el
    /// agente quiso decir, y es texto que alguien escribió.
    #[test]
    fn un_porcentaje_suelto_no_se_pierde() {
        assert_eq!(decodificar("100% seguro"), "100% seguro");
        assert_eq!(decodificar("termina en %"), "termina en %");
        assert_eq!(decodificar("%zz no es hexa"), "%zz no es hexa");
    }

    /// `RESET` limpia, y sobre todo limpia el error.
    ///
    /// Sin esto, el segundo pedido de la misma conversación saldría diciendo
    /// «contraseña incorrecta» sobre algo que nadie intentó todavía.
    #[test]
    fn reset_borra_el_pedido_anterior() {
        let mut pedido = Pedido::default();
        interpretar("SETDESC vieja", &mut pedido);
        interpretar("SETERROR se equivocó", &mut pedido);
        interpretar("SETKEYINFO n/deadbeef", &mut pedido);
        interpretar("RESET", &mut pedido);
        assert_eq!(pedido.descripcion, "");
        assert_eq!(pedido.error, "");
        assert_eq!(pedido.clave, "");
    }

    /// Lo que no entendemos se acepta si es una opción, y se rechaza si es una
    /// orden.
    ///
    /// Contestar error a una `OPTION` desconocida hace que el agente abandone
    /// el diálogo entero, y las manda de a montones —`ttyname`, `lc-messages`,
    /// `allow-external-password-cache`— que a un diálogo gráfico no le dicen
    /// nada.
    #[test]
    fn las_opciones_se_aceptan_y_las_ordenes_raras_no() {
        for opcion in [
            "OPTION ttyname=/dev/pts/3",
            "OPTION lc-messages=es_AR.UTF-8",
            "OPTION allow-external-password-cache",
            "SETQUALITYBAR",
            "SETTIMEOUT 60",
            "NOP",
        ] {
            assert_eq!(
                interpretar_solo(opcion),
                Accion::Responder(vec!["OK".into()]),
                "{opcion}"
            );
        }

        match interpretar_solo("BAILAR") {
            Accion::Responder(lineas) => assert!(lineas[0].starts_with("ERR "), "{lineas:?}"),
            otra => panic!("{otra:?}"),
        }
    }

    /// Las órdenes no distinguen mayúsculas.
    #[test]
    fn la_orden_puede_venir_en_minuscula() {
        assert_eq!(interpretar_solo("getpin"), Accion::PedirFrase);
        assert_eq!(interpretar_solo("Bye"), Accion::Terminar);
    }

    /// Una línea vacía o con final de línea pegado no rompe nada.
    #[test]
    fn las_lineas_sucias_no_rompen() {
        assert_eq!(interpretar_solo(""), Accion::Responder(vec!["OK".into()]));
        assert_eq!(interpretar_solo("GETPIN\r\n"), Accion::PedirFrase);
        assert_eq!(interpretar_solo("GETPIN\n"), Accion::PedirFrase);
    }

    /// Ninguna línea de respuesta puede llevar un salto adentro.
    ///
    /// El protocolo es de a líneas: una respuesta con un salto en el medio se
    /// lee como dos, y la segunda como una orden que nadie mandó.
    #[test]
    fn ninguna_respuesta_lleva_un_salto_adentro() {
        let mut candidatas = vec![saludo(), CANCELADO.to_string(), NO_CONFIRMADO.to_string()];
        candidatas.extend(texto(&respuesta_a_getpin(Some("con\nsalto\r\ny retorno"))));
        candidatas.extend(respuesta_a_confirm(false));
        if let Accion::Responder(lineas) = interpretar_solo("GETINFO version") {
            candidatas.extend(lineas);
        }
        for linea in candidatas {
            assert!(!linea.contains('\n'), "{linea:?}");
            assert!(!linea.contains('\r'), "{linea:?}");
        }
    }
}
