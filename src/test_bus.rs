//! Un `org.freedesktop.DBus` falso para probar las dos puertas del llavero.
//!
//! Las dos —la del portal en `portal_secret` y la del almacén cifrado en
//! `dbus_api`— le preguntan al bus las mismas dos cosas: quién tiene un nombre,
//! y qué pid hay detrás de una conexión. Sobre una conexión punto a punto no hay
//! `dbus-daemon` que conteste, así que esto se publica en `/org/freedesktop/DBus`
//! del otro lado y contesta lo que el bus de la sesión contestaría.
//!
//! Vive aparte porque son las dos reglas más delicadas del llavero, y una copia
//! por puerta se actualiza cuando alguien se acuerda.

use std::path::PathBuf;
use std::sync::Arc;

use futures_util::StreamExt;
use tokio::sync::Mutex;
use zbus::interface;

/// Adónde pregunta el llavero, y adónde se publica el bus falso.
pub const RUTA_BUS: &str = "/org/freedesktop/DBus";

/// Cuánto se espera una respuesta que tiene que llegar. Si no llega, el fallo lo
/// dice la prueba nombrando el caso, en vez de quedarse colgada.
pub const ESPERA: std::time::Duration = std::time::Duration::from_secs(10);

/// Cuánto se espera a que una conexión recién hecha conteste algo. Es el tiempo
/// entre un mensaje y el siguiente, no el de una prueba.
const ESPERA_DE_ENTRADA: std::time::Duration = std::time::Duration::from_millis(500);

/// El bus mínimo: sólo las dos preguntas que hacen las puertas.
///
/// `preguntados` guarda por qué nombres se preguntó, porque el nombre es la
/// fuente de verdad de una de las dos condiciones y una errata ahí no se ve en
/// el resultado: abriría la puerta a quien tenga el nombre mal escrito y la
/// cerraría al de verdad.
pub struct BusFalso {
    /// Quién contesta tener el nombre. `None` es el `NameHasNoOwner` de verdad,
    /// no una respuesta que no llega.
    duenia: Option<String>,
    /// El pid que el bus le atribuye a cualquier conexión. `None` es el error
    /// con el que contesta un bus que no conoce la conexión.
    pid: Option<u32>,
    preguntados: Arc<Mutex<Vec<String>>>,
}

impl BusFalso {
    pub fn nuevo(duenia: Option<&str>, pid: Option<u32>) -> Self {
        Self {
            duenia: duenia.map(str::to_owned),
            pid,
            preguntados: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// El registro de los nombres preguntados, para leerlo después de haber
    /// publicado el bus.
    pub fn registro(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.preguntados)
    }
}

#[interface(name = "org.freedesktop.DBus")]
impl BusFalso {
    #[zbus(name = "GetNameOwner")]
    async fn duenia_de(&self, nombre: &str) -> Result<String, zbus::fdo::Error> {
        self.preguntados.lock().await.push(nombre.to_owned());
        match &self.duenia {
            Some(duenia) => Ok(duenia.clone()),
            // El error con el que un bus de verdad contesta que nadie tiene el
            // nombre. Es una respuesta, no una pregunta que salió mal.
            None => Err(zbus::fdo::Error::NameHasNoOwner(nombre.to_owned())),
        }
    }

    // En `PascalCase` como lo escribe el bus, y no como lo dejaría el
    // `PascalCase` automático: produciría `GetConnectionUnixProcessId` y el bus
    // de verdad no lo entiende.
    #[zbus(name = "GetConnectionUnixProcessID")]
    fn pid_de(&self, emisor: &str) -> Result<u32, zbus::fdo::Error> {
        self.pid.ok_or_else(|| {
            zbus::fdo::Error::NameHasNoOwner(format!("no se conoce el pid de {emisor}"))
        })
    }
}

/// Publica el bus falso en `conn`, que es la punta a la que le pregunta la otra.
pub async fn publicar(conn: &zbus::Connection, bus: BusFalso) {
    conn.object_server()
        .at(RUTA_BUS, bus)
        .await
        .expect("no se pudo publicar el bus falso");
}

/// Una ida y vuelta antes de que la prueba pregunte nada.
///
/// Recién construida la conexión, el primer mensaje se pierde: la otra punta
/// todavía no está leyendo. Es una cosa de `p2p` y no del llavero, pero sin esto
/// la primera pregunta de cada prueba se queda esperando una respuesta que no va
/// a llegar, y el fallo aparece como una compuerta de tiempo y no como lo que es.
///
/// El intento perdido se corta rápido a propósito: no está fallando, está
/// abriendo la conexión.
pub async fn calentar(conn: &zbus::Connection) {
    for _ in 0..5 {
        let pregunta = conn.call_method(
            Some("org.freedesktop.DBus"),
            RUTA_BUS,
            Some("org.freedesktop.DBus"),
            "GetConnectionUnixProcessID",
            &(":1.0",),
        );
        if tokio::time::timeout(ESPERA_DE_ENTRADA, pregunta)
            .await
            .is_ok()
        {
            return;
        }
    }
    panic!("el bus de la prueba no contestó ni una vez: la conexión no quedó viva");
}

/// Un llamado a método con el emisor que se le ponga en la cabecera.
///
/// Sobre una conexión punto a punto no hay `dbus-daemon` que le asigne un nombre
/// único a nadie, así que `call_method` manda los mensajes sin emisor y toda
/// puerta cortaría en la rama de «vino sin emisor». Poner el emisor a mano es
/// justo lo que un bus real garantiza —es el broker el que lo pone, nunca el que
/// pide—, y es lo que permite fingir ser el portal, el sincronizador o un
/// impostor.
pub fn armar<B>(
    ruta: &str,
    interfaz: &str,
    metodo: &str,
    emisor: Option<&str>,
    cuerpo: &B,
) -> zbus::Message
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    let mut armado = zbus::Message::method_call(ruta, metodo)
        .expect("no se pudo armar el pedido")
        .interface(interfaz)
        .expect("interfaz del pedido");
    if let Some(emisor) = emisor {
        armado = armado.sender(emisor).expect("emisor del pedido");
    }
    armado
        .build(cuerpo)
        .expect("no se pudo serializar el pedido")
}

/// La respuesta al mensaje con ese `serial`, sea un retorno o un error.
pub async fn primera_respuesta(
    salientes: &mut zbus::MessageStream,
    serial: std::num::NonZeroU32,
) -> zbus::Message {
    tokio::time::timeout(ESPERA, async {
        while let Some(mensaje) = salientes.next().await {
            let Ok(mensaje) = mensaje else { continue };
            if mensaje.header().reply_serial() == Some(serial) {
                return Some(mensaje);
            }
        }
        None
    })
    .await
    .unwrap_or_else(|_| panic!("no llegó respuesta al pedido en {ESPERA:?}"))
    .unwrap_or_else(|| panic!("se cortó la conexión antes de la respuesta con serial {serial}"))
}

/// Un pid que no existe, sin adivinar un número alto.
///
/// Es la forma de que `/proc/<pid>/exe` no se pueda leer. Con la unidad en un
/// namespace de usuario el error era `EACCES` y no `ENOENT`, pero para una puerta
/// es lo mismo: la lectura falla y el pedido se rechaza.
pub fn pid_inexistente() -> u32 {
    (1..)
        .map(|n| u32::MAX - n)
        .find(|pid| !PathBuf::from(format!("/proc/{pid}")).exists())
        .expect("algún pid tiene que estar libre")
}
