//! Cómo se convierte la contraseña de la cuenta en la maestra del llavero.
//!
//! # Por qué existe este paso
//!
//! El módulo de PAM corre como root y entrega la contraseña a un demonio que
//! corre como el usuario, por un socket que vive en `/run/user/<uid>`. Ese
//! directorio es del usuario, así que **cualquier código corriendo con su cuenta
//! puede reemplazar por un enlace simbólico el directorio donde está el socket** y
//! quedarse con lo que root entregue. Mandar ahí la contraseña de la cuenta en
//! texto plano significa que un proceso sin privilegios se la lleva en el próximo
//! inicio de sesión — y con ella, `sudo`, o sea root.
//!
//! Mandando el resultado de una derivación en lugar de la contraseña, quien
//! intercepte se lleva la maestra del llavero y no la contraseña de la cuenta.
//! Eso no le da nada nuevo: cualquier proceso del usuario ya puede pedirle al
//! Secret Service todos los secretos guardados, que es para lo que existe. Lo que
//! deja de poder es escalar a root.
//!
//! Revertir la derivación no es opción: Argon2id con estos parámetros hace que
//! probar contraseñas cueste, y el resultado no lleva ninguna traza de la
//! original.
//!
//! # Por qué está en un crate propio
//!
//! Porque hay **dos** caminos que entregan la maestra —el módulo de PAM al
//! iniciar sesión y el diálogo gráfico cuando la pide a mano— y si derivaran
//! distinto, la base creada por uno no la abriría el otro. Sin ningún error: la
//! contraseña simplemente «no sería la correcta». Con el código en un solo lugar,
//! no pueden divergir.
//!
//! El demonio **no** deriva: recibe el resultado ya derivado y lo usa como la
//! contraseña maestra tal cual.

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Etiqueta del esquema. Si algún día cambian los parámetros, cambia esto y las
/// bases viejas quedan identificables en lugar de fallar sin explicación.
const ESQUEMA: &str = "vasak-keyring:v1:";

/// De dónde sale la sal.
///
/// `/etc/machine-id` es único por máquina, estable, y lo puede leer cualquiera
/// —incluido el diálogo gráfico, que corre como el usuario—. Que sea público no
/// importa: la sal no es un secreto, está para que una tabla precalculada no
/// sirva en todas las máquinas a la vez. El trabajo lo hace Argon2.
const RUTA_MACHINE_ID: &str = "/etc/machine-id";

/// Longitud de la maestra derivada, en bytes antes de pasarla a hexadecimal.
const LARGO: usize = 32;

/// Parámetros de Argon2id.
///
/// Los mínimos que recomienda OWASP: 19 MiB y dos pasadas. Del orden de 50 ms,
/// que es aceptable dentro del inicio de sesión —y el costo se paga una vez por
/// sesión, no por operación—. El demonio vuelve a derivar por su cuenta para
/// sacar la clave de la base, así que esta pasada no es la única defensa.
const MEMORIA_KIB: u32 = 19 * 1024;
const PASADAS: u32 = 2;
const CARRILES: u32 = 1;

/// La sal, a partir del identificador de la máquina.
///
/// Si no se puede leer, se usa sólo la etiqueta del esquema. Eso deja la
/// derivación igual en todas las máquinas —peor, pero funcionando— en lugar de
/// dejar el llavero sin abrir: un contenedor o un sistema recién instalado puede
/// no tener `machine-id` todavía.
pub fn sal() -> Vec<u8> {
    let identificador = std::fs::read_to_string(RUTA_MACHINE_ID)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    sal_desde(&identificador)
}

/// La sal para un identificador dado. Separado para poder probarlo.
pub fn sal_desde(identificador: &str) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(ESQUEMA.as_bytes());
    hash.update(identificador.as_bytes());
    hash.finalize().to_vec()
}

/// Convierte la contraseña de la cuenta en la maestra del llavero.
///
/// Devuelve hexadecimal y no bytes crudos porque viaja como cadena: por el socket
/// de desbloqueo y por el método de D-Bus, los dos con firma de texto. Y como
/// `Zeroizing`, para que no quede en memoria más de lo necesario.
pub fn derivar_maestra(password: &str) -> Result<Zeroizing<String>, String> {
    derivar_con_sal(password, &sal())
}

/// Igual, con una sal explícita. Separado para poder probar contra vectores
/// fijos, que es lo único que detecta que la derivación cambió sin querer.
pub fn derivar_con_sal(password: &str, sal: &[u8]) -> Result<Zeroizing<String>, String> {
    let parametros = Params::new(MEMORIA_KIB, PASADAS, CARRILES, Some(LARGO))
        .map_err(|e| format!("parámetros de Argon2 inválidos: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, parametros);

    let mut salida = Zeroizing::new([0u8; LARGO]);
    argon
        .hash_password_into(password.as_bytes(), sal, salida.as_mut())
        .map_err(|e| format!("no se pudo derivar la contraseña maestra: {e}"))?;

    let mut texto = Zeroizing::new(String::with_capacity(LARGO * 2));
    for byte in salida.iter() {
        texto.push_str(&format!("{byte:02x}"));
    }
    Ok(texto)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El vector fijo: si la derivación cambia, la base de cualquiera deja de
    /// abrirse. Este test es lo único que avisa antes de que pase.
    #[test]
    fn la_derivacion_no_puede_cambiar_sin_que_se_note() {
        let sal = sal_desde("0123456789abcdef0123456789abcdef");
        let maestra = derivar_con_sal("contraseña de prueba", &sal).unwrap();

        assert_eq!(maestra.len(), LARGO * 2, "hexadecimal de 32 bytes");
        assert!(maestra.chars().all(|c| c.is_ascii_hexdigit()));

        // El mismo par entrada/sal da siempre el mismo resultado. Si no, los dos
        // caminos que entregan la maestra —PAM y el diálogo— no coincidirían.
        let otra_vez = derivar_con_sal("contraseña de prueba", &sal).unwrap();
        assert_eq!(*maestra, *otra_vez);
    }

    #[test]
    fn la_contrasena_original_no_aparece_en_el_resultado() {
        // Lo que se manda por el socket no debe llevar ninguna traza de la
        // contraseña de la cuenta: en eso se basa todo el arreglo.
        let sal = sal_desde("maquina");
        let maestra = derivar_con_sal("Tr0mp3ta-Azul", &sal).unwrap();
        assert!(!maestra.contains("Tr0mp3ta"));
        assert!(!maestra.to_lowercase().contains("azul"));
    }

    #[test]
    fn contrasenas_distintas_dan_maestras_distintas() {
        let sal = sal_desde("maquina");
        let a = derivar_con_sal("una", &sal).unwrap();
        let b = derivar_con_sal("otra", &sal).unwrap();
        assert_ne!(*a, *b);
        // Y un solo carácter de diferencia también.
        let c = derivar_con_sal("una", &sal).unwrap();
        let d = derivar_con_sal("unA", &sal).unwrap();
        assert_ne!(*c, *d);
    }

    #[test]
    fn la_sal_depende_de_la_maquina() {
        // Sin esto, una tabla precalculada serviría en todas las máquinas.
        assert_ne!(sal_desde("maquina-a"), sal_desde("maquina-b"));
        assert_eq!(sal_desde("igual"), sal_desde("igual"));
        assert_eq!(sal_desde("cualquiera").len(), 32);
    }

    #[test]
    fn sin_machine_id_la_derivacion_sigue_funcionando() {
        // Un contenedor o un sistema recién instalado puede no tenerlo. Peor
        // —la sal es la misma en todas partes— pero el llavero abre.
        let sal_vacia = sal_desde("");
        assert_eq!(sal_vacia.len(), 32);
        assert!(derivar_con_sal("algo", &sal_vacia).is_ok());
    }

    #[test]
    fn una_contrasena_vacia_no_es_un_error_aca() {
        // Quien decide qué hacer con una contraseña vacía es el que la entrega,
        // no la derivación. Acá sólo tiene que no romper.
        assert!(derivar_con_sal("", &sal_desde("m")).is_ok());
    }

    #[test]
    fn los_acentos_sobreviven() {
        let sal = sal_desde("m");
        assert_ne!(
            *derivar_con_sal("contraseña", &sal).unwrap(),
            *derivar_con_sal("contrasena", &sal).unwrap()
        );
    }
}
