//! The program ssh runs when it needs a key's passphrase.
//!
//! Without one, every `git push` asks again: ssh has nowhere to keep the
//! passphrase and no way to ask for it other than the terminal it was started
//! from. With one, the passphrase can live in the keyring — which PAM already
//! unlocks at login — and nobody has to type it again.
//!
//! ssh talks to this program through the file descriptors it inherits: the
//! prompt arrives as the first argument and the answer is whatever goes to
//! standard output. That makes standard output precious. Anything else that
//! writes a line there — a GTK warning, a WebKit message — becomes part of the
//! passphrase and authentication fails for a reason nobody could guess, so the
//! real one is put aside at startup and everything else is sent to /dev/null.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::secret_service::Keyring;

/// The descriptor ssh is listening on, before it is taken out of harm's way.
static ANSWER: OnceLock<OwnedFd> = OnceLock::new();

/// Moves standard output somewhere only we can write to it.
fn claim_stdout() {
    use std::os::fd::FromRawFd;

    unsafe {
        let saved = libc::dup(libc::STDOUT_FILENO);
        if saved >= 0 {
            let _ = ANSWER.set(OwnedFd::from_raw_fd(saved));
        }

        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDOUT_FILENO);
            libc::close(devnull);
        }
    }
}

/// Hands the passphrase to ssh and ends the process.
///
/// Nothing after this can run: the passphrase has been handed over and the only
/// honest thing left is to stop existing.
pub fn answer(passphrase: &str) -> ! {
    if let Some(fd) = ANSWER.get() {
        let line = Zeroizing::new(format!("{passphrase}\n"));
        let mut written = 0;
        while written < line.len() {
            let n = unsafe {
                libc::write(
                    fd.as_raw_fd(),
                    line.as_ptr().add(written) as *const libc::c_void,
                    line.len() - written,
                )
            };
            if n <= 0 {
                break;
            }
            written += n as usize;
        }
    }
    std::process::exit(0)
}

/// Nobody typed anything: ssh has to know it was a refusal and not an empty
/// passphrase, and that is what a non-zero exit means.
pub fn give_up() -> ! {
    std::process::exit(1)
}

/// The key ssh is asking about.
///
/// The prompt is written for a person, not for us: `ssh` says
/// `Enter passphrase for key '/home/pato/.ssh/id_ed25519':` and `ssh-add` says
/// `Enter passphrase for /home/pato/.ssh/id_ed25519:`. Both carry the path, and
/// the path is what the passphrase is filed under.
pub fn key_path_from(prompt: &str) -> Option<String> {
    // Una URL no es una ruta: sin esto, `Username for 'https://github.com': `
    // terminaba archivado como la clave `//github.com'`.
    if is_git_credential_prompt(prompt) {
        return None;
    }

    if let Some(start) = prompt.find('\'') {
        let rest = &prompt[start + 1..];
        if let Some(end) = rest.find('\'') {
            let quoted = &rest[..end];
            if quoted.starts_with('/') {
                return Some(quoted.to_string());
            }
        }
    }

    // Sin comillas: la ruta llega hasta los dos puntos finales.
    let start = prompt.find('/')?;
    let path = prompt[start..].trim_end();
    let path = path.strip_suffix(':').unwrap_or(path).trim_end();
    (!path.is_empty()).then(|| path.to_string())
}

/// Git preguntando el usuario o la contraseña de un remoto HTTPS.
///
/// Git, sin un credential helper que ya la tenga, le pregunta a SSH_ASKPASS lo
/// mismo que a ssh: `Username for 'https://github.com': ` y después
/// `Password for 'https://usuario@github.com': `. No es una frase de clave y no
/// va al diálogo de «Clave SSH»: lo que se escribía ahí se mandaba a GitHub como
/// nombre de usuario. Ssh nunca pone una URL en sus pedidos; git siempre.
pub fn is_git_credential_prompt(prompt: &str) -> bool {
    prompt.contains("://")
}

/// Which of the two questions git is asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GitField {
    Username,
    Password,
    /// The password of a client certificate (`http.sslCertPasswordProtected`).
    /// `host` then carries the certificate's path.
    Certificate,
}

/// A git credential question, taken apart for the dialog.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct GitPrompt {
    pub field: GitField,
    /// `github.com`, or `host:port` when there is one.
    pub host: String,
    /// The user the password is for, when git already knows it.
    pub username: Option<String>,
}

/// Takes apart `Username for 'https://github.com': ` and
/// `Password for 'https://usuario@github.com': `.
///
/// The word in front is what git asks; the URL says for whom. A user inside the
/// URL also means it is the password being asked, which covers a git that words
/// the question some other way.
pub fn git_prompt_from(prompt: &str) -> Option<GitPrompt> {
    if !is_git_credential_prompt(prompt) {
        return None;
    }

    let start = prompt.find('\'').map_or(0, |i| i + 1);
    let rest = &prompt[start..];
    let url = rest.find('\'').map_or(rest, |end| &rest[..end]);
    let (scheme, location) = url.split_once("://")?;

    // La contraseña de un certificado de cliente llega como `cert:///ruta`, sin
    // servidor: lo que hay que mostrar es de qué archivo es.
    if scheme == "cert" {
        let path = format!("/{}", location.trim_start_matches('/'));
        return Some(GitPrompt {
            field: GitField::Certificate,
            host: path,
            username: None,
        });
    }

    let authority = location.split('/').next()?;

    let (username, host) = match authority.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()), host),
        None => (None, authority),
    };
    if host.is_empty() {
        return None;
    }

    let asks_password = prompt.trim_start().starts_with("Password") || username.is_some();
    let field = if asks_password {
        GitField::Password
    } else {
        GitField::Username
    };

    Some(GitPrompt {
        field,
        host: host.to_string(),
        username,
    })
}

/// What the dialog needs to say.
pub struct Request {
    pub prompt: String,
    pub key_path: Option<String>,
    /// Set when it is git asking for a remote's credentials, not ssh for a key.
    pub git: Option<GitPrompt>,
}

impl Request {
    /// A name for the key, for a dialog that has to fit on one line.
    pub fn key_name(&self) -> String {
        self.key_path
            .as_deref()
            .and_then(|path| path.rsplit('/').next())
            .unwrap_or("SSH")
            .to_string()
    }
}

/// Reads what ssh asked, and answers straight away if the keyring knows it.
///
/// Returns only when somebody has to be asked: the fast path never opens a
/// window, which is the whole point — a key whose passphrase is already in the
/// keyring should feel like a key with no passphrase at all.
pub fn start() -> Request {
    claim_stdout();

    let prompt = std::env::args().nth(1).unwrap_or_default();

    // Git no pasa por el llavero desde acá: lo guarda su credential helper
    // (libsecret, que es este llavero) cuando la autenticación sale bien, y la
    // próxima vez ni siquiera pregunta.
    if let Some(git) = git_prompt_from(&prompt) {
        return Request {
            prompt,
            key_path: None,
            git: Some(git),
        };
    }

    // Una URL que no se pudo interpretar sigue sin ser una clave SSH: se
    // rechaza, como antes, en vez de caer en el diálogo de «Clave SSH».
    if is_git_credential_prompt(&prompt) {
        eprintln!(
            "[vasak-ssh-askpass] «{}» es un pedido de git que no se pudo interpretar",
            prompt.trim()
        );
        give_up();
    }

    let key_path = key_path_from(&prompt);

    if let Some(path) = key_path.as_deref() {
        if let Some(passphrase) = stored_passphrase(path) {
            answer(&passphrase);
        }
    }

    Request {
        prompt,
        key_path,
        git: None,
    }
}

/// Asks the keyring, and stays quiet if it cannot answer.
///
/// Every failure here means the same thing to whoever is sitting in front of
/// the machine: they are about to be asked for the passphrase. The reason goes
/// to the log, where it can be read afterwards, and never to standard output.
fn stored_passphrase(key_path: &str) -> Option<Zeroizing<String>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;

    runtime.block_on(async {
        match Keyring::open().await {
            Ok(keyring) => match keyring.passphrase_for(key_path).await {
                Ok(found) => found,
                Err(error) => {
                    eprintln!("[vasak-ssh-askpass] no se pudo consultar el llavero: {error}");
                    None
                }
            },
            Err(error) => {
                eprintln!("[vasak-ssh-askpass] no se pudo abrir el llavero: {error}");
                None
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Las dos formas en que ssh escribe el pedido. Si la ruta no se reconoce,
    /// la frase no se puede ni buscar ni guardar: el llavero deja de servir y
    /// nadie entiende por qué.
    #[test]
    fn reconoce_la_clave_en_los_dos_formatos() {
        assert_eq!(
            key_path_from("Enter passphrase for key '/home/pato/.ssh/id_ed25519': ").as_deref(),
            Some("/home/pato/.ssh/id_ed25519")
        );
        assert_eq!(
            key_path_from("Enter passphrase for /home/pato/.ssh/id_ed25519: ").as_deref(),
            Some("/home/pato/.ssh/id_ed25519")
        );
        // Traducido, que es como llega en un sistema en español.
        assert_eq!(
            key_path_from("Introduzca la frase para /home/pato/.ssh/id_rsa:").as_deref(),
            Some("/home/pato/.ssh/id_rsa")
        );
    }

    /// Hay pedidos que no son por una clave —confirmaciones de huella del
    /// servidor, por ejemplo—: ahí no hay nada que guardar y hay que preguntar.
    #[test]
    fn sin_ruta_no_inventa_una() {
        assert!(key_path_from("Are you sure you want to continue connecting?").is_none());
    }

    /// Git por HTTPS pregunta por SSH_ASKPASS. No es una clave: ni ruta ni
    /// diálogo de «Clave SSH».
    #[test]
    fn los_pedidos_de_git_por_https_no_son_claves() {
        for prompt in [
            "Username for 'https://github.com': ",
            "Password for 'https://erv0gbup@github.com': ",
        ] {
            assert!(is_git_credential_prompt(prompt), "{prompt}");
            assert!(key_path_from(prompt).is_none(), "{prompt}");
        }
        assert!(!is_git_credential_prompt(
            "Enter passphrase for key '/home/pato/.ssh/id_ed25519': "
        ));
    }

    /// El primer pedido de git por HTTPS: todavía no sabe quién sos, así que
    /// el diálogo tiene que pedir el usuario, en texto, y decir para qué
    /// servidor.
    #[test]
    fn el_pedido_de_usuario_de_git_se_entiende() {
        assert_eq!(
            git_prompt_from("Username for 'https://github.com': "),
            Some(GitPrompt {
                field: GitField::Username,
                host: "github.com".into(),
                username: None,
            })
        );
    }

    /// El segundo pedido ya trae el usuario en la URL, y el servidor puede
    /// tener puerto. Los dos se muestran en el diálogo: sin el puerto, dos
    /// servidores en la misma máquina se ven iguales.
    #[test]
    fn el_pedido_de_contrasena_trae_el_usuario_y_el_puerto() {
        assert_eq!(
            git_prompt_from("Password for 'https://pato@gitlab.example.com:8443': "),
            Some(GitPrompt {
                field: GitField::Password,
                host: "gitlab.example.com:8443".into(),
                username: Some("pato".into()),
            })
        );
    }

    /// Si en la URL hay un usuario, lo que falta es la contraseña, diga lo que
    /// diga la palabra del principio. Si se pidiera en un campo de texto, la
    /// contraseña quedaría a la vista de quien mire la pantalla.
    #[test]
    fn un_usuario_en_la_url_implica_que_se_pide_la_contrasena() {
        let prompt = git_prompt_from("Contraseña para 'https://pato@github.com': ")
            .expect("es un pedido de git");
        assert_eq!(prompt.field, GitField::Password);
        assert_eq!(prompt.username.as_deref(), Some("pato"));
        assert_eq!(prompt.host, "github.com");
    }

    /// Con `credential.useHttpPath` git pone la ruta del repositorio en la URL.
    /// El servidor es el mismo; la ruta no es parte de él.
    #[test]
    fn la_ruta_del_repositorio_no_es_parte_del_servidor() {
        let prompt =
            git_prompt_from("Username for 'https://github.com/Vasak-OS/vasak-keyring.git': ")
                .expect("es un pedido de git");
        assert_eq!(prompt.host, "github.com");
        assert_eq!(prompt.field, GitField::Username);
    }

    /// Hay servidores donde el usuario es un correo. Git lo escribe tal cual,
    /// con su arroba, y el servidor es lo que queda después de la última.
    #[test]
    fn un_usuario_que_es_un_correo_no_se_confunde_con_el_servidor() {
        let prompt = git_prompt_from("Password for 'https://pato@vasak.net.ar@git.example.com': ")
            .expect("es un pedido de git");
        assert_eq!(prompt.username.as_deref(), Some("pato@vasak.net.ar"));
        assert_eq!(prompt.host, "git.example.com");
        assert_eq!(prompt.field, GitField::Password);
    }

    /// Lo que pregunta ssh sigue yendo al diálogo de la clave.
    #[test]
    fn los_pedidos_de_ssh_no_son_de_git() {
        for prompt in [
            "Enter passphrase for key '/home/pato/.ssh/id_ed25519': ",
            "Enter passphrase for /home/pato/.ssh/id_ed25519: ",
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
            "",
        ] {
            assert_eq!(git_prompt_from(prompt), None, "{prompt}");
        }
    }

    /// El diálogo compara `field` con "username" y "password". Si llegara
    /// "Username", un pedido de contraseña se mostraría como uno de usuario, en
    /// un campo de texto, y nada en Rust ni en TypeScript avisaría.
    #[test]
    fn el_pedido_llega_al_dialogo_con_el_campo_en_minusculas() {
        let usuario = git_prompt_from("Username for 'https://github.com': ").unwrap();
        assert_eq!(
            serde_json::to_value(&usuario).unwrap(),
            serde_json::json!({
                "field": "username",
                "host": "github.com",
                "username": null,
            })
        );

        let contrasena = git_prompt_from("Password for 'https://pato@github.com': ").unwrap();
        assert_eq!(
            serde_json::to_value(&contrasena).unwrap(),
            serde_json::json!({
                "field": "password",
                "host": "github.com",
                "username": "pato",
            })
        );
    }

    /// Todo pedido con una URL es de git, y ninguno puede terminar en el
    /// diálogo de «Clave SSH» (el bug que arregló #39). La contraseña de un
    /// certificado de cliente (`http.sslCertPasswordProtected`) llega con el
    /// protocolo `cert` y sin servidor: `git_prompt_from` devuelve `None`, y
    /// `start()` sigue de largo hasta el diálogo de SSH, cuando antes del
    /// cambio se rechazaba.
    #[test]
    fn ningun_pedido_con_url_cae_al_dialogo_de_ssh() {
        for prompt in [
            "Password for 'cert:////home/pato/cliente.p12': ",
            "Password for 'cert:///home/pato/cliente.p12': ",
        ] {
            assert!(is_git_credential_prompt(prompt), "{prompt}");
            assert!(git_prompt_from(prompt).is_some(), "{prompt}");
        }
    }

    /// La contraseña de un certificado de cliente no tiene servidor: lo que el
    /// diálogo muestra es la ruta del archivo. Git la escribe con cuatro barras
    /// (`cert://` más una ruta absoluta) y tiene que verse como una ruta, con
    /// una sola.
    #[test]
    fn la_contrasena_de_un_certificado_trae_la_ruta_con_una_sola_barra() {
        for prompt in [
            "Password for 'cert:////home/pato/cliente.p12': ",
            "Password for 'cert:///home/pato/cliente.p12': ",
        ] {
            assert_eq!(
                git_prompt_from(prompt),
                Some(GitPrompt {
                    field: GitField::Certificate,
                    host: "/home/pato/cliente.p12".into(),
                    username: None,
                }),
                "{prompt}"
            );
        }
    }

    /// El diálogo distingue el certificado por `field == "certificate"`. Con
    /// otro nombre lo mostraría como un pedido de usuario, en texto visible.
    #[test]
    fn el_certificado_llega_al_dialogo_como_certificate() {
        let certificado =
            git_prompt_from("Password for 'cert:////home/pato/cliente.p12': ").unwrap();
        assert_eq!(
            serde_json::to_value(&certificado).unwrap(),
            serde_json::json!({
                "field": "certificate",
                "host": "/home/pato/cliente.p12",
                "username": null,
            })
        );
    }

    #[test]
    fn el_nombre_para_el_dialogo_es_el_del_archivo() {
        let request = Request {
            prompt: String::new(),
            key_path: Some("/home/pato/.ssh/id_ed25519".into()),
            git: None,
        };
        assert_eq!(request.key_name(), "id_ed25519");
    }
}
