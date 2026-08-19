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

        let devnull = libc::open(b"/dev/null\0".as_ptr() as *const _, libc::O_WRONLY);
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

/// What the dialog needs to say.
pub struct Request {
    pub prompt: String,
    pub key_path: Option<String>,
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
    let key_path = key_path_from(&prompt);

    if let Some(path) = key_path.as_deref() {
        if let Some(passphrase) = stored_passphrase(path) {
            answer(&passphrase);
        }
    }

    Request { prompt, key_path }
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

    #[test]
    fn el_nombre_para_el_dialogo_es_el_del_archivo() {
        let request = Request {
            prompt: String::new(),
            key_path: Some("/home/pato/.ssh/id_ed25519".into()),
        };
        assert_eq!(request.key_name(), "id_ed25519");
    }
}
