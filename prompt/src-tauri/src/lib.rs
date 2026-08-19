//! The dialog that asks for the password when the login did not hand it over.
//!
//! The master password normally arrives from `pam_vasak_keyring` at login. When
//! that did not happen — the daemon was restarted mid-session, the login carried
//! no password (autologin, fingerprint), or PAM is not configured — the daemon
//! runs this, and it hands the password over through the same private interface
//! the PAM module uses.
//!
//! One dialog, one answer, and the process is gone: it is spawned per request
//! rather than left resident, because a WebKit process costs about 150 MB and an
//! unlock is asked for a handful of times in the life of a session.
//!
//! The exit code is the answer — 0 unlocked, anything else did not. The daemon
//! checks its own state anyway; this only saves it from waiting.

use tauri::{WebviewUrl, WebviewWindowBuilder};
use zeroize::Zeroizing;

pub mod secret_service;
pub mod ssh_askpass;

const WINDOW_LABEL: &str = "unlock-dialog";
const DIALOG_WIDTH: f64 = 460.0;
const DIALOG_HEIGHT: f64 = 300.0;

const KEYRING_SERVICE: &str = "org.freedesktop.secrets";
const KEYRING_PATH: &str = "/org/vasak/keyring";
const KEYRING_INTERFACE: &str = "org.vasak.Keyring";
const UNLOCK_METHOD: &str = "Unlock";

/// Hands the password to the daemon.
///
/// `Ok(false)` is a real answer — that password does not open the database —
/// and only `Err` means nobody replied. The dialog tells those two apart
/// because they call for different things: retyping, or giving up.
#[tauri::command]
async fn unlock(password: String) -> Result<bool, String> {
    let password = Zeroizing::new(password);

    let connection = zbus::Connection::session()
        .await
        .map_err(|error| format!("{error}"))?;

    let reply = connection
        .call_method(
            Some(KEYRING_SERVICE),
            KEYRING_PATH,
            Some(KEYRING_INTERFACE),
            UNLOCK_METHOD,
            &(password.as_str(),),
        )
        .await
        .map_err(|error| match error {
            // What the daemon says is meant to be read: after three wrong
            // passwords it answers with how long the wait is, and putting
            // "the keyring did not answer" in front of that would be a lie.
            zbus::Error::MethodError(_, Some(message), _) => message,
            other => format!("{other}"),
        })?;

    reply.body().deserialize::<bool>().map_err(|error| format!("{error}"))
}

/// Ends the process with the answer in the exit code.
#[tauri::command]
fn finish(app: tauri::AppHandle, unlocked: bool) {
    app.exit(if unlocked { 0 } else { 1 });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_config_manager::init())
        .plugin(tauri_plugin_vicons::init())
        .invoke_handler(tauri::generate_handler![unlock, finish])
        .setup(|app| {
            let window = WebviewWindowBuilder::new(app, WINDOW_LABEL, WebviewUrl::default())
                .title("Desbloquear el llavero")
                .inner_size(DIALOG_WIDTH, DIALOG_HEIGHT)
                .resizable(false)
                .decorations(false)
                .transparent(true)
                .center()
                // It is asking about something happening right now, and it holds
                // whatever asked for a secret: it must not end up behind it.
                .always_on_top(true)
                .build()?;

            // Closing the window with no answer is a no, and the daemon has to
            // hear it rather than wait for a process that is already gone.
            let handle = app.handle().clone();
            window.on_window_event(move |event| {
                if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                    handle.exit(1);
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// ---------------------------------------------------------------------------
// La frase de una clave SSH
// ---------------------------------------------------------------------------

const SSH_WINDOW_LABEL: &str = "ssh-askpass";
const SSH_DIALOG_HEIGHT: f64 = 320.0;

/// Lo que la ventana necesita saber para preguntar.
#[derive(Clone, serde::Serialize)]
struct SshRequest {
    key_name: String,
    key_path: Option<String>,
    prompt: String,
}

/// Guarda la frase si se pidió recordarla, y se la entrega a ssh.
///
/// El proceso termina acá: la frase ya salió por el descriptor que ssh está
/// leyendo y no hay nada más que hacer con ella.
#[tauri::command]
async fn ssh_answer(
    state: tauri::State<'_, SshRequest>,
    passphrase: String,
    remember: bool,
) -> Result<(), String> {
    let passphrase = Zeroizing::new(passphrase);

    if remember {
        if let Some(path) = state.key_path.clone() {
            // Que no se pueda guardar no es motivo para no entregarla: la
            // conexión de ahora funciona igual y la próxima vez se vuelve a
            // preguntar, que es exactamente lo que pasaba antes de todo esto.
            match secret_service::Keyring::open().await {
                Ok(keyring) => {
                    let label = format!("Frase de la clave SSH {}", state.key_name);
                    if let Err(error) = keyring.remember(&path, passphrase.as_str(), &label).await {
                        eprintln!("[vasak-ssh-askpass] no se pudo guardar la frase: {error}");
                    }
                }
                Err(error) => {
                    eprintln!("[vasak-ssh-askpass] no se pudo abrir el llavero: {error}")
                }
            }
        }
    }

    ssh_askpass::answer(passphrase.as_str())
}

/// Nadie escribió nada.
#[tauri::command]
fn ssh_cancel() {
    ssh_askpass::give_up()
}

#[tauri::command]
fn ssh_request(state: tauri::State<'_, SshRequest>) -> SshRequest {
    state.inner().clone()
}

/// El diálogo que pide la frase de una clave SSH.
pub fn run_ssh_askpass() {
    let request = ssh_askpass::start();
    let state = SshRequest {
        key_name: request.key_name(),
        key_path: request.key_path.clone(),
        prompt: request.prompt.clone(),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_config_manager::init())
        .plugin(tauri_plugin_vicons::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![ssh_request, ssh_answer, ssh_cancel])
        .setup(|app| {
            let window = WebviewWindowBuilder::new(
                app,
                SSH_WINDOW_LABEL,
                WebviewUrl::App("index.html#/ssh".into()),
            )
            .title("Clave SSH")
            .inner_size(DIALOG_WIDTH, SSH_DIALOG_HEIGHT)
            .resizable(false)
            .decorations(false)
            .transparent(true)
            .center()
            // Del otro lado hay un ssh esperando: si la ventana queda detrás de
            // algo, la conexión se cuelga sin que se vea por qué.
            .always_on_top(true)
            .build()?;

            window.on_window_event(|event| {
                if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                    ssh_askpass::give_up();
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
