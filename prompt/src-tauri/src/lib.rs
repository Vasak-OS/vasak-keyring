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
