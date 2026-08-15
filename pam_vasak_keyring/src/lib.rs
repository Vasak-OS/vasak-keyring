// PAM module for vasak-keyring
// Captures the login password and sends it to the daemon via D-Bus.

#![allow(non_camel_case_types, non_snake_case)]

use libc::c_int;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
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
    let cmsg = CString::new(msg).unwrap_or(CString::new("log error").unwrap());
    unsafe { pam_syslog(pamh, LOG_AUTH, cmsg.as_ptr()); }
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

// ── D-Bus: send password to the daemon ─────────────────────

/// The daemon's well-known name, lowercase as the freedesktop spec defines it.
/// This used to ask for `org.freedesktop.Secrets`, which nothing owns — D-Bus
/// names are case-sensitive, so every unlock failed and the keyring stayed
/// locked for the whole session with no error the user could see.
const KEYRING_SERVICE: &str = "org.freedesktop.secrets";
const KEYRING_PATH: &str = "/org/vasak/keyring";
const KEYRING_INTERFACE: &str = "org.vasak.Keyring";
/// zbus exports methods in CamelCase; the lowercase `unlock` did not exist.
const UNLOCK_METHOD: &str = "Unlock";

/// How long to keep trying while the daemon starts.
///
/// PAM opens the session before the user's systemd units are up, so the very
/// first attempt at login usually finds no daemon. This only costs time when
/// the daemon really is absent; the normal case answers on the first attempt.
const UNLOCK_ATTEMPTS: u32 = 10;
const UNLOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(150);

/// The uid the login is for, which is not the one this code runs as.
///
/// PAM modules run as root, in the login manager's process, before anything of
/// the user's session exists.
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

/// The bus the daemon is on: the user's, addressed explicitly.
///
/// `Connection::session()` reads the environment of the current process, and at
/// this point that process is the login manager running as root — with no
/// XDG_RUNTIME_DIR of the user in it, and often none at all. So it either found
/// root's bus or nothing, never the one the daemon is sitting on, and the unlock
/// could not have worked no matter how the PAM stack was configured.
fn session_bus(uid: u32) -> Result<zbus::blocking::Connection, zbus::Error> {
    zbus::blocking::connection::Builder::address(format!("unix:path=/run/user/{uid}/bus").as_str())?
        .build()
}

fn try_unlock(uid: u32, password: &str) -> Result<bool, zbus::Error> {
    let conn = session_bus(uid)?;
    let reply = conn.call_method(
        Some(KEYRING_SERVICE),
        KEYRING_PATH,
        Some(KEYRING_INTERFACE),
        UNLOCK_METHOD,
        &(password,),
    )?;

    Ok(reply.body().deserialize::<bool>().unwrap_or(false))
}

fn send_to_daemon(uid: u32, password: &str) -> bool {
    for attempt in 0..UNLOCK_ATTEMPTS {
        match try_unlock(uid, password) {
            // A `false` reply is a real answer — the password was wrong for the
            // existing database. Retrying cannot change that.
            Ok(unlocked) => return unlocked,
            Err(_) if attempt + 1 < UNLOCK_ATTEMPTS => std::thread::sleep(UNLOCK_RETRY),
            Err(_) => return false,
        }
    }
    false
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

    let key = CString::new("vasak_keyring_password").unwrap();
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
    let key = CString::new("vasak_keyring_password").unwrap();
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

    // Send to daemon
    if password.len() > 0 && send_to_daemon(uid, &password) {
        log(pamh, "pam_vasak_keyring: keyring unlocked successfully");
    } else {
        log(pamh, "pam_vasak_keyring: could not unlock keyring (daemon unavailable or wrong password)");
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
