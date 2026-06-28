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

fn send_to_daemon(password: &str) -> bool {
    use zbus::blocking::Connection;
    let conn = match Connection::session() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let reply = match conn.call_method(
        Some("org.freedesktop.Secrets"),
        "/org/vasak/keyring",
        Some("org.vasak.Keyring"),
        "unlock",
        &(password,),
    ) {
        Ok(r) => r,
        Err(_) => return false,
    };

    reply.body().deserialize::<bool>().unwrap_or(false)
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

    // Send to daemon
    if password.len() > 0 && send_to_daemon(&password) {
        log(pamh, "pam_vasak_keyring: keyring unlocked successfully");
    } else {
        log(pamh, "pam_vasak_keyring: could not unlock keyring (daemon unavailable or wrong password)");
    }

    // password zeroized automatically on drop (Zeroizing)

    PAM_SUCCESS
}
