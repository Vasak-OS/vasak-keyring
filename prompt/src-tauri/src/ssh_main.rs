// Prevents an additional console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    vasak_keyring_prompt_lib::run_ssh_askpass()
}
