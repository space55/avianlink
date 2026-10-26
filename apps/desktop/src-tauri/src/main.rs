//! Desktop entry point. Keeps platform wiring in the library so the
//! Tauri mobile targets can reuse it unchanged.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    avianlink_desktop_lib::run();
}
