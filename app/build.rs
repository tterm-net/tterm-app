fn main() {
    // The page may call these commands and no others; capabilities/main.json
    // grants them to the main window only.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&["api", "ws_open", "ws_send", "ws_recv", "ws_close", "open_external"]),
    ))
    .expect("the Tauri build step");
}
