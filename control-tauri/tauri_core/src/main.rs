#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use fei_control_core::commands::AppState;

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            fei_control_core::commands::connect_to_gateway,
            fei_control_core::commands::list_agents,
            fei_control_core::commands::send_command,
            fei_control_core::commands::get_system_info,
            fei_control_core::commands::get_system_metrics,
            fei_control_core::commands::list_directory,
            fei_control_core::commands::upload_file,
            fei_control_core::commands::download_file,
            fei_control_core::commands::list_plugins,
            fei_control_core::commands::install_plugin,
            fei_control_core::commands::uninstall_plugin,
            fei_control_core::commands::generate_agent,
            fei_control_core::commands::get_task,
            fei_control_core::credential_store::save_credentials,
            fei_control_core::credential_store::load_credentials,
            fei_control_core::credential_store::delete_credentials,
            fei_control_core::credential_store::import_certs_from_files,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
