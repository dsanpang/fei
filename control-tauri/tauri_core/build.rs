fn main() -> Result<(), Box<dyn std::error::Error>> {
    tauri_build::build();
    
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &["../../proto/fei_control.proto"],
            &["../../proto"],
        )?;
    
    Ok(())
}
