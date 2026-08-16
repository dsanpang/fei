use keyring::Entry;
use serde::{Deserialize, Serialize};

const SERVICE_NAME: &str = "fei.control.panel";
const KEY_PSK: &str = "chacha20_psk";
const KEY_CERT_CA: &str = "tls_ca_cert";
const KEY_CERT_CLIENT: &str = "tls_client_cert";
const KEY_CLIENT_PRIVATE: &str = "tls_client_key";
const KEY_NATS_URL: &str = "nats_url";
const KEY_GRPC_ADDR: &str = "grpc_addr";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSet {
    pub psk: Option<String>,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub nats_url: Option<String>,
    pub grpc_addr: Option<String>,
}

impl Default for CredentialSet {
    fn default() -> Self {
        Self {
            psk: None,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            nats_url: Some("nats://127.0.0.1:4222".to_string()),
            grpc_addr: Some("http://127.0.0.1:50051".to_string()),
        }
    }
}

pub struct CredentialStore {
    psk_entry: Entry,
    ca_cert_entry: Entry,
    client_cert_entry: Entry,
    client_key_entry: Entry,
    nats_url_entry: Entry,
    grpc_addr_entry: Entry,
}

impl CredentialStore {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            psk_entry: Entry::new(SERVICE_NAME, KEY_PSK)
                .map_err(|e| format!("Failed to create PSK entry: {}", e))?,
            ca_cert_entry: Entry::new(SERVICE_NAME, KEY_CERT_CA)
                .map_err(|e| format!("Failed to create CA cert entry: {}", e))?,
            client_cert_entry: Entry::new(SERVICE_NAME, KEY_CERT_CLIENT)
                .map_err(|e| format!("Failed to create client cert entry: {}", e))?,
            client_key_entry: Entry::new(SERVICE_NAME, KEY_CLIENT_PRIVATE)
                .map_err(|e| format!("Failed to create client key entry: {}", e))?,
            nats_url_entry: Entry::new(SERVICE_NAME, KEY_NATS_URL)
                .map_err(|e| format!("Failed to create NATS URL entry: {}", e))?,
            grpc_addr_entry: Entry::new(SERVICE_NAME, KEY_GRPC_ADDR)
                .map_err(|e| format!("Failed to create gRPC addr entry: {}", e))?,
        })
    }

    pub fn save_psk(&self, psk_hex: &str) -> Result<(), String> {
        self.psk_entry
            .set_password(psk_hex)
            .map_err(|e| format!("Failed to save PSK: {}", e))
    }

    pub fn load_psk(&self) -> Option<String> {
        self.psk_entry.get_password().ok()
    }

    pub fn save_ca_cert(&self, cert_pem: &str) -> Result<(), String> {
        self.ca_cert_entry
            .set_password(cert_pem)
            .map_err(|e| format!("Failed to save CA cert: {}", e))
    }

    pub fn load_ca_cert(&self) -> Option<String> {
        self.ca_cert_entry.get_password().ok()
    }

    pub fn save_client_cert(&self, cert_pem: &str) -> Result<(), String> {
        self.client_cert_entry
            .set_password(cert_pem)
            .map_err(|e| format!("Failed to save client cert: {}", e))
    }

    pub fn load_client_cert(&self) -> Option<String> {
        self.client_cert_entry.get_password().ok()
    }

    pub fn save_client_key(&self, key_pem: &str) -> Result<(), String> {
        self.client_key_entry
            .set_password(key_pem)
            .map_err(|e| format!("Failed to save client key: {}", e))
    }

    pub fn load_client_key(&self) -> Option<String> {
        self.client_key_entry.get_password().ok()
    }

    pub fn save_nats_url(&self, url: &str) -> Result<(), String> {
        self.nats_url_entry
            .set_password(url)
            .map_err(|e| format!("Failed to save NATS URL: {}", e))
    }

    pub fn load_nats_url(&self) -> Option<String> {
        self.nats_url_entry
            .get_password()
            .ok()
            .or_else(|| Some("nats://127.0.0.1:4222".to_string()))
    }

    pub fn save_grpc_addr(&self, addr: &str) -> Result<(), String> {
        self.grpc_addr_entry
            .set_password(addr)
            .map_err(|e| format!("Failed to save gRPC addr: {}", e))
    }

    pub fn load_grpc_addr(&self) -> Option<String> {
        self.grpc_addr_entry
            .get_password()
            .ok()
            .or_else(|| Some("http://127.0.0.1:50051".to_string()))
    }

    pub fn load_all(&self) -> CredentialSet {
        CredentialSet {
            psk: self.load_psk(),
            ca_cert: self.load_ca_cert(),
            client_cert: self.load_client_cert(),
            client_key: self.load_client_key(),
            nats_url: self.load_nats_url(),
            grpc_addr: self.load_grpc_addr(),
        }
    }

    pub fn save_all(&self, creds: &CredentialSet) -> Result<(), String> {
        if let Some(ref psk) = creds.psk {
            self.save_psk(psk)?;
        }
        if let Some(ref cert) = creds.ca_cert {
            self.save_ca_cert(cert)?;
        }
        if let Some(ref cert) = creds.client_cert {
            self.save_client_cert(cert)?;
        }
        if let Some(ref key) = creds.client_key {
            self.save_client_key(key)?;
        }
        if let Some(ref url) = creds.nats_url {
            self.save_nats_url(url)?;
        }
        if let Some(ref addr) = creds.grpc_addr {
            self.save_grpc_addr(addr)?;
        }
        Ok(())
    }

    pub fn delete_all(&self) -> Result<(), String> {
        let _ = self.psk_entry.delete_password();
        let _ = self.ca_cert_entry.delete_password();
        let _ = self.client_cert_entry.delete_password();
        let _ = self.client_key_entry.delete_password();
        let _ = self.nats_url_entry.delete_password();
        let _ = self.grpc_addr_entry.delete_password();
        Ok(())
    }
}

#[tauri::command]
pub fn save_credentials(creds: CredentialSet) -> Result<(), String> {
    let store = CredentialStore::new()?;
    store.save_all(&creds)
}

#[tauri::command]
pub fn load_credentials() -> Result<CredentialSet, String> {
    let store = CredentialStore::new()?;
    Ok(store.load_all())
}

#[tauri::command]
pub fn delete_credentials() -> Result<(), String> {
    let store = CredentialStore::new()?;
    store.delete_all()
}

#[tauri::command]
pub fn import_certs_from_files(
    cert_dir: String,
) -> Result<CredentialSet, String> {
    use std::fs;
    use std::path::Path;

    let cert_path = Path::new(&cert_dir);

    let psk_path = cert_path.join("psk.bin");
    let psk_hex = if psk_path.exists() {
        let psk_bytes = fs::read(&psk_path)
            .map_err(|e| format!("Failed to read PSK file: {}", e))?;
        Some(psk_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
    } else {
        None
    };

    let ca_cert = {
        let path = cert_path.join("ca-cert.pem");
        if path.exists() {
            Some(fs::read_to_string(&path).map_err(|e| format!("Failed to read CA cert: {}", e))?)
        } else {
            None
        }
    };

    let client_cert = {
        let path = cert_path.join("client-cert.pem");
        if path.exists() {
            Some(fs::read_to_string(&path).map_err(|e| format!("Failed to read client cert: {}", e))?)
        } else {
            None
        }
    };

    let client_key = {
        let path = cert_path.join("client-key.pem");
        if path.exists() {
            Some(fs::read_to_string(&path).map_err(|e| format!("Failed to read client key: {}", e))?)
        } else {
            None
        }
    };

    let creds = CredentialSet {
        psk: psk_hex,
        ca_cert,
        client_cert,
        client_key,
        nats_url: Some("nats://127.0.0.1:4222".to_string()),
        grpc_addr: Some("http://127.0.0.1:50051".to_string()),
    };

    let store = CredentialStore::new()?;
    store.save_all(&creds)?;

    Ok(creds)
}
