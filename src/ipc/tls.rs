use anyhow::{Context, Result};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Load TLS configuration from certificate and private key files
pub fn load_server_config(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    let cert_file = File::open(cert_path)
        .with_context(|| format!("Failed to open certificate file: {}", cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain = certs(&mut cert_reader)
        .context("Failed to parse certificate chain")?
        .into_iter()
        .map(Certificate)
        .collect();

    let key_file = File::open(key_path)
        .with_context(|| format!("Failed to open private key file: {}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys = pkcs8_private_keys(&mut key_reader)
        .context("Failed to parse private key")?;
    
    if keys.is_empty() {
        return Err(anyhow::anyhow!("No PKCS8 private keys found in {}", key_path.display()));
    }
    
    // Use the first key found
    let key = PrivateKey(keys.remove(0));

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("Failed to create TLS server config")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
