use crate::config::Config;
use anyhow::{Context, Result, bail};
use axum_server::tls_rustls::RustlsConfig;
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use std::io::Cursor;
use std::sync::Arc;

pub fn server_config(config: &Config) -> Result<RustlsConfig> {
    let identity = config
        .internal_mtls_identity_pem
        .as_deref()
        .context("internal mTLS identity is unavailable")?;
    let ca = config
        .internal_mtls_ca_pem
        .as_deref()
        .context("internal mTLS CA is unavailable")?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(identity))
        .collect::<Result<Vec<_>, _>>()
        .context("parse internal mTLS certificate chain")?;
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(identity))
        .context("parse internal mTLS private key")?
        .context("internal mTLS identity has no private key")?;
    let ca_certificates = rustls_pemfile::certs(&mut Cursor::new(ca))
        .collect::<Result<Vec<_>, _>>()
        .context("parse internal mTLS CA certificates")?;
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(ca_certificates);
    if added == 0 || ignored != 0 {
        bail!("internal mTLS CA contains no usable certificate or invalid certificates");
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build internal mTLS client verifier")?;
    let mut server = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)
        .context("build internal mTLS server identity")?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server)))
}
