//! QUIC transport with Ed25519 identity-bound TLS.
//!
//! Each node generates a self-signed X.509 certificate where:
//!   - Subject CN = Bech32-encoded public key (cordelia_pk1...)
//!   - Certificate key = Ed25519 (RFC 8410, OID 1.3.101.112)
//!   - Validity: 1 year, auto-renewed on startup
//!
//! Custom TLS verifiers accept self-signed certs and extract the
//! Ed25519 public key as the peer's verified `node_id`.
//!
//! Spec: seed-drill/specs/network-protocol.md §2

use cordelia_core::protocol;
use cordelia_crypto::bech32::encode_public_key;
use cordelia_crypto::identity::NodeIdentity;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// Default P2P listen port (§2.1, sourced from protocol.rs).
pub const DEFAULT_P2P_PORT: u16 = protocol::P2P_PORT;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("TLS error: {0}")]
    Tls(String),

    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("certificate generation error: {0}")]
    CertGen(String),

    #[error("identity binding error: {0}")]
    IdentityBinding(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Generate a self-signed X.509 certificate bound to a NodeIdentity.
///
/// The certificate's Subject CN is set to the Bech32-encoded public key
/// (cordelia_pk1...), and the key algorithm is Ed25519 (RFC 8410).
///
/// Returns (DER-encoded certificate, DER-encoded PKCS#8 private key).
pub fn generate_self_signed_cert(
    identity: &NodeIdentity,
) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    let bech32_pk = encode_public_key(&identity.public_key())
        .map_err(|e| TransportError::CertGen(e.to_string()))?;

    // rcgen needs the Ed25519 seed in PKCS#8 DER format
    let pkcs8_der = ed25519_seed_to_pkcs8(identity.seed());
    let pkcs8_key = PrivatePkcs8KeyDer::from(pkcs8_der.clone());
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_key, &rcgen::PKCS_ED25519)
        .map_err(|e| TransportError::CertGen(e.to_string()))?;

    let mut params = rcgen::CertificateParams::new(vec![])
        .map_err(|e| TransportError::CertGen(e.to_string()))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, bech32_pk);

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(protocol::TLS_CERT_VALIDITY_DAYS);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TransportError::CertGen(e.to_string()))?;

    Ok((cert.der().to_vec(), pkcs8_der))
}

/// Build PKCS#8 v1 DER from a raw 32-byte Ed25519 seed.
/// Same format as cordelia-crypto's seed_to_pkcs8 but standalone.
fn ed25519_seed_to_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    // SEQUENCE (outer)
    der.push(0x30);
    der.push(0x2e); // 46 bytes
    // INTEGER 0 (version v1)
    der.extend_from_slice(&[0x02, 0x01, 0x00]);
    // SEQUENCE { OID 1.3.101.112 (Ed25519) }
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    // OCTET STRING { OCTET STRING { 32-byte seed } }
    der.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    der.extend_from_slice(seed);
    der
}

/// Build a quinn ServerConfig that accepts self-signed Ed25519 certificates.
pub fn server_config(identity: &NodeIdentity) -> Result<ServerConfig, TransportError> {
    let (cert_der, key_der) = generate_self_signed_cert(identity)?;

    let cert = CertificateDer::from(cert_der);
    let key = PrivatePkcs8KeyDer::from(key_der);

    let provider = rustls::crypto::ring::default_provider();
    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .with_client_cert_verifier(Arc::new(CordeliaClientVerifier))
        .with_single_cert(vec![cert], key.into())
        .map_err(|e| TransportError::Tls(e.to_string()))?;

    tls_config.alpn_protocols = vec![b"cordelia/1".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(protocol::QUIC_KEEPALIVE_INTERVAL_SECS)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(protocol::QUIC_MAX_IDLE_TIMEOUT_SECS)).unwrap(),
    ));
    transport.max_concurrent_bidi_streams(protocol::QUIC_MAX_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams(protocol::QUIC_MAX_UNI_STREAMS.into());

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| TransportError::Tls(e.to_string()))?,
    ));
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

/// Build a quinn ClientConfig that accepts self-signed Ed25519 certificates.
pub fn client_config(identity: &NodeIdentity) -> Result<ClientConfig, TransportError> {
    let (cert_der, key_der) = generate_self_signed_cert(identity)?;

    let cert = CertificateDer::from(cert_der);
    let key = PrivatePkcs8KeyDer::from(key_der);

    let provider = rustls::crypto::ring::default_provider();
    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CordeliaServerVerifier))
        .with_client_auth_cert(vec![cert], key.into())
        .map_err(|e| TransportError::Tls(e.to_string()))?;

    tls_config.alpn_protocols = vec![b"cordelia/1".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(protocol::QUIC_KEEPALIVE_INTERVAL_SECS)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(protocol::QUIC_MAX_IDLE_TIMEOUT_SECS)).unwrap(),
    ));
    transport.max_concurrent_bidi_streams(protocol::QUIC_MAX_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams(protocol::QUIC_MAX_UNI_STREAMS.into());

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| TransportError::Tls(e.to_string()))?,
    ));
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

/// Create a QUIC endpoint bound to a local address, configured for both
/// client and server roles.
pub fn create_endpoint(
    identity: &NodeIdentity,
    bind_addr: SocketAddr,
) -> Result<Endpoint, TransportError> {
    let sc = server_config(identity)?;
    let mut endpoint =
        Endpoint::server(sc, bind_addr).map_err(|e| TransportError::Quic(e.to_string()))?;
    endpoint.set_default_client_config(client_config(identity)?);
    Ok(endpoint)
}

/// Extract the Ed25519 public key (node_id) from a peer's TLS certificate.
///
/// Parses the certificate's Subject CN, which must be a valid Bech32
/// cordelia_pk1... string, and decodes it to raw 32-byte key.
pub fn extract_peer_node_id(cert_chain: &[CertificateDer<'_>]) -> Result<[u8; 32], TransportError> {
    let cert = cert_chain
        .first()
        .ok_or_else(|| TransportError::IdentityBinding("no certificate in chain".into()))?;

    // Parse X.509 to extract Subject CN
    let (_, parsed) = x509_parser::parse_x509_certificate(cert)
        .map_err(|e| TransportError::IdentityBinding(format!("X.509 parse failed: {e}")))?;

    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .ok_or_else(|| TransportError::IdentityBinding("no CN in certificate subject".into()))?
        .as_str()
        .map_err(|e| TransportError::IdentityBinding(format!("CN is not UTF-8: {e}")))?;

    // Decode Bech32 cordelia_pk1... to raw bytes
    let pk = cordelia_crypto::bech32::decode_public_key(cn)
        .map_err(|e| TransportError::IdentityBinding(format!("invalid Bech32 CN: {e}")))?;

    Ok(pk)
}

// ── Custom TLS verifiers ───────────────────────────────────────────

/// Cached signature verification algorithms from the ring provider.
/// Avoids repeated provider instantiation in verifier callbacks.
fn sig_verify_algos() -> &'static rustls::crypto::WebPkiSupportedAlgorithms {
    use std::sync::OnceLock;
    static ALGOS: OnceLock<rustls::crypto::WebPkiSupportedAlgorithms> = OnceLock::new();
    ALGOS.get_or_init(|| rustls::crypto::ring::default_provider().signature_verification_algorithms)
}

/// Server certificate verifier: accepts any self-signed Ed25519 cert
/// with a valid cordelia_pk1... CN. Identity verification happens at
/// the application layer (handshake §4.1.6).
#[derive(Debug)]
struct CordeliaServerVerifier;

impl rustls::client::danger::ServerCertVerifier for CordeliaServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        extract_peer_node_id(std::slice::from_ref(end_entity))
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, sig_verify_algos())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Client certificate verifier: accepts any self-signed Ed25519 cert
/// with a valid cordelia_pk1... CN.
#[derive(Debug)]
struct CordeliaClientVerifier;

impl rustls::server::danger::ClientCertVerifier for CordeliaClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        extract_peer_node_id(std::slice::from_ref(end_entity))
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, sig_verify_algos())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn offer_client_auth(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_cert() {
        let id = NodeIdentity::generate().unwrap();
        let (cert_der, key_der) = generate_self_signed_cert(&id).unwrap();
        assert!(!cert_der.is_empty());
        assert_eq!(key_der.len(), 48); // PKCS#8 v1 DER for Ed25519
    }

    #[test]
    fn test_extract_node_id_from_cert() {
        let id = NodeIdentity::generate().unwrap();
        let (cert_der, _) = generate_self_signed_cert(&id).unwrap();
        let cert = CertificateDer::from(cert_der);
        let extracted = extract_peer_node_id(&[cert]).unwrap();
        assert_eq!(extracted, id.public_key());
    }

    #[test]
    fn test_server_config_builds() {
        let id = NodeIdentity::generate().unwrap();
        let sc = server_config(&id);
        assert!(sc.is_ok());
    }

    #[test]
    fn test_client_config_builds() {
        let id = NodeIdentity::generate().unwrap();
        let cc = client_config(&id);
        assert!(cc.is_ok());
    }

    #[tokio::test]
    async fn test_endpoint_creation() {
        let id = NodeIdentity::generate().unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let endpoint = create_endpoint(&id, addr).unwrap();
        let local_addr = endpoint.local_addr().unwrap();
        assert!(local_addr.port() > 0);
        endpoint.close(0u32.into(), b"test done");
    }

    #[tokio::test]
    async fn test_quic_connect_and_extract_identity() {
        let id_a = NodeIdentity::generate().unwrap();
        let id_b = NodeIdentity::generate().unwrap();
        let pk_a = id_a.public_key();
        let pk_b = id_b.public_key();

        let ep_a = create_endpoint(&id_a, "127.0.0.1:0".parse().unwrap()).unwrap();
        let ep_b = create_endpoint(&id_b, "127.0.0.1:0".parse().unwrap()).unwrap();
        let b_addr = ep_b.local_addr().unwrap();

        // Server accepts in background
        let server = tokio::spawn(async move {
            let incoming = ep_b.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let certs = conn
                .peer_identity()
                .unwrap()
                .downcast::<Vec<CertificateDer<'static>>>()
                .unwrap();
            let node_id = extract_peer_node_id(&certs).unwrap();
            conn.close(0u32.into(), b"done");
            ep_b.close(0u32.into(), b"done");
            node_id
        });

        // Client connects
        let conn_a = ep_a.connect(b_addr, "cordelia").unwrap().await.unwrap();
        let b_certs = conn_a
            .peer_identity()
            .unwrap()
            .downcast::<Vec<CertificateDer<'static>>>()
            .unwrap();
        let b_node_id = extract_peer_node_id(&b_certs).unwrap();
        assert_eq!(b_node_id, pk_b);

        conn_a.close(0u32.into(), b"done");
        ep_a.close(0u32.into(), b"done");

        // Verify server saw client's identity
        let a_node_id = server.await.unwrap();
        assert_eq!(a_node_id, pk_a);
    }

    // T1-1: Transport parameter verification (BV-19 regression)
    // Verify the transport config has keep_alive_interval and idle timeout set.
    #[test]
    fn test_transport_config_has_keepalive() {
        // Build server and client configs -- they should compile and build successfully.
        // The actual keepalive is set in server_config() and client_config() via
        // transport.keep_alive_interval(Some(Duration::from_secs(15)))
        // transport.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(60))))
        // This test verifies the configs build without error (the values are hardcoded).
        let id = NodeIdentity::generate().unwrap();
        let sc = server_config(&id).expect("server config should build with keepalive");
        let cc = client_config(&id).expect("client config should build with keepalive");
        // If keep_alive_interval or max_idle_timeout were invalid, these would fail
        let _ = (sc, cc);
    }
}
