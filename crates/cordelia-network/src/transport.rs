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
    self_signed_cert_naming(identity, &identity.public_key())
}

/// A certificate signed with `identity`'s key whose Subject CN names
/// `named`. A node always names its own key; the tests name another, to
/// check that such a certificate is refused.
fn self_signed_cert_naming(
    identity: &NodeIdentity,
    named: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    let bech32_pk = encode_public_key(named).map_err(|e| TransportError::CertGen(e.to_string()))?;

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

/// The transport settings of every connection, in either direction:
/// keep-alive and idle timeout, and what a peer may make this node hold.
///
/// - A peer may have QUIC_MAX_BIDI_STREAMS streams open at once, and no
///   unidirectional ones.
/// - It may send one message's worth on a stream, and two on the whole
///   connection, before this node has read it. So one connection can make
///   a node buffer two megabytes, whatever the peer does.
fn transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(
        protocol::QUIC_KEEPALIVE_INTERVAL_SECS,
    )));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(protocol::QUIC_MAX_IDLE_TIMEOUT_SECS))
            .unwrap(),
    ));
    transport.max_concurrent_bidi_streams(protocol::QUIC_MAX_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams(protocol::QUIC_MAX_UNI_STREAMS.into());
    transport.stream_receive_window(protocol::QUIC_STREAM_RECEIVE_WINDOW.into());
    transport.receive_window(protocol::QUIC_RECEIVE_WINDOW.into());
    transport
}

/// Build a quinn ServerConfig that accepts self-signed Ed25519 certificates.
pub fn server_config(identity: &NodeIdentity) -> Result<ServerConfig, TransportError> {
    let (cert_der, key_der) = generate_self_signed_cert(identity)?;
    server_config_with_cert(cert_der, key_der)
}

fn server_config_with_cert(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<ServerConfig, TransportError> {
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

    let transport = transport_config();

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
    client_config_with_cert(cert_der, key_der)
}

fn client_config_with_cert(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<ClientConfig, TransportError> {
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

    let transport = transport_config();

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

/// Create a QUIC endpoint that only dials out. It has no server
/// configuration, so it accepts no connection, and it binds whichever port
/// the system gives it on `bind_ip`.
pub fn create_client_endpoint(
    identity: &NodeIdentity,
    bind_ip: std::net::IpAddr,
) -> Result<Endpoint, TransportError> {
    let mut endpoint = Endpoint::client(SocketAddr::new(bind_ip, 0))
        .map_err(|e| TransportError::Quic(e.to_string()))?;
    endpoint.set_default_client_config(client_config(identity)?);
    Ok(endpoint)
}

/// Object identifier of Ed25519 keys (RFC 8410).
const OID_ED25519: &str = "1.3.101.112";

/// The node ID a peer's TLS certificate proves: the Ed25519 key the
/// certificate carries.
///
/// TLS checks that the peer holds the certificate's own key (its
/// `CertificateVerify` signature is verified against it), so that key is the
/// only identity a connection proves. The Subject CN repeats the key as a
/// Bech32 `cordelia_pk1...` string. A peer writes its own CN, so the CN is
/// never the source of the ID, and a certificate whose CN names a different
/// key is refused.
pub fn extract_peer_node_id(cert_chain: &[CertificateDer<'_>]) -> Result<[u8; 32], TransportError> {
    let cert = cert_chain
        .first()
        .ok_or_else(|| TransportError::IdentityBinding("no certificate in chain".into()))?;

    let (_, parsed) = x509_parser::parse_x509_certificate(cert)
        .map_err(|e| TransportError::IdentityBinding(format!("X.509 parse failed: {e}")))?;

    let spki = parsed.public_key();
    if spki.algorithm.algorithm.to_id_string() != OID_ED25519 {
        return Err(TransportError::IdentityBinding(
            "certificate key is not Ed25519".into(),
        ));
    }
    let key: [u8; 32] = spki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| TransportError::IdentityBinding("certificate key is not 32 bytes".into()))?;

    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .ok_or_else(|| TransportError::IdentityBinding("no CN in certificate subject".into()))?
        .as_str()
        .map_err(|e| TransportError::IdentityBinding(format!("CN is not UTF-8: {e}")))?;
    let named = cordelia_crypto::bech32::decode_public_key(cn)
        .map_err(|e| TransportError::IdentityBinding(format!("invalid Bech32 CN: {e}")))?;
    if named != key {
        return Err(TransportError::IdentityBinding(
            "certificate names a key other than its own".into(),
        ));
    }

    Ok(key)
}

/// The node key of the peer at the other end of `conn`: the key of the
/// certificate that the peer presented in this connection's TLS handshake
/// ([`extract_peer_node_id`]), which TLS proved the peer holds.
///
/// Whoever checks what a peer signs for this connection takes the peer's
/// key from here, and from nothing that the peer says in a message.
pub fn peer_key(conn: &quinn::Connection) -> Result<[u8; 32], TransportError> {
    let certs = conn
        .peer_identity()
        .ok_or_else(|| TransportError::IdentityBinding("the peer presented no identity".into()))?
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| {
            TransportError::IdentityBinding("the peer's identity is not a certificate".into())
        })?;
    extract_peer_node_id(&certs)
}

/// The value that both ends of `conn` export from its one TLS session
/// (decision 2026-10-04 §2.4 item 3, §16): SESSION_VALUE_BYTES of keying
/// material, exported under LABEL_SESSION_VALUE with no context (RFC 8446
/// §7.5, RFC 5705).
///
/// The two ends of one connection get the same bytes, and no other
/// connection gets them: not one between the same two nodes, and not one
/// that either of them has with a third. So what is signed over the value
/// was signed for this connection. Both ends get the same bytes, so what
/// is signed over it must also say which end signed.
pub fn session_value(
    conn: &quinn::Connection,
) -> Result<[u8; protocol::SESSION_VALUE_BYTES], TransportError> {
    let mut value = [0u8; protocol::SESSION_VALUE_BYTES];
    conn.export_keying_material(&mut value, protocol::LABEL_SESSION_VALUE, &[])
        .map_err(|_| TransportError::Tls("the session's value could not be exported".into()))?;
    Ok(value)
}

// ── Custom TLS verifiers ───────────────────────────────────────────

/// Cached signature verification algorithms from the ring provider.
/// Avoids repeated provider instantiation in verifier callbacks.
fn sig_verify_algos() -> &'static rustls::crypto::WebPkiSupportedAlgorithms {
    use std::sync::OnceLock;
    static ALGOS: OnceLock<rustls::crypto::WebPkiSupportedAlgorithms> = OnceLock::new();
    ALGOS.get_or_init(|| rustls::crypto::ring::default_provider().signature_verification_algorithms)
}

/// Server certificate verifier: accepts any self-signed Ed25519
/// certificate that names its own key ([`extract_peer_node_id`]). TLS then
/// proves the peer holds that key. Whether that key is the node the caller
/// meant to reach is the caller's question.
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

/// Client certificate verifier: accepts any self-signed Ed25519
/// certificate that names its own key ([`extract_peer_node_id`]).
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

    /// T19. A certificate signed with one key that names another is
    /// refused: the name is the peer's own claim, and only the key is proved.
    #[test]
    fn a_certificate_that_names_another_key_is_refused() {
        let own = NodeIdentity::generate().unwrap();
        let victim = NodeIdentity::generate().unwrap();
        let (cert_der, _) = self_signed_cert_naming(&own, &victim.public_key()).unwrap();
        let err = extract_peer_node_id(&[CertificateDer::from(cert_der)]).unwrap_err();
        assert!(
            err.to_string().contains("names a key other than its own"),
            "{err}"
        );
    }

    /// Two nodes, connected: the client's end and the server's.
    async fn connected() -> (quinn::Connection, quinn::Connection, Endpoint, Endpoint) {
        let server_id = NodeIdentity::generate().unwrap();
        let client_id = NodeIdentity::generate().unwrap();
        let server = create_endpoint(&server_id, "127.0.0.1:0".parse().unwrap()).unwrap();
        let client = create_endpoint(&client_id, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let accepting = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
        };
        let client_end = client
            .connect(server_addr, "cordelia")
            .unwrap()
            .await
            .unwrap();
        let server_end = accepting.await.unwrap();
        (client_end, server_end, client, server)
    }

    /// Both ends of one connection export the same value from its TLS
    /// session, and no other connection exports it: not another between
    /// the same two nodes, and not one with a third. The value is what the
    /// session gives under the label for it, with no context, and under
    /// no other label.
    #[tokio::test]
    async fn both_ends_export_one_value_from_a_session_and_no_other_session_gives_it() {
        let server_id = NodeIdentity::generate().unwrap();
        let client_id = NodeIdentity::generate().unwrap();
        let other_id = NodeIdentity::generate().unwrap();
        let server = create_endpoint(&server_id, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        // The client's end and the server's, of a connection from the
        // node with `identity`.
        let connect = |identity: &NodeIdentity| {
            let client = create_client_endpoint(identity, "127.0.0.1".parse().unwrap()).unwrap();
            let server = server.clone();
            async move {
                let accepting =
                    tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() });
                let client_end = client
                    .connect(server_addr, "cordelia")
                    .unwrap()
                    .await
                    .unwrap();
                (client_end, accepting.await.unwrap(), client)
            }
        };
        let (client_end, server_end, _c1) = connect(&client_id).await;
        let (again_client, again_server, _c2) = connect(&client_id).await;
        let (other_client, other_server, _c3) = connect(&other_id).await;

        // Both ends of one connection: the same 32 bytes, each time asked.
        let value = session_value(&client_end).unwrap();
        assert_eq!(value.len(), protocol::SESSION_VALUE_BYTES);
        assert_eq!(session_value(&server_end).unwrap(), value);
        assert_eq!(session_value(&client_end).unwrap(), value);
        assert_ne!(value, [0u8; 32]);

        // A second connection between the same two nodes, and one from
        // another node: each has a value of its own, at both its ends.
        let again = session_value(&again_client).unwrap();
        assert_eq!(session_value(&again_server).unwrap(), again);
        let other = session_value(&other_client).unwrap();
        assert_eq!(session_value(&other_server).unwrap(), other);
        assert!(value != again && value != other && again != other);

        // It is what the session exports under the label for it, with no
        // context, and under no other label or context.
        let exported = |conn: &quinn::Connection, label: &[u8], context: &[u8]| {
            let mut out = [0u8; 32];
            conn.export_keying_material(&mut out, label, context)
                .unwrap();
            out
        };
        assert_eq!(
            protocol::LABEL_SESSION_VALUE,
            b"EXPORTER-cordelia v2 session"
        );
        assert_eq!(
            exported(&server_end, b"EXPORTER-cordelia v2 session", &[]),
            value
        );
        assert_ne!(
            exported(&server_end, b"EXPORTER-cordelia v2 other", &[]),
            value
        );
        assert_ne!(
            exported(&server_end, protocol::LABEL_CHANNEL_PROOF, &[]),
            value
        );
        assert_ne!(
            exported(&server_end, protocol::LABEL_SESSION_VALUE, b"context"),
            value
        );
    }

    /// The key of the peer at the other end is the key of the certificate
    /// it presented, at both ends of a connection.
    #[tokio::test]
    async fn the_peers_key_is_the_key_of_its_certificate() {
        let server_id = NodeIdentity::generate().unwrap();
        let client_id = NodeIdentity::generate().unwrap();
        let server = create_endpoint(&server_id, "127.0.0.1:0".parse().unwrap()).unwrap();
        let client = create_client_endpoint(&client_id, "127.0.0.1".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let accepting = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
        };
        let client_end = client
            .connect(server_addr, "cordelia")
            .unwrap()
            .await
            .unwrap();
        let server_end = accepting.await.unwrap();
        assert_eq!(peer_key(&server_end).unwrap(), client_id.public_key());
        assert_eq!(peer_key(&client_end).unwrap(), server_id.public_key());
    }

    /// T3. A peer can have 64 streams open on one connection at once. The
    /// next one waits.
    #[tokio::test]
    async fn a_connection_holds_at_most_64_streams_open() {
        let (client, server, _c, _s) = connected().await;
        // The other end takes each stream and keeps it open.
        let holding = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok(stream) = server.accept_bi().await {
                held.push(stream);
            }
        });

        let brief = Duration::from_millis(500);
        let mut open = Vec::new();
        for n in 0..protocol::QUIC_MAX_BIDI_STREAMS {
            let (mut send, recv) = tokio::time::timeout(brief, client.open_bi())
                .await
                .unwrap_or_else(|_| panic!("stream {n} did not open"))
                .unwrap();
            send.write_all(b"x").await.unwrap();
            open.push((send, recv));
        }
        assert!(
            tokio::time::timeout(brief, client.open_bi()).await.is_err(),
            "one more stream than the limit opened"
        );
        // Nor a unidirectional one: the protocol has none.
        assert!(
            tokio::time::timeout(brief, client.open_uni())
                .await
                .is_err(),
            "a unidirectional stream opened"
        );
        holding.abort();
    }

    /// T3. One connection cannot make a node hold more than two messages'
    /// worth that it has not read, however many streams the peer uses.
    #[tokio::test]
    async fn a_connection_buffers_at_most_two_unread_messages() {
        let (client, _server_reads_nothing, _c, _s) = connected().await;
        let message = vec![0u8; protocol::MAX_MESSAGE_BYTES as usize];

        // Four streams, a message's worth on each: four megabytes offered.
        let mut streams = Vec::new();
        let mut taken = 0;
        for _ in 0..4 {
            let (mut send, recv) = client.open_bi().await.unwrap();
            let sent =
                tokio::time::timeout(Duration::from_millis(1500), send.write_all(&message)).await;
            taken += usize::from(matches!(sent, Ok(Ok(()))));
            streams.push((send, recv));
        }
        assert_eq!(taken, 2, "the connection took {taken} megabytes unread");
    }

    /// T19. A node cannot connect under a key it does not hold: a listening
    /// node refuses a client whose certificate names someone else's key.
    #[tokio::test]
    async fn a_client_that_names_another_key_cannot_connect() {
        let server_id = NodeIdentity::generate().unwrap();
        let attacker = NodeIdentity::generate().unwrap();
        let victim = NodeIdentity::generate().unwrap();

        let server = create_endpoint(&server_id, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let result = incoming.await;
            server.close(0u32.into(), b"done");
            result.is_ok()
        });

        let (cert, key) = self_signed_cert_naming(&attacker, &victim.public_key()).unwrap();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_config_with_cert(cert, key).unwrap());
        // In TLS 1.3 the client finishes first, so its side may briefly look
        // connected; what matters is that the server never accepts it.
        if let Ok(conn) = client.connect(server_addr, "cordelia").unwrap().await {
            conn.closed().await;
        }
        assert!(
            !accepted.await.unwrap(),
            "the server accepted a client that named a key it does not hold"
        );
        client.close(0u32.into(), b"done");
    }

    /// T19. Nor can a node answer under a key it does not hold: a client
    /// refuses a server whose certificate names someone else's key.
    #[tokio::test]
    async fn a_server_that_names_another_key_is_refused() {
        let attacker = NodeIdentity::generate().unwrap();
        let victim = NodeIdentity::generate().unwrap();
        let client_id = NodeIdentity::generate().unwrap();

        let (cert, key) = self_signed_cert_naming(&attacker, &victim.public_key()).unwrap();
        let server = Endpoint::server(
            server_config_with_cert(cert, key).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let serving = tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let _ = incoming.await;
            }
        });

        let client = create_client_endpoint(&client_id, "127.0.0.1".parse().unwrap()).unwrap();
        let result = client.connect(server_addr, "cordelia").unwrap().await;
        assert!(
            result.is_err(),
            "the client connected to a server that named a key it does not hold"
        );
        client.close(0u32.into(), b"done");
        serving.abort();
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

    /// An endpoint that only dials out reaches a listening one, which sees
    /// its identity, and cannot itself be connected to.
    #[tokio::test]
    async fn test_client_endpoint_dials_out_and_accepts_nothing() {
        let id_client = NodeIdentity::generate().unwrap();
        let id_server = NodeIdentity::generate().unwrap();
        let localhost: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        let client = create_client_endpoint(&id_client, localhost).unwrap();
        let server = create_endpoint(&id_server, "127.0.0.1:0".parse().unwrap()).unwrap();
        let client_addr = client.local_addr().unwrap();
        let server_addr = server.local_addr().unwrap();
        assert_ne!(client_addr.port(), 0, "the system picked a port");

        // Out: the connection works, and the server learns who dialled.
        let accepting = server.clone();
        let seen = tokio::spawn(async move {
            let conn = accepting.accept().await.unwrap().await.unwrap();
            let certs = conn
                .peer_identity()
                .unwrap()
                .downcast::<Vec<CertificateDer<'static>>>()
                .unwrap();
            let id = extract_peer_node_id(&certs).unwrap();
            // Keep the connection until the client has checked its side.
            conn.closed().await;
            id
        });
        let conn = client
            .connect(server_addr, "cordelia")
            .unwrap()
            .await
            .unwrap();
        conn.close(0u32.into(), b"done");
        assert_eq!(seen.await.unwrap(), id_client.public_key());

        // In: nothing answers. The dialler gets no connection, and the
        // client endpoint is never handed one.
        let dial = server.connect(client_addr, "cordelia").unwrap();
        let attempt = tokio::time::timeout(Duration::from_secs(2), dial).await;
        assert!(
            !matches!(attempt, Ok(Ok(_))),
            "a client-only endpoint accepted a connection"
        );
        let handed = tokio::time::timeout(Duration::from_millis(200), client.accept()).await;
        assert!(
            handed.is_err(),
            "accept() yielded on a client-only endpoint"
        );

        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
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
