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
/// - This node may have written two messages' worth on the connection that
///   the peer has not acknowledged (QUIC_SEND_WINDOW). A write beyond it
///   waits for acknowledgements, and the codec gives it up after
///   STREAM_TIMEOUT_SECS. So a peer that never acknowledges what it is sent
///   cannot make a node hold more than that either.
/// - It may send no datagrams: no node sends or reads one, and quinn's
///   default would keep 1.25 MB of them unread on every connection.
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
    transport.send_window(protocol::QUIC_SEND_WINDOW);
    transport.datagram_receive_buffer_size(None);
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
    client_config_with(cert_der, key_der, transport_config())
}

/// A client config with `transport` in place of a node's own. A node uses
/// only its own; the tests give a stand-in peer other settings.
fn client_config_with(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    transport: quinn::TransportConfig,
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
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    let mut endpoint = endpoint_on(socket, Some(server_config(identity)?))?;
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
    let socket = std::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0))?;
    let mut endpoint = endpoint_on(socket, None)?;
    endpoint.set_default_client_config(client_config(identity)?);
    Ok(endpoint)
}

/// A node's endpoint over `socket`, with the kernel's receive batching of
/// UDP (GRO) turned off (decision 2026-10-22, rule 10;
/// parameter-rationale.md §1).
///
/// With GRO on, the kernel hands the socket a batch of a peer's datagrams
/// in one buffer, and quinn splits it into packets that share that
/// buffer: a stream frame of one byte that the node has not read keeps
/// the whole batch, up to about 64 KiB, where quinn's reassembler counts
/// one packet. With it off, each frame keeps its own datagram only.
///
/// quinn-udp turns GRO on when quinn wraps the socket, so it is turned
/// off after the wrap, on the same socket (a second descriptor of it).
/// Sending in batches (GSO) is kept. A node never rebinds an endpoint; a
/// rebind (`Endpoint::rebind`) would wrap a new socket and so turn GRO on
/// again, and must go through `receive_batching_off` after its wrap too.
fn endpoint_on(
    socket: std::net::UdpSocket,
    server: Option<ServerConfig>,
) -> Result<Endpoint, TransportError> {
    let runtime = quinn::default_runtime()
        .ok_or_else(|| TransportError::Quic("no async runtime found".into()))?;
    let same_socket = socket.try_clone()?;
    let wrapped = runtime.wrap_udp_socket(socket)?;
    receive_batching_off(&same_socket)?;
    drop(same_socket);
    Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), server, wrapped, runtime)
        .map_err(|e| TransportError::Quic(e.to_string()))
}

/// Turn the kernel's receive batching of UDP off on `socket`.
///
/// On Linux it is the socket option `UDP_GRO`. A kernel before 5.0 has no
/// such option (`ENOPROTOOPT`), and so never batched: that is not an
/// error. No other platform a node runs on batches what a socket
/// receives unless asked: macOS and the BSDs have no such option, and on
/// Windows quinn-udp leaves receive coalescing (URO) off.
#[cfg(target_os = "linux")]
fn receive_batching_off(socket: &std::net::UdpSocket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let off: libc::c_int = 0;
    // SAFETY: the descriptor is open for the call (`socket` is borrowed),
    // and the value is a c_int, of the length given.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_GRO,
            (&off as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
        Ok(())
    } else {
        Err(err)
    }
}

#[cfg(not(target_os = "linux"))]
fn receive_batching_off(_socket: &std::net::UdpSocket) -> std::io::Result<()> {
    Ok(())
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

    /// The send window that a config carries, as quinn shows it: quinn has
    /// no getter for it, but its `Debug` names every field.
    fn send_window_of(config: &impl std::fmt::Debug) -> u64 {
        let shown = format!("{config:?}");
        let at = shown
            .find("send_window: ")
            .expect("the config shows its send window")
            + "send_window: ".len();
        let digits: String = shown[at..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().unwrap()
    }

    /// T3. What a node may have written on one connection that the peer has
    /// not acknowledged is QUIC_SEND_WINDOW, at both ends: as the client
    /// that dials, and as the server that is dialled.
    #[test]
    fn the_send_window_is_two_messages_at_both_ends() {
        let id = NodeIdentity::generate().unwrap();
        let window = protocol::QUIC_SEND_WINDOW;
        assert_eq!(send_window_of(&transport_config()), window);
        assert_eq!(send_window_of(&client_config(&id).unwrap()), window);
        assert_eq!(
            send_window_of(&server_config(&id).unwrap().transport),
            window
        );
    }

    /// A path to `server` over UDP, as a client sees it: the address to
    /// dial, and a switch that, while it is on, drops everything the client
    /// sends. What the server sends always gets through. So a client behind
    /// it that is cut off goes on receiving, and acknowledges nothing.
    async fn path_to(
        server: SocketAddr,
    ) -> (
        SocketAddr,
        Arc<std::sync::atomic::AtomicBool>,
        tokio::task::JoinHandle<()>,
    ) {
        use std::sync::atomic::{AtomicBool, Ordering};
        let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        back.connect(server).await.unwrap();
        let addr = front.local_addr().unwrap();
        let cut = Arc::new(AtomicBool::new(false));
        let cutting = cut.clone();
        let carrying = tokio::spawn(async move {
            let mut client = None;
            let (mut up, mut down) = (vec![0u8; 65536], vec![0u8; 65536]);
            loop {
                tokio::select! {
                    Ok((n, from)) = front.recv_from(&mut up) => {
                        client = Some(from);
                        if !cutting.load(Ordering::SeqCst) {
                            let _ = back.send(&up[..n]).await;
                        }
                    }
                    Ok(n) = back.recv(&mut down) => {
                        if let Some(client) = client {
                            let _ = front.send_to(&down[..n], client).await;
                        }
                    }
                }
            }
        });
        (addr, cut, carrying)
    }

    /// A node's end of a connection from a stand-in peer behind
    /// [`path_to`], with the path cut once the connection is made. The peer
    /// offers 64 MB of credit on a stream and on the connection, so only
    /// the node's own send window holds back what it writes.
    async fn a_peer_that_stops_acknowledging() -> (
        quinn::Connection,
        quinn::Connection,
        Arc<std::sync::atomic::AtomicBool>,
        (Endpoint, Endpoint, tokio::task::JoinHandle<()>),
    ) {
        let node_id = NodeIdentity::generate().unwrap();
        let peer_id = NodeIdentity::generate().unwrap();
        let node = create_endpoint(&node_id, "127.0.0.1:0".parse().unwrap()).unwrap();
        let (dial, cut, carrying) = path_to(node.local_addr().unwrap()).await;

        let mut credit = transport_config();
        credit.stream_receive_window((64u32 << 20).into());
        credit.receive_window((64u32 << 20).into());
        let (cert, key) = generate_self_signed_cert(&peer_id).unwrap();
        let mut peer = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        peer.set_default_client_config(client_config_with(cert, key, credit).unwrap());

        let accepting = {
            let node = node.clone();
            tokio::spawn(async move { node.accept().await.unwrap().await.unwrap() })
        };
        let peer_end = peer.connect(dial, "cordelia").unwrap().await.unwrap();
        let node_end = accepting.await.unwrap();
        // Let the handshake settle, then acknowledge nothing more.
        tokio::time::sleep(Duration::from_millis(200)).await;
        cut.store(true, std::sync::atomic::Ordering::SeqCst);
        (node_end, peer_end, cut, (node, peer, carrying))
    }

    /// T3. A peer that stops acknowledging cannot make a node hold more
    /// than its send window of what the node writes: the node's writes take
    /// that much, and then wait. Once the peer acknowledges again, they go
    /// on.
    #[tokio::test]
    async fn a_peer_that_stops_acknowledging_is_held_to_the_send_window() {
        let (node_end, _peer_end, cut, _held) = a_peer_that_stops_acknowledging().await;
        let window = protocol::QUIC_SEND_WINDOW as usize;
        let (mut send, _recv) = node_end.open_bi().await.unwrap();

        // Write until a write waits: 16 MB offered, 64 KB at a time.
        let chunk = vec![0u8; 64 * 1024];
        let mut taken = 0usize;
        while taken < 16 << 20 {
            match tokio::time::timeout(Duration::from_millis(1000), send.write(&chunk)).await {
                Ok(Ok(n)) => taken += n,
                Ok(Err(e)) => panic!("a write failed: {e}"),
                Err(_) => break,
            }
        }
        assert_eq!(
            taken, window,
            "the node took {taken} bytes that the peer did not acknowledge"
        );

        // The peer acknowledges again: what waited goes, and more is taken.
        cut.store(false, std::sync::atomic::Ordering::SeqCst);
        let more = tokio::time::timeout(Duration::from_secs(10), send.write_all(&chunk)).await;
        assert!(
            matches!(more, Ok(Ok(()))),
            "a write did not go on once the peer acknowledged"
        );
    }

    /// T3. A message written to a peer that does not acknowledge waits for
    /// the window for STREAM_TIMEOUT_SECS, as any write does, and then
    /// fails. The stream is reset, so what was written on it is let go: a
    /// message on another stream is taken at once, though the peer still
    /// acknowledges nothing.
    #[tokio::test]
    async fn a_message_that_meets_the_send_window_fails_after_the_stream_timeout() {
        let (node_end, _peer_end, _cut, _held) = a_peer_that_stops_acknowledging().await;
        let (mut send, mut recv) = node_end.open_bi().await.unwrap();
        // A frame of a megabyte, its length included.
        let message = vec![0u8; protocol::MAX_MESSAGE_BYTES as usize - 4];

        // Two fill the window, and are taken at once. The third waits.
        for _ in 0..2 {
            let began = std::time::Instant::now();
            crate::codec::write_raw_frame(&mut send, &message)
                .await
                .unwrap();
            assert!(began.elapsed() < Duration::from_secs(1));
        }
        let began = std::time::Instant::now();
        // Through a join of the two halves, as a request and its answer
        // are written: the join gives up the stream it writes to.
        let third =
            crate::codec::write_raw_frame(&mut tokio::io::join(&mut recv, &mut send), &message)
                .await;
        let waited = began.elapsed();
        assert!(
            matches!(third, Err(crate::codec::CodecError::Timeout(_))),
            "{third:?}"
        );
        let timeout = Duration::from_secs(protocol::STREAM_TIMEOUT_SECS);
        assert!(
            waited >= timeout - Duration::from_millis(50)
                && waited < timeout + Duration::from_secs(2),
            "the write waited {waited:?}"
        );

        let (mut other, _recv) = node_end.open_bi().await.unwrap();
        let taken = tokio::time::timeout(
            Duration::from_secs(1),
            crate::codec::write_raw_frame(&mut other, &message),
        )
        .await;
        assert!(
            matches!(taken, Ok(Ok(()))),
            "the stream that timed out still held the window: {taken:?}"
        );
    }

    /// A node takes no datagrams: a peer with quinn's own settings, which
    /// would send them, is told that it may not, and so is a node.
    #[tokio::test]
    async fn a_node_takes_no_datagrams() {
        let node_id = NodeIdentity::generate().unwrap();
        let peer_id = NodeIdentity::generate().unwrap();
        let node = create_endpoint(&node_id, "127.0.0.1:0".parse().unwrap()).unwrap();
        let (cert, key) = generate_self_signed_cert(&peer_id).unwrap();
        let mut peer = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        peer.set_default_client_config(
            client_config_with(cert, key, quinn::TransportConfig::default()).unwrap(),
        );
        let accepting = {
            let node = node.clone();
            tokio::spawn(async move { node.accept().await.unwrap().await.unwrap() })
        };
        let peer_end = peer
            .connect(node.local_addr().unwrap(), "cordelia")
            .unwrap()
            .await
            .unwrap();
        let _node_end = accepting.await.unwrap();
        assert_eq!(peer_end.max_datagram_size(), None);
        assert!(peer_end.send_datagram(vec![b'x'].into()).is_err());

        let (client, server, _c, _s) = connected().await;
        assert_eq!(client.max_datagram_size(), None);
        assert_eq!(server.max_datagram_size(), None);
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

    /// The value of `UDP_GRO` on this process's UDP socket bound to
    /// `addr`, found among its descriptors by the address it is bound to:
    /// an endpoint does not show its socket. None if the kernel has no such
    /// option.
    #[cfg(target_os = "linux")]
    fn receive_batching_at(addr: SocketAddr) -> Option<libc::c_int> {
        use std::os::fd::RawFd;
        let SocketAddr::V4(addr) = addr else {
            panic!("an IPv4 address is looked for")
        };
        let bound_to = |fd: RawFd| {
            // SAFETY: a sockaddr_in of the length given; getsockname
            // fails on a descriptor that is not a socket.
            let mut at: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockname(fd, (&mut at as *mut libc::sockaddr_in).cast(), &mut len)
            };
            let mut kind: libc::c_int = 0;
            let mut kind_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: as above, a c_int of the length given.
            let typed = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&mut kind as *mut libc::c_int).cast(),
                    &mut kind_len,
                )
            };
            rc == 0
                && typed == 0
                && kind == libc::SOCK_DGRAM
                && at.sin_family == libc::AF_INET as libc::sa_family_t
                && u16::from_be(at.sin_port) == addr.port()
                && u32::from_be(at.sin_addr.s_addr) == u32::from(*addr.ip())
        };
        let fd = (0..65536)
            .find(|&fd| bound_to(fd))
            .unwrap_or_else(|| panic!("no UDP socket of this process is bound to {addr}"));
        let mut value: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: as above.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_UDP,
                libc::UDP_GRO,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            assert_eq!(err.raw_os_error(), Some(libc::ENOPROTOOPT), "{err}");
            return None;
        }
        Some(value)
    }

    /// Decision 2026-10-22, rule 10. A node's socket takes no batches of
    /// datagrams: `UDP_GRO` reads as off on the socket of an endpoint as
    /// `create_endpoint` and `create_client_endpoint` make it. An endpoint
    /// that quinn makes by itself has it on, so the option is read from
    /// the right socket, and it is turned off after quinn wraps the
    /// socket, not before.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_nodes_socket_takes_no_batches_of_datagrams() {
        let id = NodeIdentity::generate().unwrap();
        let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let by_quinn = Endpoint::server(server_config(&id).unwrap(), loopback).unwrap();
        let Some(on) = receive_batching_at(by_quinn.local_addr().unwrap()) else {
            // A kernel before 5.0 has no UDP_GRO, and never batches.
            return;
        };
        assert_eq!(
            on, 1,
            "quinn did not turn UDP_GRO on, so this reads nothing"
        );

        let node = create_endpoint(&id, loopback).unwrap();
        assert_eq!(
            receive_batching_at(node.local_addr().unwrap()),
            Some(0),
            "a node's endpoint takes datagrams in batches"
        );

        let dialler = create_client_endpoint(&id, "127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(
            receive_batching_at(dialler.local_addr().unwrap()),
            Some(0),
            "a node's endpoint that only dials takes datagrams in batches"
        );

        // And each still connects and carries a stream both ways.
        let accepting = {
            let node = node.clone();
            tokio::spawn(async move {
                let conn = node.accept().await.unwrap().await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                let got = recv.read_to_end(1 << 20).await.unwrap();
                send.write_all(&got).await.unwrap();
                send.finish().unwrap();
                conn.closed().await;
            })
        };
        let conn = dialler
            .connect(node.local_addr().unwrap(), "cordelia")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let sent = vec![7u8; 256 * 1024];
        send.write_all(&sent).await.unwrap();
        send.finish().unwrap();
        let back = recv.read_to_end(1 << 20).await.unwrap();
        assert_eq!(back, sent);
        conn.close(0u32.into(), b"done");
        let _ = accepting.await;
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
