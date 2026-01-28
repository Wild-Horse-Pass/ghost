//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: transport.rs                                                                                                   |
//|======================================================================================================================|

//! Anonymous transport layer for mesh network
//!
//! Provides transport abstraction supporting:
//! - TCP (default, clearnet)
//! - Tor via SOCKS5 proxy
//! - I2P via SAM bridge
//!
//! # Privacy Architecture
//!
//! For privacy-sensitive deployments, nodes can operate over Tor or I2P
//! to hide their real IP addresses from other mesh participants.
//!
//! ## Tor Mode
//! - Requires a running Tor daemon with SOCKS5 proxy (default: 127.0.0.1:9050)
//! - All outbound connections routed through Tor circuits
//! - Can operate as a Tor hidden service for inbound connections
//!
//! ## I2P Mode
//! - Requires a running I2P router with SAM bridge enabled
//! - Connections routed through I2P garlic routing
//! - Can operate as an I2P destination (eepsite) for inbound

use std::fmt;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

/// Transport type for mesh connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    /// Direct TCP (clearnet) - default, no privacy protection
    Tcp,
    /// Tor SOCKS5 proxy - hides IP via onion routing
    Tor,
    /// I2P SAM bridge - hides IP via garlic routing
    I2p,
}

impl Default for TransportType {
    fn default() -> Self {
        Self::Tcp
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Tor => write!(f, "tor"),
            Self::I2p => write!(f, "i2p"),
        }
    }
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Primary transport type
    pub transport_type: TransportType,
    /// Tor-specific configuration
    #[serde(default)]
    pub tor: TorConfig,
    /// I2P-specific configuration
    #[serde(default)]
    pub i2p: I2pConfig,
    /// Connection timeout
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// Allow fallback to TCP if anonymous transport fails
    #[serde(default)]
    pub allow_clearnet_fallback: bool,
}

fn default_connect_timeout_secs() -> u64 {
    30
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            transport_type: TransportType::Tcp,
            tor: TorConfig::default(),
            i2p: I2pConfig::default(),
            connect_timeout_secs: 30,
            allow_clearnet_fallback: false,
        }
    }
}

/// Tor transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    /// Enable Tor transport
    pub enabled: bool,
    /// SOCKS5 proxy address (Tor daemon)
    pub socks_proxy: String,
    /// Tor control port for hidden service management
    pub control_port: Option<String>,
    /// Control port authentication cookie file
    pub control_auth_cookie: Option<PathBuf>,
    /// Create a hidden service for inbound connections
    pub hidden_service: bool,
    /// Hidden service directory (for persistent .onion address)
    pub hidden_service_dir: Option<PathBuf>,
    /// Our .onion address (set after hidden service creation)
    #[serde(skip_serializing)]
    pub onion_address: Option<String>,
    /// Require all connections go through Tor (no clearnet)
    pub strict_mode: bool,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socks_proxy: "127.0.0.1:9050".to_string(),
            control_port: None,
            control_auth_cookie: None,
            hidden_service: false,
            hidden_service_dir: None,
            onion_address: None,
            strict_mode: false,
        }
    }
}

/// I2P transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct I2pConfig {
    /// Enable I2P transport
    pub enabled: bool,
    /// SAM bridge address
    pub sam_address: String,
    /// Session name (for reconnection)
    pub session_name: String,
    /// Our I2P destination (b32 address)
    #[serde(skip_serializing)]
    pub destination: Option<String>,
    /// Signature type for destination
    pub signature_type: I2pSignatureType,
    /// Inbound tunnel length (hops)
    pub inbound_length: u8,
    /// Outbound tunnel length (hops)
    pub outbound_length: u8,
    /// Require all connections go through I2P (no clearnet)
    pub strict_mode: bool,
}

impl Default for I2pConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sam_address: "127.0.0.1:7656".to_string(),
            session_name: "ghost-mesh".to_string(),
            destination: None,
            signature_type: I2pSignatureType::EdDsaSha512Ed25519,
            inbound_length: 3,
            outbound_length: 3,
            strict_mode: false,
        }
    }
}

/// I2P signature types for destination generation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum I2pSignatureType {
    /// DSA-SHA1 (legacy, not recommended)
    DsaSha1,
    /// ECDSA-SHA256-P256
    EcdsaSha256P256,
    /// ECDSA-SHA384-P384
    EcdsaSha384P384,
    /// ECDSA-SHA512-P521
    EcdsaSha512P521,
    /// Ed25519-SHA512 (recommended)
    EdDsaSha512Ed25519,
}

impl Default for I2pSignatureType {
    fn default() -> Self {
        Self::EdDsaSha512Ed25519
    }
}

impl I2pSignatureType {
    pub fn sam_code(&self) -> u8 {
        match self {
            Self::DsaSha1 => 0,
            Self::EcdsaSha256P256 => 1,
            Self::EcdsaSha384P384 => 2,
            Self::EcdsaSha512P521 => 3,
            Self::EdDsaSha512Ed25519 => 7,
        }
    }
}

/// Transport errors
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("Tor error: {0}")]
    Tor(String),

    #[error("I2P error: {0}")]
    I2p(String),

    #[error("SOCKS5 error: {0}")]
    Socks5(String),

    #[error("SAM protocol error: {0}")]
    Sam(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Transport not available: {0}")]
    NotAvailable(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

/// Anonymous address representation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AnonymousAddress {
    /// Regular TCP address (IP:port)
    Tcp(String),
    /// Tor .onion address
    Onion(String),
    /// I2P .b32.i2p address
    I2p(String),
}

impl AnonymousAddress {
    /// Parse an address string into appropriate type
    pub fn parse(addr: &str) -> Self {
        if addr.ends_with(".onion") || addr.contains(".onion:") {
            Self::Onion(addr.to_string())
        } else if addr.ends_with(".i2p") || addr.contains(".i2p:") {
            Self::I2p(addr.to_string())
        } else {
            Self::Tcp(addr.to_string())
        }
    }

    /// Get the transport type for this address
    pub fn transport_type(&self) -> TransportType {
        match self {
            Self::Tcp(_) => TransportType::Tcp,
            Self::Onion(_) => TransportType::Tor,
            Self::I2p(_) => TransportType::I2p,
        }
    }

    /// Get the raw address string
    pub fn as_str(&self) -> &str {
        match self {
            Self::Tcp(s) | Self::Onion(s) | Self::I2p(s) => s,
        }
    }
}

impl fmt::Display for AnonymousAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(a) => write!(f, "tcp://{}", a),
            Self::Onion(a) => write!(f, "onion://{}", a),
            Self::I2p(a) => write!(f, "i2p://{}", a),
        }
    }
}

/// Transport layer for anonymous mesh connections
pub struct Transport {
    config: TransportConfig,
    /// Cached Tor SOCKS proxy address
    tor_proxy: Option<SocketAddr>,
    /// I2P SAM session state
    i2p_session: RwLock<Option<I2pSession>>,
}

/// I2P SAM session state
struct I2pSession {
    /// Our destination (base64)
    destination: String,
    /// Our b32 address
    b32_address: String,
    /// Session ID
    session_id: String,
}

impl Transport {
    /// Create a new transport layer
    pub fn new(config: TransportConfig) -> Result<Self, TransportError> {
        let tor_proxy = if config.tor.enabled {
            let addr: SocketAddr = config.tor.socks_proxy.parse().map_err(|e| {
                TransportError::InvalidAddress(format!(
                    "Invalid Tor SOCKS proxy address '{}': {}",
                    config.tor.socks_proxy, e
                ))
            })?;
            Some(addr)
        } else {
            None
        };

        Ok(Self {
            config,
            tor_proxy,
            i2p_session: RwLock::new(None),
        })
    }

    /// Get the configured transport type
    pub fn transport_type(&self) -> TransportType {
        self.config.transport_type
    }

    /// Check if Tor is available
    pub async fn check_tor_available(&self) -> Result<(), TransportError> {
        if !self.config.tor.enabled {
            return Err(TransportError::NotAvailable("Tor not enabled".into()));
        }

        let proxy = self
            .tor_proxy
            .ok_or_else(|| TransportError::NotAvailable("Tor proxy not configured".into()))?;

        // Try to connect to the SOCKS proxy
        let timeout = Duration::from_secs(5);
        match tokio::time::timeout(timeout, TcpStream::connect(proxy)).await {
            Ok(Ok(_stream)) => {
                info!(proxy = %proxy, "Tor SOCKS proxy is available");
                Ok(())
            }
            Ok(Err(e)) => Err(TransportError::Tor(format!(
                "Cannot connect to Tor SOCKS proxy at {}: {}",
                proxy, e
            ))),
            Err(_) => Err(TransportError::Timeout(
                "Tor SOCKS proxy connection timed out".into(),
            )),
        }
    }

    /// Check if I2P SAM is available
    pub async fn check_i2p_available(&self) -> Result<(), TransportError> {
        if !self.config.i2p.enabled {
            return Err(TransportError::NotAvailable("I2P not enabled".into()));
        }

        let sam_addr: SocketAddr = self.config.i2p.sam_address.parse().map_err(|e| {
            TransportError::InvalidAddress(format!(
                "Invalid I2P SAM address '{}': {}",
                self.config.i2p.sam_address, e
            ))
        })?;

        let timeout = Duration::from_secs(5);
        match tokio::time::timeout(timeout, TcpStream::connect(sam_addr)).await {
            Ok(Ok(mut stream)) => {
                // Send HELLO to verify SAM protocol
                let hello = "HELLO VERSION MIN=3.0 MAX=3.3\n";
                stream
                    .write_all(hello.as_bytes())
                    .await
                    .map_err(|e| TransportError::Sam(format!("Failed to send HELLO: {}", e)))?;

                let mut response = vec![0u8; 256];
                let n = stream
                    .read(&mut response)
                    .await
                    .map_err(|e| TransportError::Sam(format!("Failed to read response: {}", e)))?;

                let response_str = String::from_utf8_lossy(&response[..n]);
                if response_str.contains("HELLO REPLY RESULT=OK") {
                    info!(sam = %sam_addr, "I2P SAM bridge is available");
                    Ok(())
                } else {
                    Err(TransportError::Sam(format!(
                        "SAM HELLO failed: {}",
                        response_str.trim()
                    )))
                }
            }
            Ok(Err(e)) => Err(TransportError::I2p(format!(
                "Cannot connect to I2P SAM bridge at {}: {}",
                sam_addr, e
            ))),
            Err(_) => Err(TransportError::Timeout(
                "I2P SAM bridge connection timed out".into(),
            )),
        }
    }

    /// Initialize I2P session (creates destination if needed)
    pub async fn init_i2p_session(&self) -> Result<String, TransportError> {
        if !self.config.i2p.enabled {
            return Err(TransportError::NotAvailable("I2P not enabled".into()));
        }

        // Check if we already have a session
        if let Some(session) = self.i2p_session.read().as_ref() {
            return Ok(session.b32_address.clone());
        }

        let sam_addr: SocketAddr = self
            .config
            .i2p
            .sam_address
            .parse()
            .map_err(|e: std::net::AddrParseError| TransportError::InvalidAddress(e.to_string()))?;

        let mut stream = TcpStream::connect(sam_addr)
            .await
            .map_err(|e| TransportError::I2p(format!("Failed to connect to SAM: {}", e)))?;

        // HELLO handshake
        let hello = "HELLO VERSION MIN=3.0 MAX=3.3\n";
        stream.write_all(hello.as_bytes()).await?;

        let mut response = vec![0u8; 1024];
        let n = stream.read(&mut response).await?;
        let response_str = String::from_utf8_lossy(&response[..n]);

        if !response_str.contains("HELLO REPLY RESULT=OK") {
            return Err(TransportError::Sam(format!(
                "HELLO failed: {}",
                response_str
            )));
        }

        // Create session with TRANSIENT destination
        let session_create = format!(
            "SESSION CREATE STYLE=STREAM ID={} DESTINATION=TRANSIENT SIGNATURE_TYPE={}\n",
            self.config.i2p.session_name,
            self.config.i2p.signature_type.sam_code()
        );
        stream.write_all(session_create.as_bytes()).await?;

        let n = stream.read(&mut response).await?;
        let response_str = String::from_utf8_lossy(&response[..n]);

        if !response_str.contains("SESSION STATUS RESULT=OK") {
            return Err(TransportError::Sam(format!(
                "SESSION CREATE failed: {}",
                response_str
            )));
        }

        // Parse destination from response
        let dest_start = response_str
            .find("DESTINATION=")
            .ok_or_else(|| TransportError::Sam("No DESTINATION in response".into()))?;
        let dest_str = &response_str[dest_start + 12..];
        let dest_end = dest_str.find(char::is_whitespace).unwrap_or(dest_str.len());
        let destination = dest_str[..dest_end].to_string();

        // Calculate b32 address from destination
        let b32_address = self.calculate_i2p_b32(&destination)?;

        info!(
            b32 = %b32_address,
            "I2P session created"
        );

        let session = I2pSession {
            destination,
            b32_address: b32_address.clone(),
            session_id: self.config.i2p.session_name.clone(),
        };

        *self.i2p_session.write() = Some(session);

        Ok(b32_address)
    }

    /// Calculate I2P b32 address from destination
    fn calculate_i2p_b32(&self, destination: &str) -> Result<String, TransportError> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        use sha2::{Digest, Sha256};

        // Decode base64 destination
        let dest_bytes = STANDARD
            .decode(destination)
            .map_err(|e| TransportError::I2p(format!("Invalid destination base64: {}", e)))?;

        // SHA-256 hash
        let mut hasher = Sha256::new();
        hasher.update(&dest_bytes);
        let hash = hasher.finalize();

        // Base32 encode (I2P uses lowercase RFC4648 without padding)
        let b32 = base32_encode_lowercase(&hash);

        Ok(format!("{}.b32.i2p", b32))
    }
}

/// RFC4648 Base32 lowercase encoding (no padding) for I2P b32 addresses
fn base32_encode_lowercase(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

    let mut result = String::new();
    let mut bits = 0u64;
    let mut num_bits = 0;

    for &byte in data {
        bits = (bits << 8) | (byte as u64);
        num_bits += 8;

        while num_bits >= 5 {
            num_bits -= 5;
            let index = ((bits >> num_bits) & 0x1f) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    // Handle remaining bits
    if num_bits > 0 {
        let index = ((bits << (5 - num_bits)) & 0x1f) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}

impl Transport {
    /// Connect to a peer via the configured transport
    pub async fn connect(
        &self,
        address: &AnonymousAddress,
    ) -> Result<Box<dyn AsyncStream>, TransportError> {
        let addr_transport = address.transport_type();

        match (self.config.transport_type, addr_transport) {
            // Direct TCP connection
            (TransportType::Tcp, TransportType::Tcp) => self.connect_tcp(address.as_str()).await,

            // Tor connection to .onion address (Tor transport for Tor address)
            (TransportType::Tor, TransportType::Tor) | (_, TransportType::Tor)
                if self.config.tor.enabled =>
            {
                self.connect_via_tor(address.as_str()).await
            }

            // Tor connection to clearnet address (for privacy)
            (TransportType::Tor, TransportType::Tcp) if self.config.tor.enabled => {
                if self.config.tor.strict_mode {
                    return Err(TransportError::Tor(
                        "Strict Tor mode enabled - cannot connect to clearnet addresses".into(),
                    ));
                }
                self.connect_via_tor(address.as_str()).await
            }

            // I2P connection to .i2p address
            (TransportType::I2p, TransportType::I2p) | (_, TransportType::I2p)
                if self.config.i2p.enabled =>
            {
                self.connect_via_i2p(address.as_str()).await
            }

            // Clearnet fallback
            (_, TransportType::Tcp) if self.config.allow_clearnet_fallback => {
                warn!(
                    address = %address,
                    "Falling back to clearnet TCP connection"
                );
                self.connect_tcp(address.as_str()).await
            }

            // Cannot connect
            _ => Err(TransportError::NotAvailable(format!(
                "Cannot connect to {} address with {} transport (fallback disabled)",
                addr_transport, self.config.transport_type
            ))),
        }
    }

    /// Direct TCP connection
    async fn connect_tcp(&self, address: &str) -> Result<Box<dyn AsyncStream>, TransportError> {
        let timeout = Duration::from_secs(self.config.connect_timeout_secs);

        debug!(address = %address, "Connecting via TCP");

        match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                info!(address = %address, "TCP connection established");
                Ok(Box::new(stream))
            }
            Ok(Err(e)) => Err(TransportError::Connection(format!(
                "TCP connection to {} failed: {}",
                address, e
            ))),
            Err(_) => Err(TransportError::Timeout(format!(
                "TCP connection to {} timed out",
                address
            ))),
        }
    }

    /// Connect via Tor SOCKS5 proxy
    async fn connect_via_tor(&self, address: &str) -> Result<Box<dyn AsyncStream>, TransportError> {
        let proxy = self
            .tor_proxy
            .ok_or_else(|| TransportError::NotAvailable("Tor proxy not configured".into()))?;

        debug!(address = %address, proxy = %proxy, "Connecting via Tor");

        // Parse target address
        let (host, port) = self.parse_host_port(address)?;

        // Connect to SOCKS proxy
        let timeout = Duration::from_secs(self.config.connect_timeout_secs);
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(proxy))
            .await
            .map_err(|_| TransportError::Timeout("Tor proxy connection timed out".into()))?
            .map_err(|e| TransportError::Tor(format!("Failed to connect to Tor proxy: {}", e)))?;

        // SOCKS5 handshake
        self.socks5_handshake(&mut stream, &host, port).await?;

        info!(address = %address, "Tor connection established");
        Ok(Box::new(stream))
    }

    /// Connect via I2P SAM bridge
    async fn connect_via_i2p(&self, address: &str) -> Result<Box<dyn AsyncStream>, TransportError> {
        // Ensure we have a session
        self.init_i2p_session().await?;

        let sam_addr: SocketAddr = self
            .config
            .i2p
            .sam_address
            .parse()
            .map_err(|e: std::net::AddrParseError| TransportError::InvalidAddress(e.to_string()))?;

        debug!(address = %address, sam = %sam_addr, "Connecting via I2P");

        // Connect to SAM for STREAM CONNECT
        let mut stream = TcpStream::connect(sam_addr)
            .await
            .map_err(|e| TransportError::I2p(format!("Failed to connect to SAM: {}", e)))?;

        // HELLO
        stream.write_all(b"HELLO VERSION MIN=3.0 MAX=3.3\n").await?;
        let mut response = vec![0u8; 1024];
        let n = stream.read(&mut response).await?;
        let response_str = String::from_utf8_lossy(&response[..n]);

        if !response_str.contains("HELLO REPLY RESULT=OK") {
            return Err(TransportError::Sam(format!(
                "HELLO failed: {}",
                response_str
            )));
        }

        // STREAM CONNECT
        let connect_cmd = format!(
            "STREAM CONNECT ID={} DESTINATION={} SILENT=false\n",
            self.config.i2p.session_name, address
        );
        stream.write_all(connect_cmd.as_bytes()).await?;

        let n = stream.read(&mut response).await?;
        let response_str = String::from_utf8_lossy(&response[..n]);

        if response_str.contains("STREAM STATUS RESULT=OK") {
            info!(address = %address, "I2P connection established");
            Ok(Box::new(stream))
        } else {
            Err(TransportError::I2p(format!(
                "STREAM CONNECT failed: {}",
                response_str
            )))
        }
    }

    /// Parse host:port from address string
    fn parse_host_port(&self, address: &str) -> Result<(String, u16), TransportError> {
        // Remove protocol prefix if present
        let addr = address
            .strip_prefix("tcp://")
            .or_else(|| address.strip_prefix("onion://"))
            .or_else(|| address.strip_prefix("i2p://"))
            .unwrap_or(address);

        // Split host:port
        if let Some(colon_pos) = addr.rfind(':') {
            let host = addr[..colon_pos].to_string();
            let port: u16 = addr[colon_pos + 1..].parse().map_err(|e| {
                TransportError::InvalidAddress(format!(
                    "Invalid port in address '{}': {}",
                    address, e
                ))
            })?;
            Ok((host, port))
        } else {
            Err(TransportError::InvalidAddress(format!(
                "Address '{}' missing port",
                address
            )))
        }
    }

    /// SOCKS5 handshake implementation
    async fn socks5_handshake(
        &self,
        stream: &mut TcpStream,
        host: &str,
        port: u16,
    ) -> Result<(), TransportError> {
        // Version identifier/method selection
        // [version (1), nmethods (1), methods (1..255)]
        // We support: 0x00 = no auth
        stream.write_all(&[0x05, 0x01, 0x00]).await?;

        // Read method selection response
        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|e| TransportError::Socks5(format!("Failed to read auth method: {}", e)))?;

        if response[0] != 0x05 {
            return Err(TransportError::Socks5(
                "Invalid SOCKS version in response".into(),
            ));
        }
        if response[1] != 0x00 {
            return Err(TransportError::Socks5(format!(
                "SOCKS proxy requires auth method 0x{:02x}, we only support 0x00 (none)",
                response[1]
            )));
        }

        // Connection request
        // [version (1), cmd (1), reserved (1), atyp (1), addr (var), port (2)]
        let mut request = vec![
            0x05, // version
            0x01, // cmd: CONNECT
            0x00, // reserved
        ];

        // Address type and address
        if host.ends_with(".onion") {
            // Domain name (ATYP = 0x03)
            request.push(0x03);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        } else if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            // IPv4 (ATYP = 0x01)
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            // IPv6 (ATYP = 0x04)
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        } else {
            // Domain name (ATYP = 0x03)
            request.push(0x03);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }

        // Port (big-endian)
        request.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&request).await?;

        // Read connection response
        // [version (1), reply (1), reserved (1), atyp (1), addr (var), port (2)]
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.map_err(|e| {
            TransportError::Socks5(format!("Failed to read connect response: {}", e))
        })?;

        if response[0] != 0x05 {
            return Err(TransportError::Socks5(
                "Invalid SOCKS version in connect response".into(),
            ));
        }

        // Check reply code
        match response[1] {
            0x00 => (), // Success
            0x01 => {
                return Err(TransportError::Socks5(
                    "General SOCKS server failure".into(),
                ))
            }
            0x02 => {
                return Err(TransportError::Socks5(
                    "Connection not allowed by ruleset".into(),
                ))
            }
            0x03 => return Err(TransportError::Socks5("Network unreachable".into())),
            0x04 => return Err(TransportError::Socks5("Host unreachable".into())),
            0x05 => return Err(TransportError::Socks5("Connection refused".into())),
            0x06 => return Err(TransportError::Socks5("TTL expired".into())),
            0x07 => return Err(TransportError::Socks5("Command not supported".into())),
            0x08 => return Err(TransportError::Socks5("Address type not supported".into())),
            code => {
                return Err(TransportError::Socks5(format!(
                    "Unknown error code: 0x{:02x}",
                    code
                )))
            }
        }

        // Read and discard bound address (we don't need it)
        let atyp = response[3];
        let addr_len = match atyp {
            0x01 => 4, // IPv4
            0x03 => {
                // Domain - first read length byte
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                len[0] as usize
            }
            0x04 => 16, // IPv6
            _ => {
                return Err(TransportError::Socks5(format!(
                    "Unknown address type: 0x{:02x}",
                    atyp
                )))
            }
        };

        // Read address + port
        let mut addr_port = vec![0u8; addr_len + 2];
        stream.read_exact(&mut addr_port).await?;

        debug!(host = %host, port = %port, "SOCKS5 handshake complete");
        Ok(())
    }

    /// Get our anonymous address for this transport
    pub async fn get_our_address(&self, port: u16) -> Result<AnonymousAddress, TransportError> {
        match self.config.transport_type {
            TransportType::Tcp => {
                // Would need to determine public IP - for now return placeholder
                Ok(AnonymousAddress::Tcp(format!("0.0.0.0:{}", port)))
            }
            TransportType::Tor => {
                if let Some(ref onion) = self.config.tor.onion_address {
                    Ok(AnonymousAddress::Onion(format!("{}:{}", onion, port)))
                } else {
                    Err(TransportError::NotAvailable(
                        "Tor hidden service not configured".into(),
                    ))
                }
            }
            TransportType::I2p => {
                let session = self.i2p_session.read();
                if let Some(ref sess) = *session {
                    Ok(AnonymousAddress::I2p(format!(
                        "{}:{}",
                        sess.b32_address, port
                    )))
                } else {
                    Err(TransportError::NotAvailable(
                        "I2P session not initialized".into(),
                    ))
                }
            }
        }
    }

    /// Get the transport configuration
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }
}

/// Trait for async read/write streams
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymous_address_parse() {
        assert!(matches!(
            AnonymousAddress::parse("127.0.0.1:8080"),
            AnonymousAddress::Tcp(_)
        ));

        assert!(matches!(
            AnonymousAddress::parse("abc123.onion:8080"),
            AnonymousAddress::Onion(_)
        ));

        assert!(matches!(
            AnonymousAddress::parse("xyz456.b32.i2p:8080"),
            AnonymousAddress::I2p(_)
        ));
    }

    #[test]
    fn test_transport_type_display() {
        assert_eq!(TransportType::Tcp.to_string(), "tcp");
        assert_eq!(TransportType::Tor.to_string(), "tor");
        assert_eq!(TransportType::I2p.to_string(), "i2p");
    }

    #[test]
    fn test_i2p_signature_type_codes() {
        assert_eq!(I2pSignatureType::DsaSha1.sam_code(), 0);
        assert_eq!(I2pSignatureType::EdDsaSha512Ed25519.sam_code(), 7);
    }

    #[test]
    fn test_default_configs() {
        let config = TransportConfig::default();
        assert_eq!(config.transport_type, TransportType::Tcp);
        assert!(!config.tor.enabled);
        assert!(!config.i2p.enabled);

        let tor = TorConfig::default();
        assert_eq!(tor.socks_proxy, "127.0.0.1:9050");

        let i2p = I2pConfig::default();
        assert_eq!(i2p.sam_address, "127.0.0.1:7656");
    }

    #[test]
    fn test_parse_host_port() {
        let config = TransportConfig::default();
        let transport = Transport::new(config).unwrap();

        let (host, port) = transport.parse_host_port("127.0.0.1:8080").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);

        let (host, port) = transport.parse_host_port("tcp://example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);

        let (host, port) = transport.parse_host_port("abc123.onion:8555").unwrap();
        assert_eq!(host, "abc123.onion");
        assert_eq!(port, 8555);

        assert!(transport.parse_host_port("no-port").is_err());
    }

    #[tokio::test]
    async fn test_transport_new() {
        // Default config should work
        let config = TransportConfig::default();
        assert!(Transport::new(config).is_ok());

        // Invalid SOCKS proxy should fail
        let mut config = TransportConfig::default();
        config.tor.enabled = true;
        config.tor.socks_proxy = "not-an-address".to_string();
        assert!(Transport::new(config).is_err());
    }
}
