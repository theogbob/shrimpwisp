//! Wisp v2.1 protocol types and constants.

/// Wisp protocol version
pub const WISP_VERSION_MAJOR: u8 = 2;
pub const WISP_VERSION_MINOR: u8 = 1;

/// Packet type discriminants (contiguous 0x01-0x05 for jump table)
pub const PACKET_CONNECT: u8 = 0x01;
pub const PACKET_DATA: u8 = 0x02;
pub const PACKET_CONTINUE: u8 = 0x03;
pub const PACKET_CLOSE: u8 = 0x04;
pub const PACKET_INFO: u8 = 0x05;

/// Reserved stream ID for connection-level control
pub const STREAM_ID_CONTROL: u32 = 0;

/// Wisp header size: 1 (type) + 4 (stream_id LE) = 5 bytes
pub const WISP_HEADER_SIZE: usize = 5;

/// Stream type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamType {
    Tcp = 0x01,
    Udp = 0x02,
}

impl StreamType {
    #[inline(always)]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Tcp),
            0x02 => Some(Self::Udp),
            _ => None,
        }
    }
}

/// Close reason codes per Wisp v2.1 spec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseReason {
    /// 0x01 - Unspecified or unknown
    Unknown = 0x01,
    /// 0x02 - Voluntary stream closure (reset)
    Voluntary = 0x02,
    /// 0x03 - Unexpected closure due to network error
    NetworkError = 0x03,
    /// 0x04 - Incompatible extensions (handshake only)
    IncompatibleExtensions = 0x04,
    /// 0x41 - Invalid stream info (reserved addr, invalid port)
    InvalidInfo = 0x41,
    /// 0x42 - Unreachable destination (DNS failure)
    Unreachable = 0x42,
    /// 0x43 - Connection timed out
    TimedOut = 0x43,
    /// 0x44 - Connection refused by destination
    Refused = 0x44,
    /// 0x47 - TCP data transfer timed out
    TransferTimeout = 0x47,
    /// 0x48 - Destination blocked by proxy
    Blocked = 0x48,
    /// 0x49 - Throttled by server
    Throttled = 0x49,
    /// 0x81 - Client unexpected error
    ClientError = 0x81,
    /// 0xc0 - Auth failed: invalid credentials
    AuthInvalidCredentials = 0xc0,
    /// 0xc1 - Auth failed: invalid signature
    AuthInvalidSignature = 0xc1,
    /// 0xc2 - Auth required but not provided
    AuthRequired = 0xc2,
}

impl CloseReason {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Unknown,
            0x02 => Self::Voluntary,
            0x03 => Self::NetworkError,
            0x04 => Self::IncompatibleExtensions,
            0x41 => Self::InvalidInfo,
            0x42 => Self::Unreachable,
            0x43 => Self::TimedOut,
            0x44 => Self::Refused,
            0x47 => Self::TransferTimeout,
            0x48 => Self::Blocked,
            0x49 => Self::Throttled,
            0x81 => Self::ClientError,
            0xc0 => Self::AuthInvalidCredentials,
            0xc1 => Self::AuthInvalidSignature,
            0xc2 => Self::AuthRequired,
            _ => Self::Unknown,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// CONNECT packet parsed payload
#[derive(Debug, Clone)]
pub struct ConnectPayload {
    pub stream_type: StreamType,
    pub port: u16,
    pub hostname: String,
}

/// Extension metadata entry format
#[derive(Debug, Clone)]
pub struct ExtensionEntry {
    pub id: u8,
    pub payload: Vec<u8>,
}
