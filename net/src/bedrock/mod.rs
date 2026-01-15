pub mod batch;
pub mod error;
pub mod jwt;
pub mod login;
pub mod network_settings;
pub mod varint;

pub use batch::{Compression, decode_batch_payload, decode_packet_batch, encode_packet_batch};
pub use error::{Error, Result};
pub use login::{LoginPacket, decode_login_packet, decode_login_payload};
pub use network_settings::{
    COMPRESSION_ALGORITHM_NONE,
    COMPRESSION_ALGORITHM_SNAPPY,
    COMPRESSION_ALGORITHM_ZLIB,
    NetworkSettings,
    decode_network_settings,
    decode_request_network_settings,
    encode_network_settings,
};

pub const PACKET_BATCH_ID: u32 = 0xfe;
pub const LOGIN_PACKET_ID: u32 = 0x01;
pub const REQUEST_NETWORK_SETTINGS_PACKET_ID: u32 = 0xc1;
pub const NETWORK_SETTINGS_PACKET_ID: u32 = 0x8f;
