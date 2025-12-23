/// Protocol state used to select packet IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketState {
    Handshaking,
    Status,
    Login,
}

/// Next state value in the handshake packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeNextState {
    Status,
    Login,
}
