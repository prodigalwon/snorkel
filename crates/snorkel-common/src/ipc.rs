pub const DEFAULT_SOCKET_PATH: &str = "/run/snorkel/janitor.sock";
pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_MESSAGE_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum DnsToJanitor {
    Wake = 1,
    Shutdown = 2,
}

impl DnsToJanitor {
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    pub const fn from_discriminant(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Wake),
            2 => Some(Self::Shutdown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    UnknownVersion,
    UnknownDiscriminant,
    TrailingBytes,
}

pub fn encode(msg: DnsToJanitor, out: &mut [u8]) -> Result<usize, DecodeError> {
    let Some(version_slot) = out.get_mut(0) else {
        return Err(DecodeError::Truncated);
    };
    *version_slot = PROTOCOL_VERSION;

    let Some(disc_slot) = out.get_mut(1) else {
        return Err(DecodeError::Truncated);
    };
    *disc_slot = msg.discriminant();

    Ok(2)
}

pub fn decode(bytes: &[u8]) -> Result<DnsToJanitor, DecodeError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(DecodeError::TrailingBytes);
    }

    let Some(&version) = bytes.first() else {
        return Err(DecodeError::Truncated);
    };
    if version != PROTOCOL_VERSION {
        return Err(DecodeError::UnknownVersion);
    }

    let Some(&discriminant) = bytes.get(1) else {
        return Err(DecodeError::Truncated);
    };

    let Some(msg) = DnsToJanitor::from_discriminant(discriminant) else {
        return Err(DecodeError::UnknownDiscriminant);
    };

    if bytes.len() != 2 {
        return Err(DecodeError::TrailingBytes);
    }

    Ok(msg)
}
