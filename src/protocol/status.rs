use thiserror::Error;

use super::{impl_packet_for, impl_request_id, Packet, RequestId};

/// Error Codes for SSH_FXP_STATUS
#[derive(Debug, Error, Clone, Copy, PartialEq)]
pub enum StatusCode {
    /// Indicates successful completion of the operation.
    #[error("Ok")]
    Ok,
    /// Indicates end-of-file condition; for SSH_FX_READ it means that no more data is available in the file,
    /// and for SSH_FX_READDIR it indicates that no more files are contained in the directory.
    #[error("Eof")]
    Eof,
    /// A reference is made to a file which should exist but doesn't.
    #[error("No such file")]
    NoSuchFile,
    /// Authenticated user does not have sufficient permissions to perform the operation.
    #[error("Permission denied")]
    PermissionDenied,
    /// A generic catch-all error message;
    /// it should be returned if an error occurs for which there is no more specific error code defined.
    #[error("Failure")]
    Failure,
    /// May be returned if a badly formatted packet or protocol incompatibility is detected.
    #[error("Bad message")]
    BadMessage,
    /// A pseudo-error which indicates that the client has no connection to the server
    /// (it can only be generated locally by the client, and MUST NOT be returned by servers).
    #[error("No connection")]
    NoConnection,
    /// A pseudo-error which indicates that the connection to the server has been lost
    /// (it can only be generated locally by the client, and MUST NOT be returned by servers).
    #[error("Connection lost")]
    ConnectionLost,
    /// Indicates that an attempt was made to perform an operation which is not supported for the server
    /// (it may be generated locally by the client if e.g. the version number exchange indicates that a required feature is not supported by the server,
    /// or it may be returned by the server if the server does not implement an operation).
    #[error("Operation unsupported")]
    OpUnsupported,
    /// A code not defined by SFTP v3, e.g. from a newer protocol version or a vendor extension.
    #[error("Unknown status code {0}")]
    Other(u32),
}

impl From<u32> for StatusCode {
    fn from(code: u32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::Eof,
            2 => Self::NoSuchFile,
            3 => Self::PermissionDenied,
            4 => Self::Failure,
            5 => Self::BadMessage,
            6 => Self::NoConnection,
            7 => Self::ConnectionLost,
            8 => Self::OpUnsupported,
            code => Self::Other(code),
        }
    }
}

impl From<StatusCode> for u32 {
    fn from(code: StatusCode) -> Self {
        match code {
            StatusCode::Ok => 0,
            StatusCode::Eof => 1,
            StatusCode::NoSuchFile => 2,
            StatusCode::PermissionDenied => 3,
            StatusCode::Failure => 4,
            StatusCode::BadMessage => 5,
            StatusCode::NoConnection => 6,
            StatusCode::ConnectionLost => 7,
            StatusCode::OpUnsupported => 8,
            StatusCode::Other(code) => code,
        }
    }
}

impl serde::Serialize for StatusCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32((*self).into())
    }
}

impl<'de> serde::Deserialize<'de> for StatusCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <u32 as serde::Deserialize>::deserialize(deserializer).map(Self::from)
    }
}

/// Implementation for SSH_FXP_STATUS as defined in the specification draft
/// <https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub id: u32,
    pub status_code: StatusCode,
    pub error_message: String,
    pub language_tag: String,
}

impl_request_id!(Status);
impl_packet_for!(Status);

#[cfg(test)]
mod tests {
    use bytes::{BufMut, Bytes, BytesMut};

    use super::*;

    #[test]
    fn codes_round_trip_including_unknown() {
        for code in 0..=12 {
            let mut wire = BytesMut::new();
            wire.put_u8(101); // STATUS
            wire.put_u32(1);
            wire.put_u32(code);
            wire.put_u32(0); // error message
            wire.put_u32(0); // language tag

            let Packet::Status(status) = Packet::try_from(&mut wire.clone().freeze()).unwrap()
            else {
                panic!("expected STATUS");
            };
            assert_eq!(u32::from(status.status_code), code);
            assert_eq!(status.status_code == StatusCode::Other(code), code > 8);

            let encoded = Bytes::try_from(Packet::Status(status)).unwrap();
            assert_eq!(encoded[4..], wire[..]);
        }
    }
}
