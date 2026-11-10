use bytes::{BufMut, BytesMut};
use russh_sftp::{
    client::SftpSession,
    protocol::{
        ExtendedReply, FileAttributes, Handle, OpenFlags, Packet, Status, StatusCode, Version,
    },
    server::{self, StatusReply},
};
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;

/// Advertises `limits@openssh.com` with a max packet length that does not fit in u32.
struct HugeLimits;

impl server::Handler for HugeLimits {
    type Error = StatusReply;

    fn unimplemented(&self) -> StatusReply {
        StatusCode::OpUnsupported.into()
    }

    async fn init(&mut self, _: u32, _: HashMap<String, String>) -> Result<Version, StatusReply> {
        let mut version = Version::new();
        version
            .extensions
            .insert("limits@openssh.com".into(), "1".into());
        Ok(version)
    }

    async fn extended(&mut self, id: u32, _: String, _: Vec<u8>) -> Result<Packet, StatusReply> {
        let mut data = BytesMut::new();
        data.put_u64(1 << 32); // max_packet_len
        data.put_u64(0);
        data.put_u64(0);
        data.put_u64(0);
        Ok(ExtendedReply {
            id,
            data: data.to_vec(),
        }
        .into())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        _: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, StatusReply> {
        Ok(Handle {
            id,
            handle: filename,
        })
    }

    async fn write(
        &mut self,
        id: u32,
        _: String,
        _: u64,
        _: Vec<u8>,
    ) -> Result<Status, StatusReply> {
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, StatusReply> {
        self.write(id, handle, 0, vec![]).await
    }
}

#[tokio::test]
async fn server_packet_limit_above_u32_does_not_disable_writes() {
    let (client, server) = tokio::io::duplex(1 << 16);
    server::run(server, HugeLimits).await;
    let sftp = SftpSession::new(client).await.unwrap();

    let mut file = sftp.open_with_flags("f", OpenFlags::WRITE).await.unwrap();
    file.write_all(b"data").await.unwrap();
    file.close().await.unwrap();
}
