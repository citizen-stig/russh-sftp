mod attrs;
mod close;
mod data;
mod extended;
mod file;
mod file_attrs;
mod fsetstat;
mod fstat;
mod handle;
mod init;
mod lstat;
mod mkdir;
mod name;
mod open;
mod opendir;
mod read;
mod readdir;
mod readlink;
mod realpath;
mod remove;
mod rename;
mod rmdir;
mod setstat;
mod stat;
mod status;
mod symlink;
mod version;
mod write;

use bytes::{Buf, Bytes};

use crate::{de, error::Error, ser};

pub(crate) use self::write::WriteRef;
pub use self::{
    attrs::Attrs,
    close::Close,
    data::Data,
    extended::{Extended, ExtendedReply},
    file::File,
    file_attrs::{
        FileAttr, FileAttributes, FileMode, FilePermissionFlags, FilePermissions, FileType,
    },
    fsetstat::FSetStat,
    fstat::Fstat,
    handle::Handle,
    init::Init,
    lstat::Lstat,
    mkdir::MkDir,
    name::Name,
    open::{Open, OpenFlags},
    opendir::OpenDir,
    read::Read,
    readdir::ReadDir,
    readlink::ReadLink,
    realpath::RealPath,
    remove::Remove,
    rename::Rename,
    rmdir::RmDir,
    setstat::SetStat,
    stat::Stat,
    status::{Status, StatusCode},
    symlink::Symlink,
    version::Version,
    write::Write,
};

pub const VERSION: u32 = 3;

const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_FSTAT: u8 = 8;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_FSETSTAT: u8 = 10;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_READLINK: u8 = 19;
const SSH_FXP_SYMLINK: u8 = 20;

const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;

const SSH_FXP_EXTENDED: u8 = 200;
const SSH_FXP_EXTENDED_REPLY: u8 = 201;

pub(crate) trait RequestId: Sized {
    fn get_request_id(&self) -> u32;
}

macro_rules! impl_request_id {
    ($packet:ty) => {
        impl RequestId for $packet {
            fn get_request_id(&self) -> u32 {
                self.id
            }
        }
    };
}

macro_rules! impl_packet_for {
    ($name:ident) => {
        impl From<$name> for Packet {
            fn from(input: $name) -> Self {
                Self::$name(input)
            }
        }
    };
}

pub(crate) use impl_packet_for;
pub(crate) use impl_request_id;

#[derive(Debug)]
pub enum Packet {
    Init(Init),
    Version(Version),
    Open(Open),
    Close(Close),
    Read(Read),
    Write(Write),
    Lstat(Lstat),
    Fstat(Fstat),
    SetStat(SetStat),
    FSetStat(FSetStat),
    OpenDir(OpenDir),
    ReadDir(ReadDir),
    Remove(Remove),
    MkDir(MkDir),
    RmDir(RmDir),
    RealPath(RealPath),
    Stat(Stat),
    Rename(Rename),
    ReadLink(ReadLink),
    Symlink(Symlink),
    Status(Status),
    Handle(Handle),
    Data(Data),
    Name(Name),
    Attrs(Attrs),
    Extended(Extended),
    ExtendedReply(ExtendedReply),
}

impl Packet {
    pub fn get_request_id(&self) -> u32 {
        match self {
            Self::Open(open) => open.get_request_id(),
            Self::Close(close) => close.get_request_id(),
            Self::Read(read) => read.get_request_id(),
            Self::Write(write) => write.get_request_id(),
            Self::Lstat(lstat) => lstat.get_request_id(),
            Self::Fstat(fstat) => fstat.get_request_id(),
            Self::SetStat(setstat) => setstat.get_request_id(),
            Self::FSetStat(fsetstat) => fsetstat.get_request_id(),
            Self::OpenDir(opendir) => opendir.get_request_id(),
            Self::ReadDir(readdir) => readdir.get_request_id(),
            Self::Remove(remove) => remove.get_request_id(),
            Self::MkDir(mkdir) => mkdir.get_request_id(),
            Self::RmDir(rmdir) => rmdir.get_request_id(),
            Self::RealPath(realpath) => realpath.get_request_id(),
            Self::Stat(stat) => stat.get_request_id(),
            Self::Rename(rename) => rename.get_request_id(),
            Self::ReadLink(readlink) => readlink.get_request_id(),
            Self::Symlink(symlink) => symlink.get_request_id(),
            Self::Extended(extended) => extended.get_request_id(),
            _ => 0,
        }
    }

    pub fn status(id: u32, status_code: StatusCode, msg: &str, tag: &str) -> Self {
        Packet::Status(Status {
            id,
            status_code,
            error_message: msg.to_string(),
            language_tag: tag.to_string(),
        })
    }

    pub fn error(id: u32, status_code: StatusCode) -> Self {
        Self::status(id, status_code, &status_code.to_string(), "en-US")
    }
}

impl TryFrom<&mut Bytes> for Packet {
    type Error = Error;

    /// Decodes type and payload after the stream reader has consumed the length.
    fn try_from(bytes: &mut Bytes) -> Result<Self, Self::Error> {
        let r#type = bytes.try_get_u8()?;
        debug!("packet type {}", r#type);

        let request = match r#type {
            SSH_FXP_INIT => Self::Init(de::from_bytes(bytes)?),
            SSH_FXP_VERSION => Self::Version(de::from_bytes(bytes)?),
            SSH_FXP_OPEN => Self::Open(de::from_bytes(bytes)?),
            SSH_FXP_CLOSE => Self::Close(de::from_bytes(bytes)?),
            SSH_FXP_READ => Self::Read(de::from_bytes(bytes)?),
            SSH_FXP_WRITE => Self::Write(de::from_bytes(bytes)?),
            SSH_FXP_LSTAT => Self::Lstat(de::from_bytes(bytes)?),
            SSH_FXP_FSTAT => Self::Fstat(de::from_bytes(bytes)?),
            SSH_FXP_SETSTAT => Self::SetStat(de::from_bytes(bytes)?),
            SSH_FXP_FSETSTAT => Self::FSetStat(de::from_bytes(bytes)?),
            SSH_FXP_OPENDIR => Self::OpenDir(de::from_bytes(bytes)?),
            SSH_FXP_READDIR => Self::ReadDir(de::from_bytes(bytes)?),
            SSH_FXP_REMOVE => Self::Remove(de::from_bytes(bytes)?),
            SSH_FXP_MKDIR => Self::MkDir(de::from_bytes(bytes)?),
            SSH_FXP_RMDIR => Self::RmDir(de::from_bytes(bytes)?),
            SSH_FXP_REALPATH => Self::RealPath(de::from_bytes(bytes)?),
            SSH_FXP_STAT => Self::Stat(de::from_bytes(bytes)?),
            SSH_FXP_RENAME => Self::Rename(de::from_bytes(bytes)?),
            SSH_FXP_READLINK => Self::ReadLink(de::from_bytes(bytes)?),
            SSH_FXP_SYMLINK => Self::Symlink(de::from_bytes(bytes)?),
            SSH_FXP_STATUS => Self::Status(de::from_bytes(bytes)?),
            SSH_FXP_HANDLE => Self::Handle(de::from_bytes(bytes)?),
            SSH_FXP_DATA => Self::Data(de::from_bytes(bytes)?),
            SSH_FXP_NAME => Self::Name(de::from_bytes(bytes)?),
            SSH_FXP_ATTRS => Self::Attrs(de::from_bytes(bytes)?),
            SSH_FXP_EXTENDED => Self::Extended(de::from_bytes(bytes)?),
            SSH_FXP_EXTENDED_REPLY => Self::ExtendedReply(de::from_bytes(bytes)?),
            _ => return Err(Error::BadMessage("unknown type".to_owned())),
        };

        Ok(request)
    }
}

impl TryFrom<Packet> for Bytes {
    type Error = Error;

    /// Encodes length, type and payload into a single buffer.
    fn try_from(packet: Packet) -> Result<Self, Self::Error> {
        match packet {
            Packet::Init(packet) => ser::to_packet_bytes(SSH_FXP_INIT, &packet),
            Packet::Version(packet) => ser::to_packet_bytes(SSH_FXP_VERSION, &packet),
            Packet::Open(packet) => ser::to_packet_bytes(SSH_FXP_OPEN, &packet),
            Packet::Close(packet) => ser::to_packet_bytes(SSH_FXP_CLOSE, &packet),
            Packet::Read(packet) => ser::to_packet_bytes(SSH_FXP_READ, &packet),
            Packet::Write(packet) => ser::to_packet_bytes(SSH_FXP_WRITE, &packet),
            Packet::Lstat(packet) => ser::to_packet_bytes(SSH_FXP_LSTAT, &packet),
            Packet::Fstat(packet) => ser::to_packet_bytes(SSH_FXP_FSTAT, &packet),
            Packet::SetStat(packet) => ser::to_packet_bytes(SSH_FXP_SETSTAT, &packet),
            Packet::FSetStat(packet) => ser::to_packet_bytes(SSH_FXP_FSETSTAT, &packet),
            Packet::OpenDir(packet) => ser::to_packet_bytes(SSH_FXP_OPENDIR, &packet),
            Packet::ReadDir(packet) => ser::to_packet_bytes(SSH_FXP_READDIR, &packet),
            Packet::Remove(packet) => ser::to_packet_bytes(SSH_FXP_REMOVE, &packet),
            Packet::MkDir(packet) => ser::to_packet_bytes(SSH_FXP_MKDIR, &packet),
            Packet::RmDir(packet) => ser::to_packet_bytes(SSH_FXP_RMDIR, &packet),
            Packet::RealPath(packet) => ser::to_packet_bytes(SSH_FXP_REALPATH, &packet),
            Packet::Stat(packet) => ser::to_packet_bytes(SSH_FXP_STAT, &packet),
            Packet::Rename(packet) => ser::to_packet_bytes(SSH_FXP_RENAME, &packet),
            Packet::ReadLink(packet) => ser::to_packet_bytes(SSH_FXP_READLINK, &packet),
            Packet::Symlink(packet) => ser::to_packet_bytes(SSH_FXP_SYMLINK, &packet),
            Packet::Status(packet) => ser::to_packet_bytes(SSH_FXP_STATUS, &packet),
            Packet::Handle(packet) => ser::to_packet_bytes(SSH_FXP_HANDLE, &packet),
            Packet::Data(packet) => ser::to_packet_bytes(SSH_FXP_DATA, &packet),
            Packet::Name(packet) => ser::to_packet_bytes(SSH_FXP_NAME, &packet),
            Packet::Attrs(packet) => ser::to_packet_bytes(SSH_FXP_ATTRS, &packet),
            Packet::Extended(packet) => ser::to_packet_bytes(SSH_FXP_EXTENDED, &packet),
            Packet::ExtendedReply(packet) => ser::to_packet_bytes(SSH_FXP_EXTENDED_REPLY, &packet),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use std::collections::HashMap;

    use super::*;

    fn attrs() -> FileAttributes {
        FileAttributes {
            size: Some(1024),
            uid: Some(1000),
            gid: Some(100),
            permissions: Some(0o100644),
            atime: Some(1_700_000_000),
            mtime: Some(1_700_000_001),
            ..Default::default()
        }
    }

    fn one_extension() -> HashMap<String, String> {
        // A single entry keeps the encoding independent of HashMap iteration order.
        HashMap::from([("fsync@openssh.com".to_owned(), "1".to_owned())])
    }

    /// Wire type numbers from draft-ietf-secsh-filexfer-02 and the packets to encode with them.
    fn packets() -> Vec<(u8, Packet)> {
        let h = || "handle".to_owned();
        let p = || "/tmp/file".to_owned();
        vec![
            (
                1,
                Init {
                    version: 3,
                    extensions: one_extension(),
                }
                .into(),
            ),
            (
                2,
                Version {
                    version: 3,
                    extensions: one_extension(),
                }
                .into(),
            ),
            (
                3,
                Open {
                    id: 1,
                    filename: p(),
                    pflags: OpenFlags::READ | OpenFlags::CREATE,
                    attrs: attrs(),
                }
                .into(),
            ),
            (4, Close { id: 2, handle: h() }.into()),
            (
                5,
                Read {
                    id: 3,
                    handle: h(),
                    offset: u64::MAX,
                    len: 32768,
                }
                .into(),
            ),
            (
                6,
                Write {
                    id: 4,
                    handle: h(),
                    offset: 7,
                    data: vec![0, 1, 2, 255],
                }
                .into(),
            ),
            (7, Lstat { id: 5, path: p() }.into()),
            (8, Fstat { id: 6, handle: h() }.into()),
            (
                9,
                SetStat {
                    id: 7,
                    path: p(),
                    attrs: attrs(),
                }
                .into(),
            ),
            (
                10,
                FSetStat {
                    id: 8,
                    handle: h(),
                    attrs: FileAttributes::empty(),
                }
                .into(),
            ),
            (11, OpenDir { id: 9, path: p() }.into()),
            (
                12,
                ReadDir {
                    id: 10,
                    handle: h(),
                }
                .into(),
            ),
            (
                13,
                Remove {
                    id: 11,
                    filename: p(),
                }
                .into(),
            ),
            (
                14,
                MkDir {
                    id: 12,
                    path: p(),
                    attrs: attrs(),
                }
                .into(),
            ),
            (15, RmDir { id: 13, path: p() }.into()),
            (16, RealPath { id: 14, path: p() }.into()),
            (17, Stat { id: 15, path: p() }.into()),
            (
                18,
                Rename {
                    id: 16,
                    oldpath: p(),
                    newpath: "/tmp/new".to_owned(),
                }
                .into(),
            ),
            (19, ReadLink { id: 17, path: p() }.into()),
            (
                20,
                Symlink {
                    id: 18,
                    linkpath: p(),
                    targetpath: "/tmp/target".to_owned(),
                }
                .into(),
            ),
            (
                101,
                Packet::status(19, StatusCode::OpUnsupported, "nope", "en-US"),
            ),
            (
                102,
                Handle {
                    id: 20,
                    handle: h(),
                }
                .into(),
            ),
            (
                103,
                Data {
                    id: 21,
                    data: vec![9; 100],
                }
                .into(),
            ),
            (
                104,
                Name {
                    id: 22,
                    files: vec![File::new("a", attrs()), File::dummy("b")],
                }
                .into(),
            ),
            (
                105,
                Attrs {
                    id: 23,
                    attrs: attrs(),
                }
                .into(),
            ),
            (
                200,
                Extended {
                    id: 24,
                    request: "statvfs@openssh.com".to_owned(),
                    data: vec![1, 2, 3],
                }
                .into(),
            ),
            (
                201,
                ExtendedReply {
                    id: 25,
                    data: vec![4, 5, 6],
                }
                .into(),
            ),
        ]
    }

    #[test]
    fn every_packet_round_trips() {
        for (r#type, packet) in packets() {
            let encoded = Bytes::try_from(packet).unwrap();
            assert_eq!(
                u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize,
                encoded.len() - 4,
                "length prefix of type {type}"
            );
            assert_eq!(encoded[4], r#type);

            let mut payload = encoded.slice(4..);
            let decoded = Packet::try_from(&mut payload).unwrap();
            assert!(!payload.has_remaining(), "type {type} left bytes unread");
            assert_eq!(Bytes::try_from(decoded).unwrap(), encoded, "type {type}");
        }
    }

    #[test]
    fn name_matches_spec_layout() {
        let mut wire = BytesMut::new();
        wire.put_u8(104);
        wire.put_u32(7); // id
        wire.put_u32(1); // count
        wire.put_u32(3);
        wire.put_slice(b"a.c"); // filename
        wire.put_u32(2);
        wire.put_slice(b"ln"); // longname
        wire.put_u32(0x1 | 0x4); // SIZE | PERMISSIONS
        wire.put_u64(42);
        wire.put_u32(0o100600);

        let Packet::Name(name) = Packet::try_from(&mut wire.clone().freeze()).unwrap() else {
            panic!("expected NAME");
        };
        assert_eq!(name.id, 7);
        let [file] = &name.files[..] else {
            panic!("expected one entry");
        };
        assert_eq!(
            (file.filename.as_str(), file.longname.as_str()),
            ("a.c", "ln")
        );
        assert_eq!(file.attrs.size, Some(42));
        assert_eq!(file.attrs.permissions, Some(0o100600));
        assert_eq!((file.attrs.uid, file.attrs.gid), (None, None));
        assert_eq!((file.attrs.atime, file.attrs.mtime), (None, None));

        let encoded = Bytes::try_from(Packet::Name(name)).unwrap();
        assert_eq!(encoded[4..], wire[..]);
    }

    #[test]
    fn rejects_unknown_type_and_truncated_payload() {
        assert!(Packet::try_from(&mut Bytes::from_static(&[99, 0, 0, 0, 1])).is_err());

        let full = Bytes::try_from(Packet::from(Close {
            id: 1,
            handle: "handle".to_owned(),
        }))
        .unwrap();
        for end in 5..full.len() {
            assert!(
                Packet::try_from(&mut full.slice(4..end)).is_err(),
                "accepted {end} bytes"
            );
        }
    }
}
