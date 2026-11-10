//! In-process client/server over `tokio::io::duplex`, no SSH, so per-request client
//! overhead (request map, framing) dominates. Separate from upload_benchmark, which needs a live SSH server.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use russh_sftp::{
    client::SftpSession,
    protocol::{Attrs, FileAttributes, Handle, OpenFlags, Status, StatusCode, Version},
    server::{self, StatusReply},
};
use std::{collections::HashMap, sync::Arc};
use tokio::{io::AsyncWriteExt, runtime::Runtime, task::JoinSet};

const STATS_PER_TASK: usize = 200;
const FILE_COUNT: usize = 8;
const FILE_SIZE: usize = 4 * 1024 * 1024;

struct Sink;

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: String::new(),
    }
}

impl server::Handler for Sink {
    type Error = StatusReply;

    fn unimplemented(&self) -> StatusReply {
        StatusCode::OpUnsupported.into()
    }

    async fn init(&mut self, _: u32, _: HashMap<String, String>) -> Result<Version, StatusReply> {
        Ok(Version::new())
    }

    async fn stat(&mut self, id: u32, _: String) -> Result<Attrs, StatusReply> {
        Ok(Attrs {
            id,
            attrs: FileAttributes::default(),
        })
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
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, _: String) -> Result<Status, StatusReply> {
        Ok(ok(id))
    }
}

fn session(rt: &Runtime) -> Arc<SftpSession> {
    rt.block_on(async {
        let (client, server) = tokio::io::duplex(1 << 20);
        server::run(server, Sink).await;
        Arc::new(SftpSession::new(client).await.unwrap())
    })
}

async fn stat_concurrent(sftp: &Arc<SftpSession>, tasks: usize) {
    let mut set = JoinSet::new();
    for _ in 0..tasks {
        let sftp = Arc::clone(sftp);
        set.spawn(async move {
            for _ in 0..STATS_PER_TASK {
                sftp.metadata("f").await.unwrap();
            }
        });
    }
    while let Some(r) = set.join_next().await {
        r.unwrap();
    }
}

async fn write_concurrent(sftp: &Arc<SftpSession>, data: &Arc<Vec<u8>>) {
    let mut set = JoinSet::new();
    for i in 0..FILE_COUNT {
        let sftp = Arc::clone(sftp);
        let data = Arc::clone(data);
        set.spawn(async move {
            let mut file = sftp.create(format!("f{i}")).await.unwrap();
            file.write_all(&data).await.unwrap();
            file.close().await.unwrap();
        });
    }
    while let Some(r) = set.join_next().await {
        r.unwrap();
    }
}

fn bench(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let sftp = session(&rt);

    let mut group = c.benchmark_group("request_map");
    for tasks in [1, 16, 64] {
        group.throughput(Throughput::Elements((tasks * STATS_PER_TASK) as u64));
        group.bench_with_input(BenchmarkId::new("stat", tasks), &tasks, |b, &tasks| {
            b.to_async(&rt).iter(|| stat_concurrent(&sftp, tasks))
        });
    }

    let data = Arc::new(vec![0u8; FILE_SIZE]);
    group.throughput(Throughput::Bytes((FILE_COUNT * FILE_SIZE) as u64));
    group.bench_function("write_8x4mb", |b| {
        b.to_async(&rt).iter(|| write_concurrent(&sftp, &data))
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
