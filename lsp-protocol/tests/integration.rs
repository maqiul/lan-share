//! LSP v3.0 端到端集成测试

use lsp_protocol::{LspClient, LspServer, ServerConfig};
use lsp_protocol::transport::{UdpConnection, encode_frame, decode_frame};
use lsp_protocol::protocol::*;
use bytes::Bytes;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// 获取一个空闲 UDP 端口（绑定 :0 后释放）
fn get_free_port() -> u16 {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.local_addr().unwrap().port()
}

async fn start_test_server(shared_dir: PathBuf, port: u16) -> tokio::task::JoinHandle<()> {
    let config = ServerConfig {
        device_id: "test-server".to_string(),
        device_name: "Test Server".to_string(),
        shared_dir,
        pin: "123456".to_string(),
        max_streams: 64,
        max_frame_size: 16 * 1024 * 1024,
        use_encryption: true,
        use_compression: true,
    };
    let server = Arc::new(LspServer::new(config));
    let addr = format!("127.0.0.1:{}", port);
    tokio::spawn(async move {
        let _ = server.serve(&addr).await;
    })
}

/// 直接测试 UdpConnection 收发（绕过 LspClient/LspServer）
#[tokio::test]
async fn test_udp_connection_send_recv() {
    let server_socket = UdpSocket::bind("127.0.0.1:19998").await.unwrap();
    let server_socket = Arc::new(server_socket);

    let client_conn = UdpConnection::connect_client("127.0.0.1:19998", false, false)
        .await
        .expect("connect_client failed");

    let frame = Frame::new(FrameType::Keepalive, 0, 0, Bytes::new());
    client_conn.send_frame(frame).await.expect("send_frame failed");

    let mut buf = [0u8; 65535];
    let (len, src) = timeout(Duration::from_secs(3), server_socket.recv_from(&mut buf))
        .await
        .expect("server recv timeout")
        .unwrap();

    let decoded = decode_frame(&buf[..len]).expect("decode_frame failed");
    assert_eq!(decoded.frame_type, FrameType::Keepalive);

    let resp = Frame::new(FrameType::KeepaliveAck, 0, 0, Bytes::new());
    let resp_data = encode_frame(&resp).expect("encode_frame failed");
    server_socket.send_to(&resp_data, src).await.unwrap();

    let recv = timeout(Duration::from_secs(3), client_conn.recv_frame())
        .await
        .expect("client recv timeout")
        .expect("recv_frame error");
    assert_eq!(recv.frame_type, FrameType::KeepaliveAck);
}

/// 最基础的 UDP 通信测试
#[tokio::test]
async fn test_udp_basic_echo() {
    let server = UdpSocket::bind("127.0.0.1:19999").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();

    client.send_to(b"hello", "127.0.0.1:19999").await.unwrap();

    let mut buf = [0u8; 1024];
    let (len, src) = timeout(Duration::from_secs(2), server.recv_from(&mut buf))
        .await
        .expect("server recv timeout")
        .unwrap();
    assert_eq!(&buf[..len], b"hello");
    assert_eq!(src, client_addr);

    server.send_to(b"world", src).await.unwrap();

    let (len, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("client recv timeout")
        .unwrap();
    assert_eq!(&buf[..len], b"world");
}

#[tokio::test]
async fn test_udp_handshake_and_auth() {
    let port = get_free_port();
    let tmp_dir = std::env::temp_dir().join("lsp_test_auth");
    let _ = std::fs::create_dir_all(&tmp_dir);

    let server_handle = start_test_server(tmp_dir.clone(), port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = timeout(Duration::from_secs(10), async {
        let mut client = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-client".to_string(),
            "Test Client".to_string(),
        )
        .await
        .expect("UDP connect failed");

        client.handshake().await.expect("Handshake failed");
        let permission = client.authenticate("123456").await.expect("Auth failed");
        assert_eq!(permission, "read,write,delete,rename,mkdir");
        client.goodbye().await.ok();
    })
    .await;

    server_handle.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = result {
        panic!("Test timed out or failed: {:?}", e);
    }
}

/// 启动注入账号验证器的测试服务端
async fn start_test_server_with_accounts(shared_dir: PathBuf, port: u16) -> tokio::task::JoinHandle<()> {
    let config = ServerConfig {
        device_id: "test-server".to_string(),
        device_name: "Test Server".to_string(),
        shared_dir,
        pin: "123456".to_string(),
        max_streams: 64,
        max_frame_size: 16 * 1024 * 1024,
        use_encryption: true,
        use_compression: true,
    };
    let verifier: lsp_protocol::AccountVerifier = Arc::new(|username, password| {
        match (username, password) {
            ("alice", "secret") => Some("read,write,delete,rename,share,mkdir".to_string()),
            ("bob", "readonly") => Some("read".to_string()),
            // 细粒度测试账号：可写+建目录，但不可删除/重命名
            ("carol", "writeonly") => Some("read,write,mkdir".to_string()),
            _ => None,
        }
    });
    let server = Arc::new(LspServer::new(config).with_account_verifier(verifier));
    let addr = format!("127.0.0.1:{}", port);
    tokio::spawn(async move {
        let _ = server.serve(&addr).await;
    })
}

/// 账号模式认证：正确凭据映射权限，错误密码被拒绝
#[tokio::test]
async fn test_udp_account_auth() {
    let port = get_free_port();
    let tmp_dir = std::env::temp_dir().join("lsp_test_account_auth");
    let _ = std::fs::create_dir_all(&tmp_dir);

    let server_handle = start_test_server_with_accounts(tmp_dir.clone(), port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = timeout(Duration::from_secs(15), async {
        // 正确账号密码 → 全部权限
        let mut client = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-client".to_string(),
            "Test Client".to_string(),
        )
        .await
        .expect("UDP connect failed");
        client.handshake().await.expect("Handshake failed");
        let permission = client
            .authenticate_account("alice", "secret")
            .await
            .expect("Account auth failed");
        assert_eq!(permission, "read,write,delete,rename,share,mkdir");
        client.goodbye().await.ok();

        // 只读账号 → read（验证服务端采用验证器返回的权限）
        let mut client2 = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-client-2".to_string(),
            "Test Client 2".to_string(),
        )
        .await
        .expect("UDP connect failed");
        client2.handshake().await.expect("Handshake failed");
        let permission2 = client2
            .authenticate_account("bob", "readonly")
            .await
            .expect("Account auth (read) failed");
        assert_eq!(permission2, "read");
        client2.goodbye().await.ok();

        // 错误密码 → 认证失败
        let mut client3 = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-client-3".to_string(),
            "Test Client 3".to_string(),
        )
        .await
        .expect("UDP connect failed");
        client3.handshake().await.expect("Handshake failed");
        let bad = client3.authenticate_account("alice", "wrongpass").await;
        assert!(bad.is_err(), "Wrong password should fail");
        client3.goodbye().await.ok();
    })
    .await;

    server_handle.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = result {
        panic!("Test timed out or failed: {:?}", e);
    }
}

/// 前导斜杠路径解析：根路径 "/" 应解析到共享目录而非盘符根，且拒绝目录穿越
#[tokio::test]
async fn test_udp_leading_slash_path() {
    let port = get_free_port();
    let tmp_dir = std::env::temp_dir().join("lsp_test_slash");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    // 在共享目录内放一个标志性文件
    std::fs::write(tmp_dir.join("marker.txt"), b"hello share").unwrap();

    let server_handle = start_test_server(tmp_dir.clone(), port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = timeout(Duration::from_secs(10), async {
        let mut client = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-client".to_string(),
            "Test Client".to_string(),
        )
        .await
        .expect("UDP connect failed");
        client.handshake().await.expect("Handshake failed");
        client.authenticate("123456").await.expect("Auth failed");

        // 根路径 "/" 应列出共享目录内容（含 marker.txt），而非盘符根
        let entries = client.list_files("/", false).await.expect("List root failed");
        assert!(
            entries.iter().any(|e| e.name == "marker.txt"),
            "root listing should contain marker.txt from shared dir, got: {:?}",
            entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>()
        );

        // 带前导斜杠的子路径 stat 应命中共享目录内的文件
        let stat = client.stat_file("/marker.txt").await.expect("Stat /marker.txt failed");
        assert_eq!(stat.size, 11);

        // 目录穿越应被拒绝（返回错误，而非逃逸到上级目录）
        let traversal = client.stat_file("/../lsp_test_slash/marker.txt").await;
        assert!(traversal.is_err(), "path traversal should be rejected");

        client.goodbye().await.ok();
    })
    .await;

    server_handle.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = result {
        panic!("Test timed out or failed: {:?}", e);
    }
}

#[tokio::test]
async fn test_udp_file_upload_download() {
    let port = get_free_port();
    let tmp_dir = std::env::temp_dir().join("lsp_test_transfer");
    let _ = std::fs::create_dir_all(&tmp_dir);

    let server_handle = start_test_server(tmp_dir.clone(), port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = timeout(Duration::from_secs(15), async {
        let mut client = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-client".to_string(),
            "Test Client".to_string(),
        )
        .await
        .expect("UDP connect failed");

        client.handshake().await.expect("Handshake failed");
        client.authenticate("123456").await.expect("Auth failed");

        let test_data = b"Hello, LSP v3.0 over UDP! Integration test file.";
        let local_upload = tmp_dir.join("upload_src.txt");
        std::fs::write(&local_upload, test_data).unwrap();

        let uploaded = client
            .upload_file(local_upload.clone(), "uploaded.txt")
            .await
            .expect("Upload failed");
        assert_eq!(uploaded, test_data.len() as u64);
        assert!(tmp_dir.join("uploaded.txt").exists());

        let local_download = tmp_dir.join("download_dst.txt");
        let downloaded = client
            .download_file("uploaded.txt", local_download.clone(), 0)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, test_data.len() as u64);

        let downloaded_data = std::fs::read(&local_download).unwrap();
        assert_eq!(downloaded_data, test_data);

        client.goodbye().await.ok();
    })
    .await;

    server_handle.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = result {
        panic!("Test timed out or failed: {:?}", e);
    }
}

#[tokio::test]
async fn test_udp_file_operations() {
    let port = get_free_port();
    let tmp_dir = std::env::temp_dir().join("lsp_test_ops");
    let _ = std::fs::create_dir_all(&tmp_dir);

    let server_handle = start_test_server(tmp_dir.clone(), port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = timeout(Duration::from_secs(15), async {
        let mut client = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-client".to_string(),
            "Test Client".to_string(),
        )
        .await
        .expect("UDP connect failed");

        client.handshake().await.expect("Handshake failed");
        client.authenticate("123456").await.expect("Auth failed");

        client.mkdir("test_dir").await.expect("Mkdir failed");
        assert!(tmp_dir.join("test_dir").is_dir());

        let entries = client.list_files(".", false).await.expect("List failed");
        assert!(entries.iter().any(|e| e.name == "test_dir"));

        std::fs::write(tmp_dir.join("test_dir/old.txt"), b"rename me").unwrap();
        client.rename("test_dir/old.txt", "test_dir/new.txt").await.expect("Rename failed");
        assert!(tmp_dir.join("test_dir/new.txt").exists());

        client.delete_file("test_dir/new.txt", false).await.expect("Delete failed");
        assert!(!tmp_dir.join("test_dir/new.txt").exists());

        client.delete_file("test_dir", true).await.expect("Delete dir failed");
        assert!(!tmp_dir.join("test_dir").exists());

        client.goodbye().await.ok();
    })
    .await;

    server_handle.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = result {
        panic!("Test timed out or failed: {:?}", e);
    }
}

/// 大文件传输测试：1MB 文件，~16 个 65KB 分块
#[tokio::test]
async fn test_udp_large_file_transfer() {
    let port = get_free_port();
    let tmp_dir = std::env::temp_dir().join("lsp_test_large");
    let _ = std::fs::create_dir_all(&tmp_dir);

    let server_handle = start_test_server(tmp_dir.clone(), port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = timeout(Duration::from_secs(30), async {
        let mut client = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-client".to_string(),
            "Test Client".to_string(),
        )
        .await
        .expect("UDP connect failed");

        client.handshake().await.expect("Handshake failed");
        client.authenticate("123456").await.expect("Auth failed");

        // 生成 1MB 伪随机数据（可重复）
        let file_size = 1024 * 1024;
        let mut test_data = Vec::with_capacity(file_size);
        let mut seed: u32 = 0xDEADBEEF;
        for _ in 0..file_size {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            test_data.push((seed >> 16) as u8);
        }

        let local_upload = tmp_dir.join("large_upload.bin");
        std::fs::write(&local_upload, &test_data).unwrap();

        // 上传 1MB
        let uploaded = client
            .upload_file(local_upload.clone(), "large_file.bin")
            .await
            .expect("Large upload failed");
        assert_eq!(uploaded, file_size as u64, "Upload size mismatch");

        // 验证服务端文件
        let server_file = tmp_dir.join("large_file.bin");
        assert!(server_file.exists(), "Server file not found");
        let server_data = std::fs::read(&server_file).unwrap();
        assert_eq!(server_data.len(), file_size, "Server file size mismatch");
        assert_eq!(server_data, test_data, "Server file content mismatch");

        // 下载 1MB
        let local_download = tmp_dir.join("large_download.bin");
        let downloaded = client
            .download_file("large_file.bin", local_download.clone(), 0)
            .await
            .expect("Large download failed");
        assert_eq!(downloaded, file_size as u64, "Download size mismatch");

        let downloaded_data = std::fs::read(&local_download).unwrap();
        assert_eq!(downloaded_data.len(), file_size, "Download file size mismatch");
        assert_eq!(downloaded_data, test_data, "Download file content mismatch");

        client.goodbye().await.ok();
    })
    .await;

    server_handle.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = result {
        panic!("Test timed out or failed: {:?}", e);
    }
}

/// 差异传输测试：先上传完整文件，再修改少量内容后 delta 同步
#[tokio::test]
async fn test_udp_delta_transfer() {
    let port = get_free_port();
    let tmp_dir = std::env::temp_dir().join("lsp_test_delta");
    let _ = std::fs::create_dir_all(&tmp_dir);

    let server_handle = start_test_server(tmp_dir.clone(), port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = timeout(Duration::from_secs(30), async {
        let mut client = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-client".to_string(),
            "Test Client".to_string(),
        )
        .await
        .expect("UDP connect failed");

        client.handshake().await.expect("Handshake failed");
        client.authenticate("123456").await.expect("Auth failed");

        // 生成 256KB 原始数据
        let file_size = 256 * 1024;
        let mut original_data = Vec::with_capacity(file_size);
        let mut seed: u32 = 0xCAFEBABE;
        for _ in 0..file_size {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            original_data.push((seed >> 16) as u8);
        }

        // 先完整上传
        let local_original = tmp_dir.join("delta_original.bin");
        std::fs::write(&local_original, &original_data).unwrap();
        client
            .upload_file(local_original.clone(), "delta_file.bin")
            .await
            .expect("Initial upload failed");

        // 修改少量内容（改 2 个 4KB 块 = 8KB / 256KB ≈ 3%）
        let mut modified_data = original_data.clone();
        for i in 0..4096 {
            modified_data[4096 + i] = modified_data[4096 + i].wrapping_add(1);
            modified_data[8192 + i] = modified_data[8192 + i].wrapping_add(2);
        }

        let local_modified = tmp_dir.join("delta_modified.bin");
        std::fs::write(&local_modified, &modified_data).unwrap();

        // Delta 上传
        let delta_size = client
            .delta_upload(local_modified.clone(), "delta_file.bin")
            .await
            .expect("Delta upload failed");

        // delta 应远小于完整文件
        assert!(
            delta_size < file_size as u64 / 2,
            "Delta size {} should be much smaller than file size {}",
            delta_size, file_size
        );

        // 验证服务端文件内容
        let server_file = tmp_dir.join("delta_file.bin");
        let server_data = std::fs::read(&server_file).unwrap();
        assert_eq!(server_data.len(), file_size, "Server file size mismatch");
        assert_eq!(server_data, modified_data, "Server file content mismatch after delta");

        client.goodbye().await.ok();
    })
    .await;

    server_handle.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = result {
        panic!("Test timed out or failed: {:?}", e);
    }
}

/// 只读账号（bob）的写操作应被服务端拒绝，读操作正常
#[tokio::test]
async fn test_udp_readonly_write_denied() {
    let port = get_free_port();
    let tmp_dir = std::env::temp_dir().join("lsp_test_readonly");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    // 预置一个可读文件
    std::fs::write(tmp_dir.join("existing.txt"), b"readonly content").unwrap();

    let server_handle = start_test_server_with_accounts(tmp_dir.clone(), port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = timeout(Duration::from_secs(15), async {
        let mut client = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-readonly".to_string(),
            "Test ReadOnly".to_string(),
        )
        .await
        .expect("UDP connect failed");
        client.handshake().await.expect("Handshake failed");
        let permission = client
            .authenticate_account("bob", "readonly")
            .await
            .expect("Account auth failed");
        assert_eq!(permission, "read");

        // 写操作一律被拒（服务端返回 0x05 错误帧）
        assert!(client.mkdir("hacked_dir").await.is_err(), "mkdir should be denied");
        assert!(client.upload_data(b"hack", "hacked.txt").await.is_err(), "upload_data should be denied");
        assert!(client.delete_file("existing.txt", false).await.is_err(), "delete should be denied");
        assert!(client.rename("existing.txt", "renamed.txt").await.is_err(), "rename should be denied");

        // 服务端文件未被破坏
        assert!(tmp_dir.join("existing.txt").exists(), "existing file must remain");
        assert!(!tmp_dir.join("hacked_dir").exists(), "mkdir must not happen");
        assert!(!tmp_dir.join("hacked.txt").exists(), "upload must not happen");

        // 读操作正常
        let entries = client.list_files("/", false).await.expect("list should work");
        assert!(entries.iter().any(|e| e.name == "existing.txt"));
        let stat = client.stat_file("existing.txt").await.expect("stat should work");
        assert_eq!(stat.size, 16);

        client.goodbye().await.ok();
    })
    .await;

    server_handle.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = result {
        panic!("Test timed out or failed: {:?}", e);
    }
}

/// 内存缓冲上传（upload_data）：读写账号直接由内存写入远端文件
#[tokio::test]
async fn test_udp_upload_data_memory() {
    let port = get_free_port();
    let tmp_dir = std::env::temp_dir().join("lsp_test_upload_data");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();

    let server_handle = start_test_server_with_accounts(tmp_dir.clone(), port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = timeout(Duration::from_secs(15), async {
        let mut client = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-upload-data".to_string(),
            "Test UploadData".to_string(),
        )
        .await
        .expect("UDP connect failed");
        client.handshake().await.expect("Handshake failed");
        let permission = client
            .authenticate_account("alice", "secret")
            .await
            .expect("Account auth failed");
        assert_eq!(permission, "read,write,delete,rename,share,mkdir");

        // 内存数据上传（无需本地落盘）
        let test_data = b"Hello from memory buffer upload!";
        let uploaded = client
            .upload_data(test_data, "memory.txt")
            .await
            .expect("upload_data failed");
        assert_eq!(uploaded, test_data.len() as u64);

        // 验证服务端文件内容
        let server_data = std::fs::read(tmp_dir.join("memory.txt")).unwrap();
        assert_eq!(server_data, test_data);

        // 覆盖写：upload_data 恒为整体替换
        let new_data = b"overwritten";
        client.upload_data(new_data, "memory.txt").await.expect("overwrite failed");
        let server_data = std::fs::read(tmp_dir.join("memory.txt")).unwrap();
        assert_eq!(server_data, new_data);

        client.goodbye().await.ok();
    })
    .await;

    server_handle.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = result {
        panic!("Test timed out or failed: {:?}", e);
    }
}

/// 细粒度权限：carol(read,write,mkdir) 可上传/建目录，但删除/重命名被拒
#[tokio::test]
async fn test_udp_fine_grained_permissions() {
    let port = get_free_port();
    let tmp_dir = std::env::temp_dir().join("lsp_test_fine_grained");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    std::fs::write(tmp_dir.join("target.txt"), b"to be renamed or deleted").unwrap();

    let server_handle = start_test_server_with_accounts(tmp_dir.clone(), port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = timeout(Duration::from_secs(15), async {
        let mut client = LspClient::connect(
            &format!("127.0.0.1:{}", port),
            "test-fine-grained".to_string(),
            "Test FineGrained".to_string(),
        )
        .await
        .expect("UDP connect failed");
        client.handshake().await.expect("Handshake failed");
        let permission = client
            .authenticate_account("carol", "writeonly")
            .await
            .expect("Account auth failed");
        assert_eq!(permission, "read,write,mkdir");

        // write 权限 ✓：上传文件成功
        client
            .upload_data(b"carol was here", "carol.txt")
            .await
            .expect("upload_data should succeed with write perm");
        assert_eq!(std::fs::read(tmp_dir.join("carol.txt")).unwrap(), b"carol was here");

        // mkdir 权限 ✓：建目录成功
        client.mkdir("carol_dir").await.expect("mkdir should succeed with mkdir perm");
        assert!(tmp_dir.join("carol_dir").is_dir());

        // delete 权限 ✗：删除被拒
        let del_err = client.delete_file("target.txt", false).await;
        assert!(del_err.is_err(), "delete should be denied without delete perm");
        assert!(tmp_dir.join("target.txt").exists(), "file must still exist after denied delete");

        // rename 权限 ✗：重命名被拒
        let ren_err = client.rename("target.txt", "renamed.txt").await;
        assert!(ren_err.is_err(), "rename should be denied without rename perm");
        assert!(tmp_dir.join("target.txt").exists(), "file must still exist after denied rename");

        client.goodbye().await.ok();
    })
    .await;

    server_handle.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    if let Err(e) = result {
        panic!("Test timed out or failed: {:?}", e);
    }
}
