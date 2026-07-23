use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::io::{self, Cursor};
use tokio_util::codec::{Decoder, Encoder};

/// 协议魔数 "LSP3"
pub const MAGIC: u32 = 0x4C535033;
pub const PROTOCOL_VERSION: u8 = 3;
pub const BASE_HEADER_SIZE: usize = 20;
pub const EXT_HEADER_SIZE: usize = 6;
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16MB
pub const DEFAULT_CHUNK_SIZE: usize = 65000; // ~64KB，留余量给帧头+加密
pub const INITIAL_WINDOW_SIZE: u32 = 1024 * 1024; // 1MB
pub const MAX_WINDOW_SIZE: u32 = 64 * 1024 * 1024; // 64MB
pub const AEAD_TAG_SIZE: usize = 16;
pub const AEAD_NONCE_SIZE: usize = 12;

/// 帧类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    // 连接管理 (0x01-0x0F)
    Hello = 0x01,
    HelloAck = 0x02,
    AuthInit = 0x03,
    AuthChallenge = 0x04,
    AuthResponse = 0x05,
    AuthOk = 0x06,
    AuthFail = 0x07,
    Capability = 0x08,
    Keepalive = 0x09,
    KeepaliveAck = 0x0A,
    Goodbye = 0x0B,

    // 流管理 (0x10-0x1F)
    StreamOpen = 0x10,
    StreamOpenAck = 0x11,
    StreamClose = 0x12,
    StreamWindowUpdate = 0x13,
    StreamReset = 0x14,

    // 文件操作 (0x20-0x2F)
    FileList = 0x20,
    FileListResp = 0x21,
    FileStat = 0x22,
    FileStatResp = 0x23,
    FileMkdir = 0x24,
    FileRename = 0x25,
    FileDelete = 0x26,
    FileLock = 0x27,
    FileUnlock = 0x28,
    FileWatch = 0x29,
    FileNotify = 0x2A,

    // 数据传输 (0x30-0x3F)
    ReadReq = 0x30,
    ReadData = 0x31,
    WriteReq = 0x32,
    WriteData = 0x33,
    WriteCommit = 0x34,
    WriteRollback = 0x35,

    // 可靠传输 (0x40-0x4F)
    Sack = 0x40,           // 选择性确认
    WindowUpdate = 0x41,   // 窗口更新（流控）
    DeltaSync = 0x42,      // 差异同步请求
    DeltaSyncResp = 0x43,  // 差异同步响应（签名）
    DeltaData = 0x44,      // 差异数据传输

    // 通用 (0xF0-0xFF)
    Ack = 0xF0,
    Nack = 0xF1,
    Error = 0xFE,
    Ping = 0xFF,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::HelloAck),
            0x03 => Some(Self::AuthInit),
            0x04 => Some(Self::AuthChallenge),
            0x05 => Some(Self::AuthResponse),
            0x06 => Some(Self::AuthOk),
            0x07 => Some(Self::AuthFail),
            0x08 => Some(Self::Capability),
            0x09 => Some(Self::Keepalive),
            0x0A => Some(Self::KeepaliveAck),
            0x0B => Some(Self::Goodbye),
            0x10 => Some(Self::StreamOpen),
            0x11 => Some(Self::StreamOpenAck),
            0x12 => Some(Self::StreamClose),
            0x13 => Some(Self::StreamWindowUpdate),
            0x14 => Some(Self::StreamReset),
            0x20 => Some(Self::FileList),
            0x21 => Some(Self::FileListResp),
            0x22 => Some(Self::FileStat),
            0x23 => Some(Self::FileStatResp),
            0x24 => Some(Self::FileMkdir),
            0x25 => Some(Self::FileRename),
            0x26 => Some(Self::FileDelete),
            0x27 => Some(Self::FileLock),
            0x28 => Some(Self::FileUnlock),
            0x29 => Some(Self::FileWatch),
            0x2A => Some(Self::FileNotify),
            0x30 => Some(Self::ReadReq),
            0x31 => Some(Self::ReadData),
            0x32 => Some(Self::WriteReq),
            0x33 => Some(Self::WriteData),
            0x34 => Some(Self::WriteCommit),
            0x35 => Some(Self::WriteRollback),
            0x40 => Some(Self::Sack),
            0x41 => Some(Self::WindowUpdate),
            0x42 => Some(Self::DeltaSync),
            0x43 => Some(Self::DeltaSyncResp),
            0x44 => Some(Self::DeltaData),
            0xF0 => Some(Self::Ack),
            0xF1 => Some(Self::Nack),
            0xFE => Some(Self::Error),
            0xFF => Some(Self::Ping),
            _ => None,
        }
    }
}

/// 标志位
#[derive(Debug, Clone, Copy, Default)]
pub struct Flags(pub u16);

impl Flags {
    pub const ENCRYPTED: u16 = 0x0001;
    pub const COMPRESSED: u16 = 0x0002;
    pub const FIN: u16 = 0x0004;
    pub const RST: u16 = 0x0008;
    pub const ACK_FRAME: u16 = 0x0010;
    pub const HAS_EXT: u16 = 0x0020;
    pub const PRIORITY: u16 = 0x0040;
    pub const RELIABLE: u16 = 0x0080;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with(mut self, flag: u16) -> Self {
        self.0 |= flag;
        self
    }

    pub fn has(&self, flag: u16) -> bool {
        self.0 & flag != 0
    }
}

/// 扩展帧头
#[derive(Debug, Clone)]
pub struct ExtensionHeader {
    pub ext_type: u16,
    pub ext_length: u32,
    pub ext_data: Bytes,
}

/// 协议帧
#[derive(Debug, Clone)]
pub struct Frame {
    pub version: u8,
    pub frame_type: FrameType,
    pub flags: Flags,
    pub stream_id: u32,
    pub seq_num: u32,
    pub extension: Option<ExtensionHeader>,
    pub payload: Bytes,
    /// 加密 nonce（ENCRYPTED 标志时存在）
    pub nonce: Option<[u8; AEAD_NONCE_SIZE]>,
    /// AEAD 认证标签（ENCRYPTED 标志时存在）
    pub tag: Option<[u8; AEAD_TAG_SIZE]>,
    /// 压缩算法（COMPRESSED 标志时存在）
    pub compression_algo: Option<u8>,
    /// 原始载荷大小（压缩前）
    pub original_size: Option<u32>,
}

impl Frame {
    pub fn new(frame_type: FrameType, stream_id: u32, seq_num: u32, payload: Bytes) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            frame_type,
            flags: Flags::new(),
            stream_id,
            seq_num,
            extension: None,
            payload,
            nonce: None,
            tag: None,
            compression_algo: None,
            original_size: None,
        }
    }

    pub fn with_flags(mut self, flags: Flags) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_extension(mut self, ext: ExtensionHeader) -> Self {
        self.flags = self.flags.with(Flags::HAS_EXT);
        self.extension = Some(ext);
        self
    }

    /// 设置加密信息
    pub fn with_encryption(mut self, nonce: [u8; AEAD_NONCE_SIZE], tag: [u8; AEAD_TAG_SIZE]) -> Self {
        self.flags = self.flags.with(Flags::ENCRYPTED);
        self.nonce = Some(nonce);
        self.tag = Some(tag);
        self
    }

    /// 设置压缩信息
    pub fn with_compression(mut self, algo: u8, original_size: u32) -> Self {
        self.flags = self.flags.with(Flags::COMPRESSED);
        self.compression_algo = Some(algo);
        self.original_size = Some(original_size);
        self
    }

    /// 计算帧总长度
    pub fn frame_length(&self) -> usize {
        let mut len = BASE_HEADER_SIZE;
        if self.flags.has(Flags::HAS_EXT) {
            len += EXT_HEADER_SIZE;
            if let Some(ref ext) = self.extension {
                len += ext.ext_data.len();
            }
        }
        if self.flags.has(Flags::ENCRYPTED) {
            len += AEAD_NONCE_SIZE + AEAD_TAG_SIZE;
        }
        if self.flags.has(Flags::COMPRESSED) {
            len += 5; // 1 byte algo + 4 bytes original_size
        }
        len += self.payload.len();
        len
    }
}

/// 协议编解码器
///
/// 处理帧的序列化/反序列化。加密和压缩在传输层处理：
/// - ENCRYPTED 标志：载荷格式为 nonce(12B) + ciphertext + tag(16B)
/// - COMPRESSED 标志：载荷已压缩，算法由扩展头 ext_type 指示
pub struct LspCodec {
    max_frame_size: usize,
}

impl LspCodec {
    pub fn new() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE,
        }
    }

    pub fn with_max_frame_size(max_size: usize) -> Self {
        Self {
            max_frame_size: max_size,
        }
    }
}

impl Default for LspCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for LspCodec {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        if src.len() < BASE_HEADER_SIZE {
            return Ok(None);
        }

        // 解析基础帧头
        let mut cursor = Cursor::new(&src[..BASE_HEADER_SIZE]);
        let magic = cursor.get_u32();
        if magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid magic: 0x{:08X}, expected 0x{:08X}", magic, MAGIC),
            ));
        }

        let version = cursor.get_u8();
        let frame_type_raw = cursor.get_u8();
        let flags_raw = cursor.get_u16();
        let frame_length = cursor.get_u32() as usize;
        let stream_id = cursor.get_u32();
        let seq_num = cursor.get_u32();

        let frame_type = FrameType::from_u8(frame_type_raw).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown frame type: 0x{:02X}", frame_type_raw),
            )
        })?;

        if frame_length > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Frame too large: {} bytes", frame_length),
            ));
        }

        if src.len() < frame_length {
            src.reserve(frame_length - src.len());
            return Ok(None);
        }

        // 消费帧头
        src.advance(BASE_HEADER_SIZE);

        let flags = Flags(flags_raw);
        let mut offset = 0;
        let mut extension = None;

        // 解析扩展帧头
        if flags.has(Flags::HAS_EXT) {
            if src.len() < EXT_HEADER_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Incomplete extension header",
                ));
            }

            let ext_type = u16::from_be_bytes([src[0], src[1]]);
            let ext_length = u32::from_be_bytes([src[2], src[3], src[4], src[5]]) as usize;
            src.advance(EXT_HEADER_SIZE);
            offset += EXT_HEADER_SIZE;

            if src.len() < ext_length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Incomplete extension data",
                ));
            }

            let ext_data = src.split_to(ext_length).freeze();
            offset += ext_length;

            extension = Some(ExtensionHeader {
                ext_type,
                ext_length: ext_length as u32,
                ext_data,
            });
        }

        // 处理加密
        let mut nonce = None;
        let mut tag = None;
        if flags.has(Flags::ENCRYPTED) {
            if src.len() < AEAD_NONCE_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Incomplete nonce",
                ));
            }
            let mut nonce_bytes = [0u8; AEAD_NONCE_SIZE];
            nonce_bytes.copy_from_slice(&src[..AEAD_NONCE_SIZE]);
            nonce = Some(nonce_bytes);
            src.advance(AEAD_NONCE_SIZE);
            offset += AEAD_NONCE_SIZE;
        }

        // 处理压缩元数据
        let mut compression_algo = None;
        let mut original_size = None;
        if flags.has(Flags::COMPRESSED) {
            if src.len() < 5 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Incomplete compression header",
                ));
            }
            compression_algo = Some(src[0]);
            original_size = Some(u32::from_be_bytes([src[1], src[2], src[3], src[4]]));
            src.advance(5);
            offset += 5;
        }

        // 计算载荷长度
        let payload_length = frame_length - BASE_HEADER_SIZE - offset;
        let actual_payload_length = if flags.has(Flags::ENCRYPTED) {
            payload_length - AEAD_TAG_SIZE
        } else {
            payload_length
        };

        if src.len() < payload_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incomplete payload",
            ));
        }

        let payload = src.split_to(actual_payload_length).freeze();

        // 读取 AEAD tag
        if flags.has(Flags::ENCRYPTED) {
            if src.len() < AEAD_TAG_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Incomplete AEAD tag",
                ));
            }
            let mut tag_bytes = [0u8; AEAD_TAG_SIZE];
            tag_bytes.copy_from_slice(&src[..AEAD_TAG_SIZE]);
            tag = Some(tag_bytes);
            src.advance(AEAD_TAG_SIZE);
        }

        Ok(Some(Frame {
            version,
            frame_type,
            flags,
            stream_id,
            seq_num,
            extension,
            payload,
            nonce,
            tag,
            compression_algo,
            original_size,
        }))
    }
}

impl Encoder<Frame> for LspCodec {
    type Error = io::Error;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> io::Result<()> {
        let frame_length = frame.frame_length();
        if frame_length > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Frame too large: {} bytes", frame_length),
            ));
        }

        dst.reserve(frame_length);

        // 写入基础帧头
        dst.put_u32(MAGIC);
        dst.put_u8(frame.version);
        dst.put_u8(frame.frame_type as u8);
        dst.put_u16(frame.flags.0);
        dst.put_u32(frame_length as u32);
        dst.put_u32(frame.stream_id);
        dst.put_u32(frame.seq_num);

        // 写入扩展帧头
        if frame.flags.has(Flags::HAS_EXT) {
            if let Some(ref ext) = frame.extension {
                dst.put_u16(ext.ext_type);
                dst.put_u32(ext.ext_length);
                dst.extend_from_slice(&ext.ext_data);
            }
        }

        // 写入加密 nonce
        if frame.flags.has(Flags::ENCRYPTED) {
            if let Some(ref nonce) = frame.nonce {
                dst.extend_from_slice(nonce);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ENCRYPTED flag set but no nonce",
                ));
            }
        }

        // 写入压缩元数据
        if frame.flags.has(Flags::COMPRESSED) {
            let algo = frame.compression_algo.unwrap_or(0);
            let orig_size = frame.original_size.unwrap_or(0);
            dst.put_u8(algo);
            dst.put_u32(orig_size);
        }

        // 写入载荷
        dst.extend_from_slice(&frame.payload);

        // 写入 AEAD tag
        if frame.flags.has(Flags::ENCRYPTED) {
            if let Some(ref tag) = frame.tag {
                dst.extend_from_slice(tag);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ENCRYPTED flag set but no tag",
                ));
            }
        }

        Ok(())
    }
}

// ===== 消息载荷定义 =====

#[derive(Debug, Serialize, Deserialize)]
pub struct HelloPayload {
    pub version: u8,
    pub capabilities: Vec<String>,
    pub device_info: DeviceInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub os: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HelloAckPayload {
    pub version: u8,
    pub capabilities: Vec<String>,
    pub max_streams: u32,
    pub max_frame_size: u32,
    pub session_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthInitPayload {
    pub client_pubkey: String, // hex encoded X25519 public key
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthChallengePayload {
    pub server_pubkey: String,
    pub nonce: String,
    pub encrypted_challenge: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponsePayload {
    pub pin_proof: String,
    pub device_name: String,
    pub session_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthOkPayload {
    pub permission: String,
    pub server_proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthFailPayload {
    pub reason: String,
    pub error_code: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StreamOpenPayload {
    pub stream_type: String, // "file_list", "download", "upload", "watch"
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StreamWindowUpdatePayload {
    pub stream_id: u32,
    pub increment: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub created: i64,
    pub modified: i64,
    pub accessed: i64,
    pub is_dir: bool,
    pub readonly: bool,
    pub hidden: bool,
    pub sha256: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileListPayload {
    pub path: String,
    pub recursive: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileListRespPayload {
    pub path: String,
    pub entries: Vec<FileEntry>,
    pub total: u32,
    pub has_more: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileStatPayload {
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileStatRespPayload {
    pub entry: FileEntry,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileMkdirPayload {
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileRenamePayload {
    pub old_path: String,
    pub new_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileDeletePayload {
    pub path: String,
    pub recursive: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileLockPayload {
    pub path: String,
    pub mode: String, // "exclusive", "shared"
    pub ttl: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileWatchPayload {
    pub path: String,
    pub events: Vec<String>, // "create", "modify", "delete", "rename"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileNotifyPayload {
    pub event: String,
    pub path: String,
    pub old_path: Option<String>,
    pub entry: Option<FileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadReqPayload {
    pub path: String,
    pub offset: u64,
    pub length: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadDataPayload {
    pub path: String,
    pub offset: u64,
    pub data: Vec<u8>,
    pub is_last: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteReqPayload {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub overwrite: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteDataPayload {
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteCommitPayload {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AckPayload {
    pub stream_id: u32,
    pub seq_num: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NackPayload {
    pub stream_id: u32,
    pub seq_num: u32,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: u8,
    pub message: String,
    pub stream_id: Option<u32>,
}

// ===== v3.0 新增载荷 =====

/// SACK 载荷（选择性确认）
#[derive(Debug, Serialize, Deserialize)]
pub struct SackPayload {
    /// 累计确认点
    pub ack_seq: u32,
    /// SACK 块列表
    pub blocks: Vec<SackBlockPayload>,
}

/// SACK 块
#[derive(Debug, Serialize, Deserialize)]
pub struct SackBlockPayload {
    pub left: u32,
    pub right: u32,
}

/// 窗口更新载荷
#[derive(Debug, Serialize, Deserialize)]
pub struct WindowUpdatePayload {
    pub stream_id: u32,
    /// 新的接收窗口大小（字节）
    pub window_size: u32,
}

/// 差异同步请求
#[derive(Debug, Serialize, Deserialize)]
pub struct DeltaSyncPayload {
    pub path: String,
    /// 块大小
    pub block_size: usize,
}

/// 差异同步响应（文件签名）
#[derive(Debug, Serialize, Deserialize)]
pub struct DeltaSyncRespPayload {
    pub path: String,
    pub block_size: usize,
    pub file_size: u64,
    /// 各块校验和（弱校验 + 强校验）
    pub blocks: Vec<DeltaBlockChecksum>,
    /// 文件是否存在（不存在则全量传输）
    pub exists: bool,
}

/// 差异块校验和
#[derive(Debug, Serialize, Deserialize)]
pub struct DeltaBlockChecksum {
    pub index: u32,
    pub weak: u32,
    pub strong: String, // hex encoded
}

/// 差异数据载荷
#[derive(Debug, Serialize, Deserialize)]
pub struct DeltaDataPayload {
    pub path: String,
    /// 差异指令（JSON 序列化的 DeltaInstruction 列表）
    pub instructions: Vec<DeltaInstructionPayload>,
    /// 原始文件大小
    pub source_size: u64,
    /// 差异大小
    pub delta_size: u64,
}

/// 差异指令载荷
#[derive(Debug, Serialize, Deserialize)]
pub enum DeltaInstructionPayload {
    Copy { block_index: u32 },
    Literal { data: Vec<u8> },
}

// ===== 数据帧二进制编解码 =====
// 控制帧用 JSON，数据帧（WriteData / ReadData）用紧凑二进制避免 JSON 膨胀

/// WriteData 二进制格式: offset(8B BE) + raw_data
pub fn encode_write_data(offset: u64, data: &[u8]) -> Bytes {
    let mut buf = Vec::with_capacity(8 + data.len());
    buf.extend_from_slice(&offset.to_be_bytes());
    buf.extend_from_slice(data);
    Bytes::from(buf)
}

pub fn decode_write_data(payload: &[u8]) -> io::Result<(u64, &[u8])> {
    if payload.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "WriteData payload too short"));
    }
    let offset = u64::from_be_bytes(payload[..8].try_into().unwrap());
    Ok((offset, &payload[8..]))
}

/// ReadData 二进制格式: offset(8B BE) + is_last(1B) + raw_data
pub fn encode_read_data(offset: u64, is_last: bool, data: &[u8]) -> Bytes {
    let mut buf = Vec::with_capacity(9 + data.len());
    buf.extend_from_slice(&offset.to_be_bytes());
    buf.push(if is_last { 1 } else { 0 });
    buf.extend_from_slice(data);
    Bytes::from(buf)
}

pub fn decode_read_data(payload: &[u8]) -> io::Result<(u64, bool, &[u8])> {
    if payload.len() < 9 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ReadData payload too short"));
    }
    let offset = u64::from_be_bytes(payload[..8].try_into().unwrap());
    let is_last = payload[8] != 0;
    Ok((offset, is_last, &payload[9..]))
}

/// DeltaData 二进制格式:
///   path_len(2B BE) + path_bytes
///   source_size(8B BE) + delta_size(8B BE)
///   num_instructions(4B BE)
///   每条指令: type(1B: 0=Copy,1=Literal)
///     Copy:    block_index(4B BE)
///     Literal: data_len(4B BE) + raw_data
pub fn encode_delta_data(
    path: &str,
    source_size: u64,
    delta_size: u64,
    instructions: &[DeltaInstructionPayload],
) -> Bytes {
    let path_bytes = path.as_bytes();
    let mut buf = Vec::with_capacity(2 + path_bytes.len() + 8 + 8 + 4 + instructions.len() * 8);
    buf.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(path_bytes);
    buf.extend_from_slice(&source_size.to_be_bytes());
    buf.extend_from_slice(&delta_size.to_be_bytes());
    buf.extend_from_slice(&(instructions.len() as u32).to_be_bytes());
    for inst in instructions {
        match inst {
            DeltaInstructionPayload::Copy { block_index } => {
                buf.push(0u8);
                buf.extend_from_slice(&block_index.to_be_bytes());
            }
            DeltaInstructionPayload::Literal { data } => {
                buf.push(1u8);
                buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
                buf.extend_from_slice(data);
            }
        }
    }
    Bytes::from(buf)
}

pub fn decode_delta_data(payload: &[u8]) -> io::Result<(String, u64, u64, Vec<DeltaInstructionPayload>)> {
    let mut pos = 0;
    if payload.len() < 2 { return Err(io::Error::new(io::ErrorKind::InvalidData, "DeltaData too short")); }
    let path_len = u16::from_be_bytes(payload[pos..pos+2].try_into().unwrap()) as usize;
    pos += 2;
    if payload.len() < pos + path_len + 20 { return Err(io::Error::new(io::ErrorKind::InvalidData, "DeltaData too short")); }
    let path = String::from_utf8_lossy(&payload[pos..pos+path_len]).to_string();
    pos += path_len;
    let source_size = u64::from_be_bytes(payload[pos..pos+8].try_into().unwrap());
    pos += 8;
    let delta_size = u64::from_be_bytes(payload[pos..pos+8].try_into().unwrap());
    pos += 8;
    let num_inst = u32::from_be_bytes(payload[pos..pos+4].try_into().unwrap()) as usize;
    pos += 4;
    let mut instructions = Vec::with_capacity(num_inst);
    for _ in 0..num_inst {
        if pos >= payload.len() { return Err(io::Error::new(io::ErrorKind::InvalidData, "DeltaData truncated")); }
        let inst_type = payload[pos]; pos += 1;
        match inst_type {
            0 => {
                if pos + 4 > payload.len() { return Err(io::Error::new(io::ErrorKind::InvalidData, "DeltaData truncated")); }
                let block_index = u32::from_be_bytes(payload[pos..pos+4].try_into().unwrap());
                pos += 4;
                instructions.push(DeltaInstructionPayload::Copy { block_index });
            }
            1 => {
                if pos + 4 > payload.len() { return Err(io::Error::new(io::ErrorKind::InvalidData, "DeltaData truncated")); }
                let data_len = u32::from_be_bytes(payload[pos..pos+4].try_into().unwrap()) as usize;
                pos += 4;
                if pos + data_len > payload.len() { return Err(io::Error::new(io::ErrorKind::InvalidData, "DeltaData truncated")); }
                let data = payload[pos..pos+data_len].to_vec();
                pos += data_len;
                instructions.push(DeltaInstructionPayload::Literal { data });
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown delta instruction type")),
        }
    }
    Ok((path, source_size, delta_size, instructions))
}
