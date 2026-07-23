//! LSP v3.0 压缩模块
//!
//! 实现帧载荷的透明压缩/解压，减少局域网带宽占用。
//!
//! ## 支持的算法
//!
//! - **LZ4**（默认）：极快的压缩/解压速度，适合实时传输
//! - **Zstd**：更高压缩比，适合大文件
//! - **None**：不压缩（已压缩的文件如 .zip/.jpg 跳过）
//!
//! ## 策略
//!
//! - 小于 256 字节的数据不压缩（开销大于收益）
//! - 已知不可压缩的 MIME 类型跳过（jpg/png/zip/mp4 等）
//! - 压缩后比原始数据大时，回退为不压缩
//! - 压缩级别可配置

use std::collections::HashSet;

/// 压缩算法
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum CompressionAlgo {
    /// 不压缩
    None = 0x00,
    /// LZ4 快速压缩
    Lz4 = 0x01,
    /// Zstd 高压缩比
    Zstd = 0x02,
}

impl CompressionAlgo {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Lz4),
            0x02 => Some(Self::Zstd),
            _ => None,
        }
    }
}

/// 压缩配置
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// 使用的算法
    pub algo: CompressionAlgo,
    /// 压缩级别（1-12，LZ4 用 1，Zstd 用 3-9）
    pub level: u32,
    /// 最小压缩阈值（字节），小于此值不压缩
    pub min_size: usize,
    /// 是否跳过已知不可压缩的类型
    pub skip_incompressible: bool,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algo: CompressionAlgo::Lz4,
            level: 1,
            min_size: 256,
            skip_incompressible: true,
        }
    }
}

impl CompressionConfig {
    /// 高性能配置（LZ4 最快）
    pub fn fast() -> Self {
        Self {
            algo: CompressionAlgo::Lz4,
            level: 1,
            min_size: 512,
            skip_incompressible: true,
        }
    }

    /// 高压缩比配置（Zstd）
    pub fn best() -> Self {
        Self {
            algo: CompressionAlgo::Zstd,
            level: 6,
            min_size: 128,
            skip_incompressible: true,
        }
    }
}

/// 压缩结果
#[derive(Debug)]
pub struct CompressedData {
    /// 压缩后的数据
    pub data: Vec<u8>,
    /// 使用的算法
    pub algo: CompressionAlgo,
    /// 原始大小
    pub original_size: usize,
    /// 是否实际压缩了（false 表示原样返回）
    pub compressed: bool,
}

impl CompressedData {
    /// 压缩比（compressed_size / original_size）
    pub fn ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 1.0;
        }
        self.data.len() as f64 / self.original_size as f64
    }
}

/// 已知不可压缩的文件扩展名
fn incompressible_extensions() -> HashSet<&'static str> {
    [
        // 图片
        "jpg", "jpeg", "png", "gif", "webp", "avif", "heic", "bmp",
        // 视频
        "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v",
        // 音频
        "mp3", "aac", "ogg", "flac", "wav", "wma", "m4a", "opus",
        // 压缩包
        "zip", "rar", "7z", "gz", "bz2", "xz", "zst", "lz4",
        // 其他
        "pdf", "docx", "xlsx", "pptx", "apk", "dmg", "iso",
    ]
    .iter()
    .cloned()
    .collect()
}

/// 检查文件是否可能不可压缩
pub fn is_incompressible(filename: &str) -> bool {
    let ext = filename
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    incompressible_extensions().contains(ext.as_str())
}

/// 压缩器
pub struct Compressor {
    config: CompressionConfig,
}

impl Compressor {
    pub fn new(config: CompressionConfig) -> Self {
        Self { config }
    }

    /// 压缩数据
    ///
    /// 如果数据太小或不可压缩，返回原数据（algo=None）
    pub fn compress(&self, data: &[u8], filename: Option<&str>) -> CompressedData {
        // 检查是否需要跳过
        if data.len() < self.config.min_size {
            return CompressedData {
                data: data.to_vec(),
                algo: CompressionAlgo::None,
                original_size: data.len(),
                compressed: false,
            };
        }

        if self.config.skip_incompressible {
            if let Some(name) = filename {
                if is_incompressible(name) {
                    return CompressedData {
                        data: data.to_vec(),
                        algo: CompressionAlgo::None,
                        original_size: data.len(),
                        compressed: false,
                    };
                }
            }
        }

        match self.config.algo {
            CompressionAlgo::None => CompressedData {
                data: data.to_vec(),
                algo: CompressionAlgo::None,
                original_size: data.len(),
                compressed: false,
            },
            CompressionAlgo::Lz4 => self.compress_lz4(data),
            CompressionAlgo::Zstd => self.compress_zstd(data),
        }
    }

    /// 解压数据
    pub fn decompress(&self, data: &[u8], algo: CompressionAlgo, original_size: usize) -> Result<Vec<u8>, CompressionError> {
        match algo {
            CompressionAlgo::None => Ok(data.to_vec()),
            CompressionAlgo::Lz4 => self.decompress_lz4(data, original_size),
            CompressionAlgo::Zstd => self.decompress_zstd(data, original_size),
        }
    }

    /// LZ4 压缩（使用 lz4_flex 纯 Rust 实现）
    fn compress_lz4(&self, data: &[u8]) -> CompressedData {
        let compressed = lz4_flex::compress_prepend_size(data);

        // 如果压缩后更大，回退
        if compressed.len() >= data.len() {
            return CompressedData {
                data: data.to_vec(),
                algo: CompressionAlgo::None,
                original_size: data.len(),
                compressed: false,
            };
        }

        CompressedData {
            data: compressed,
            algo: CompressionAlgo::Lz4,
            original_size: data.len(),
            compressed: true,
        }
    }

    /// LZ4 解压
    fn decompress_lz4(&self, data: &[u8], _original_size: usize) -> Result<Vec<u8>, CompressionError> {
        lz4_flex::decompress_size_prepended(data)
            .map_err(|e| CompressionError::DecompressFailed(format!("LZ4: {}", e)))
    }

    /// Zstd 压缩
    fn compress_zstd(&self, data: &[u8]) -> CompressedData {
        let level = self.config.level.min(21) as i32;
        match zstd::encode_all(std::io::Cursor::new(data), level) {
            Ok(compressed) => {
                if compressed.len() >= data.len() {
                    return CompressedData {
                        data: data.to_vec(),
                        algo: CompressionAlgo::None,
                        original_size: data.len(),
                        compressed: false,
                    };
                }

                CompressedData {
                    data: compressed,
                    algo: CompressionAlgo::Zstd,
                    original_size: data.len(),
                    compressed: true,
                }
            }
            Err(_) => CompressedData {
                data: data.to_vec(),
                algo: CompressionAlgo::None,
                original_size: data.len(),
                compressed: false,
            },
        }
    }

    /// Zstd 解压
    fn decompress_zstd(&self, data: &[u8], _original_size: usize) -> Result<Vec<u8>, CompressionError> {
        zstd::decode_all(std::io::Cursor::new(data))
            .map_err(|e| CompressionError::DecompressFailed(format!("Zstd: {}", e)))
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new(CompressionConfig::default())
    }
}

/// 压缩错误
#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    #[error("Decompression failed: {0}")]
    DecompressFailed(String),

    #[error("Unknown algorithm: {0}")]
    UnknownAlgo(u8),

    #[error("Size mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: usize, actual: usize },
}

/// 压缩统计
#[derive(Debug, Clone, Default)]
pub struct CompressionStats {
    /// 总压缩次数
    pub compress_count: u64,
    /// 总解压次数
    pub decompress_count: u64,
    /// 压缩前总字节
    pub bytes_before: u64,
    /// 压缩后总字节
    pub bytes_after: u64,
    /// 跳过压缩次数（太小或不可压缩）
    pub skipped: u64,
}

impl CompressionStats {
    /// 总体压缩比
    pub fn overall_ratio(&self) -> f64 {
        if self.bytes_before == 0 {
            return 1.0;
        }
        self.bytes_after as f64 / self.bytes_before as f64
    }

    /// 节省的字节数
    pub fn bytes_saved(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz4_roundtrip() {
        let compressor = Compressor::new(CompressionConfig {
            algo: CompressionAlgo::Lz4,
            ..Default::default()
        });

        let data = b"Hello, World! This is a test of LZ4 compression. ".repeat(100);
        let compressed = compressor.compress(&data, None);

        assert!(compressed.compressed);
        assert_eq!(compressed.algo, CompressionAlgo::Lz4);
        assert!(compressed.data.len() < data.len());

        let decompressed = compressor
            .decompress(&compressed.data, compressed.algo, compressed.original_size)
            .unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_zstd_roundtrip() {
        let compressor = Compressor::new(CompressionConfig {
            algo: CompressionAlgo::Zstd,
            level: 3,
            ..Default::default()
        });

        let data = b"Zstandard compression test data. ".repeat(200);
        let compressed = compressor.compress(&data, None);

        assert!(compressed.compressed);
        assert_eq!(compressed.algo, CompressionAlgo::Zstd);
        assert!(compressed.data.len() < data.len());

        let decompressed = compressor
            .decompress(&compressed.data, compressed.algo, compressed.original_size)
            .unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_small_data_skip() {
        let compressor = Compressor::default();
        let data = b"tiny";
        let result = compressor.compress(data, None);

        assert!(!result.compressed);
        assert_eq!(result.algo, CompressionAlgo::None);
        assert_eq!(result.data, data);
    }

    #[test]
    fn test_incompressible_skip() {
        let compressor = Compressor::default();
        let data = vec![0u8; 10000]; // 足够大
        let result = compressor.compress(&data, Some("photo.jpg"));

        assert!(!result.compressed);
        assert_eq!(result.algo, CompressionAlgo::None);
    }

    #[test]
    fn test_incompressible_detection() {
        assert!(is_incompressible("photo.jpg"));
        assert!(is_incompressible("video.mp4"));
        assert!(is_incompressible("archive.zip"));
        assert!(is_incompressible("song.mp3"));
        assert!(!is_incompressible("document.txt"));
        assert!(!is_incompressible("source.rs"));
        assert!(!is_incompressible("data.json"));
    }

    #[test]
    fn test_random_data_fallback() {
        // 随机数据通常不可压缩，压缩后可能更大
        let compressor = Compressor::new(CompressionConfig {
            algo: CompressionAlgo::Lz4,
            min_size: 0,
            skip_incompressible: false,
            ..Default::default()
        });

        // 使用伪随机数据
        let data: Vec<u8> = (0..10000).map(|i| (i * 7 + 13) as u8).collect();
        let result = compressor.compress(&data, None);

        // 无论是否压缩，解压后应该还原
        let decompressed = compressor
            .decompress(&result.data, result.algo, result.original_size)
            .unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_ratio() {
        let compressor = Compressor::default();
        // 高度可压缩的数据
        let data = vec![0u8; 100000];
        let result = compressor.compress(&data, None);

        assert!(result.compressed);
        assert!(result.ratio() < 0.1); // 压缩到 <10%
    }

    #[test]
    fn test_no_compression_algo() {
        let compressor = Compressor::new(CompressionConfig {
            algo: CompressionAlgo::None,
            ..Default::default()
        });

        let data = b"Some data that won't be compressed".repeat(100);
        let result = compressor.compress(&data, None);

        assert!(!result.compressed);
        assert_eq!(result.algo, CompressionAlgo::None);
    }

    #[test]
    fn test_stats() {
        let mut stats = CompressionStats::default();
        stats.compress_count = 10;
        stats.bytes_before = 100000;
        stats.bytes_after = 30000;

        assert!((stats.overall_ratio() - 0.3).abs() < 0.01);
        assert_eq!(stats.bytes_saved(), 70000);
    }
}
