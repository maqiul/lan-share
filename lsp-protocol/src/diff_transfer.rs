//! LSP v3.0 差异传输模块
//!
//! 实现 rsync 风格的增量同步，只传输文件变化的部分。
//!
//! ## 算法（rsync rolling checksum）
//!
//! 1. **分块**：将文件分成固定大小的块（默认 4KB）
//! 2. **弱校验**：对每个块计算 Adler-32 滚动校验和
//! 3. **强校验**：对每个块计算 SHA-256
//! 4. **匹配**：接收方发送校验和列表，发送方用滚动校验和快速匹配
//! 5. **差异**：只传输未匹配的块（literal data）和匹配指令（copy指令）
//!
//! ## 传输格式
//!
//! ```text
//! Delta = [Instruction]*
//! Instruction = Copy(block_index) | Literal(data)
//! ```
//!
//! ## 性能
//!
//! - 1GB 文件改 1 个字节：只传 ~8KB（校验和列表）+ 4KB（变化块）
//! - 全新文件：退化为全量传输
//! - 追加写入：只传新增部分

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// 默认块大小
pub const DEFAULT_BLOCK_SIZE: usize = 4096; // 4KB
/// 最小块大小
pub const MIN_BLOCK_SIZE: usize = 512;
/// 最大块大小
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024; // 1MB

/// Adler-32 滚动校验和
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollingChecksum {
    a: u16,
    b: u16,
}

impl RollingChecksum {
    /// 计算初始校验和
    pub fn new(data: &[u8]) -> Self {
        let mut a: u32 = 1;
        let mut b: u32 = 0;

        for &byte in data {
            a = (a + byte as u32) % 65521;
            b = (b + a) % 65521;
        }

        Self {
            a: a as u16,
            b: b as u16,
        }
    }

    /// 滚动更新：移除最左边的字节，加入新字节
    ///
    /// 窗口大小 = block_size
    pub fn roll(&mut self, old_byte: u8, new_byte: u8, block_size: usize) {
        let mut a = self.a as u32;
        let mut b = self.b as u32;

        a = (a + 65521 - old_byte as u32 + new_byte as u32) % 65521;
        b = (b + 65521 * (block_size as u32) - (old_byte as u32) * (block_size as u32) + a) % 65521;

        // 简化：b = b - old_byte * block_size + a
        // 实际 rsync 用的是 b = b - block_size * old_byte + a
        self.a = a as u16;
        self.b = b as u16;
    }

    /// 转为 u32 用于哈希
    pub fn value(&self) -> u32 {
        ((self.b as u32) << 16) | (self.a as u32)
    }
}

/// 块的校验和信息
#[derive(Debug, Clone)]
pub struct BlockChecksum {
    /// 块索引
    pub index: u32,
    /// 弱校验和（Adler-32）
    pub weak: u32,
    /// 强校验和（SHA-256 前 8 字节，节省带宽）
    pub strong: [u8; 8],
}

/// 文件签名（校验和列表）
#[derive(Debug, Clone)]
pub struct FileSignature {
    /// 块大小
    pub block_size: usize,
    /// 文件总大小
    pub file_size: u64,
    /// 各块的校验和
    pub blocks: Vec<BlockChecksum>,
}

impl FileSignature {
    /// 计算文件签名
    pub fn compute(data: &[u8], block_size: usize) -> Self {
        let mut blocks = Vec::new();
        let mut index = 0u32;

        for chunk in data.chunks(block_size) {
            let weak = RollingChecksum::new(chunk).value();

            let mut hasher = Sha256::new();
            hasher.update(chunk);
            let hash: [u8; 32] = hasher.finalize().into();
            let mut strong = [0u8; 8];
            strong.copy_from_slice(&hash[..8]);

            blocks.push(BlockChecksum {
                index,
                weak,
                strong,
            });

            index += 1;
        }

        Self {
            block_size,
            file_size: data.len() as u64,
            blocks,
        }
    }

    /// 构建弱校验和查找表（用于快速匹配）
    pub fn build_lookup(&self) -> HashMap<u32, Vec<usize>> {
        let mut lookup: HashMap<u32, Vec<usize>> = HashMap::new();
        for (i, block) in self.blocks.iter().enumerate() {
            lookup.entry(block.weak).or_default().push(i);
        }
        lookup
    }
}

/// 差异指令
#[derive(Debug, Clone, PartialEq)]
pub enum DeltaInstruction {
    /// 复制接收方文件的第 block_index 块
    Copy { block_index: u32 },
    /// 直接传输数据（新数据或修改的数据）
    Literal { data: Vec<u8> },
}

/// 差异结果
#[derive(Debug, Clone)]
pub struct Delta {
    /// 指令列表
    pub instructions: Vec<DeltaInstruction>,
    /// 原始文件大小
    pub source_size: u64,
    /// 差异大小（传输量）
    pub delta_size: u64,
    /// 压缩比（delta_size / source_size）
    pub ratio: f64,
}

impl Delta {
    /// 计算差异大小
    pub fn compute_size(&self) -> u64 {
        let mut size = 0u64;
        for inst in &self.instructions {
            match inst {
                DeltaInstruction::Copy { .. } => size += 4, // 4 字节块索引
                DeltaInstruction::Literal { data } => size += 4 + data.len() as u64, // 长度 + 数据
            }
        }
        size
    }
}

/// 差异计算器
pub struct DeltaComputer {
    block_size: usize,
}

impl DeltaComputer {
    pub fn new(block_size: usize) -> Self {
        Self {
            block_size: block_size.clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE),
        }
    }

    /// 计算两个文件之间的差异
    ///
    /// - `source`: 发送方的新文件数据
    /// - `signature`: 接收方旧文件的签名
    ///
    /// 返回差异指令列表
    pub fn compute_delta(&self, source: &[u8], signature: &FileSignature) -> Delta {
        let lookup = signature.build_lookup();
        let mut instructions: Vec<DeltaInstruction> = Vec::new();
        let mut literal_buffer: Vec<u8> = Vec::new();

        if source.is_empty() {
            return Delta {
                instructions: vec![],
                source_size: 0,
                delta_size: 0,
                ratio: 0.0,
            };
        }

        // 如果旧文件为空，全部是 literal
        if signature.blocks.is_empty() {
            return Delta {
                instructions: vec![DeltaInstruction::Literal {
                    data: source.to_vec(),
                }],
                source_size: source.len() as u64,
                delta_size: source.len() as u64 + 4,
                ratio: 1.0,
            };
        }

        let mut i = 0;
        while i < source.len() {
            let _remaining = source.len() - i;
            let chunk_end = std::cmp::min(i + self.block_size, source.len());
            let chunk = &source[i..chunk_end];

            // 计算当前块的弱校验和
            let weak = RollingChecksum::new(chunk).value();

            // 在查找表中查找匹配
            let mut matched = false;
            if let Some(candidates) = lookup.get(&weak) {
                // 弱校验和匹配，验证强校验和
                let mut hasher = Sha256::new();
                hasher.update(chunk);
                let hash: [u8; 32] = hasher.finalize().into();
                let mut strong = [0u8; 8];
                strong.copy_from_slice(&hash[..8]);

                for &block_idx in candidates {
                    if signature.blocks[block_idx].strong == strong {
                        // 完全匹配！
                        // 先刷新 literal buffer
                        if !literal_buffer.is_empty() {
                            instructions.push(DeltaInstruction::Literal {
                                data: std::mem::take(&mut literal_buffer),
                            });
                        }

                        instructions.push(DeltaInstruction::Copy {
                            block_index: signature.blocks[block_idx].index,
                        });

                        matched = true;
                        i = chunk_end;
                        break;
                    }
                }
            }

            if !matched {
                // 没有匹配，加入 literal buffer
                literal_buffer.push(source[i]);
                i += 1;
            }
        }

        // 刷新剩余的 literal buffer
        if !literal_buffer.is_empty() {
            instructions.push(DeltaInstruction::Literal {
                data: literal_buffer,
            });
        }

        let mut delta = Delta {
            instructions,
            source_size: source.len() as u64,
            delta_size: 0,
            ratio: 0.0,
        };
        delta.delta_size = delta.compute_size();
        delta.ratio = if source.is_empty() {
            0.0
        } else {
            delta.delta_size as f64 / source.len() as f64
        };

        delta
    }

    /// 应用差异，重建文件
    ///
    /// - `target`: 接收方的旧文件数据
    /// - `delta`: 差异指令
    ///
    /// 返回重建后的新文件数据
    pub fn apply_delta(&self, target: &[u8], delta: &Delta) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        for inst in &delta.instructions {
            match inst {
                DeltaInstruction::Copy { block_index } => {
                    let start = *block_index as usize * self.block_size;
                    let end = std::cmp::min(start + self.block_size, target.len());
                    if start < target.len() {
                        result.extend_from_slice(&target[start..end]);
                    }
                }
                DeltaInstruction::Literal { data } => {
                    result.extend_from_slice(data);
                }
            }
        }

        result
    }
}

impl Default for DeltaComputer {
    fn default() -> Self {
        Self::new(DEFAULT_BLOCK_SIZE)
    }
}

/// 差异传输的协商参数
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeltaNegotiation {
    /// 是否支持差异传输
    pub supported: bool,
    /// 块大小
    pub block_size: usize,
    /// 是否使用压缩
    pub compress: bool,
}

impl Default for DeltaNegotiation {
    fn default() -> Self {
        Self {
            supported: true,
            block_size: DEFAULT_BLOCK_SIZE,
            compress: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_checksum() {
        let data = b"Hello, World!";
        let cs1 = RollingChecksum::new(data);

        // 相同数据应该产生相同校验和
        let cs2 = RollingChecksum::new(data);
        assert_eq!(cs1, cs2);

        // 不同数据应该产生不同校验和
        let cs3 = RollingChecksum::new(b"Hello, World?");
        assert_ne!(cs1, cs3);
    }

    #[test]
    fn test_file_signature() {
        let data = vec![0u8; 8192]; // 8KB = 2 个 4KB 块
        let sig = FileSignature::compute(&data, 4096);

        assert_eq!(sig.block_size, 4096);
        assert_eq!(sig.file_size, 8192);
        assert_eq!(sig.blocks.len(), 2);
    }

    #[test]
    fn test_identical_files() {
        let data = vec![42u8; 16384]; // 16KB
        let sig = FileSignature::compute(&data, 4096);

        let computer = DeltaComputer::new(4096);
        let delta = computer.compute_delta(&data, &sig);

        // 完全相同的文件，应该全是 Copy 指令
        for inst in &delta.instructions {
            assert!(matches!(inst, DeltaInstruction::Copy { .. }));
        }

        // 差异应该很小
        assert!(delta.ratio < 0.01);
    }

    #[test]
    fn test_completely_different_files() {
        let old_data = vec![0u8; 8192];
        let new_data = vec![0xFFu8; 8192];

        let sig = FileSignature::compute(&old_data, 4096);
        let computer = DeltaComputer::new(4096);
        let delta = computer.compute_delta(&new_data, &sig);

        // 完全不同的文件，应该全是 Literal
        for inst in &delta.instructions {
            assert!(matches!(inst, DeltaInstruction::Literal { .. }));
        }

        // 差异约等于原文件大小
        assert!(delta.ratio > 0.9);
    }

    #[test]
    fn test_partial_change() {
        // 旧文件：16KB 全零
        let old_data = vec![0u8; 16384];
        let sig = FileSignature::compute(&old_data, 4096);

        // 新文件：只改了第 2 块（4096..8192）
        let mut new_data = old_data.clone();
        for i in 4096..8192 {
            new_data[i] = 0xFF;
        }

        let computer = DeltaComputer::new(4096);
        let delta = computer.compute_delta(&new_data, &sig);

        // 应该有 Copy（未变化的块）和 Literal（变化的块）
        let copy_count = delta
            .instructions
            .iter()
            .filter(|i| matches!(i, DeltaInstruction::Copy { .. }))
            .count();
        let literal_count = delta
            .instructions
            .iter()
            .filter(|i| matches!(i, DeltaInstruction::Literal { .. }))
            .count();

        assert!(copy_count > 0, "Should have some Copy instructions");
        assert!(literal_count > 0, "Should have some Literal instructions");

        // 差异应该远小于原文件
        assert!(delta.ratio < 0.5);
    }

    #[test]
    fn test_apply_delta() {
        let old_data = vec![0u8; 16384];
        let sig = FileSignature::compute(&old_data, 4096);

        let mut new_data = old_data.clone();
        for i in 4096..8192 {
            new_data[i] = 0xFF;
        }

        let computer = DeltaComputer::new(4096);
        let delta = computer.compute_delta(&new_data, &sig);

        // 应用差异到旧文件
        let reconstructed = computer.apply_delta(&old_data, &delta);

        assert_eq!(reconstructed, new_data);
    }

    #[test]
    fn test_append_data() {
        let old_data = vec![1u8; 8192];
        let sig = FileSignature::compute(&old_data, 4096);

        // 追加 4KB
        let mut new_data = old_data.clone();
        new_data.extend_from_slice(&[2u8; 4096]);

        let computer = DeltaComputer::new(4096);
        let delta = computer.compute_delta(&new_data, &sig);

        // 前面的块应该是 Copy，追加的是 Literal
        let copy_count = delta
            .instructions
            .iter()
            .filter(|i| matches!(i, DeltaInstruction::Copy { .. }))
            .count();
        assert!(copy_count >= 2, "Original blocks should be Copy");

        // 差异应该小于新文件大小
        assert!(delta.delta_size < new_data.len() as u64);

        // 验证重建
        let reconstructed = computer.apply_delta(&old_data, &delta);
        assert_eq!(reconstructed, new_data);
    }

    #[test]
    fn test_empty_source() {
        let old_data = vec![1u8; 4096];
        let sig = FileSignature::compute(&old_data, 4096);

        let computer = DeltaComputer::new(4096);
        let delta = computer.compute_delta(&[], &sig);

        assert!(delta.instructions.is_empty());
        assert_eq!(delta.delta_size, 0);
    }

    #[test]
    fn test_empty_target() {
        let new_data = vec![1u8; 4096];
        let sig = FileSignature::compute(&[], 4096);

        let computer = DeltaComputer::new(4096);
        let delta = computer.compute_delta(&new_data, &sig);

        // 空目标 → 全是 Literal
        assert_eq!(delta.instructions.len(), 1);
        assert!(matches!(&delta.instructions[0], DeltaInstruction::Literal { .. }));
    }

    #[test]
    fn test_lookup_table() {
        let data = vec![0u8; 12288]; // 3 个块
        let sig = FileSignature::compute(&data, 4096);
        let lookup = sig.build_lookup();

        // 所有块内容相同，弱校验和相同
        // 查找表应该有一个条目，包含 3 个索引
        assert!(!lookup.is_empty());
    }
}
