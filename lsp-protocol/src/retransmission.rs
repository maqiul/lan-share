//! LSP v3.0 可靠传输模块
//!
//! 实现超时重传、RTT 估算（Jacobson/Karels）、累计确认 + 选择性确认（SACK）。
//!
//! ## 核心机制
//!
//! - **发送窗口**：维护已发送但未确认的帧缓冲区
//! - **RTT 估算**：使用 Jacobson/Karels 算法动态调整 RTO
//! - **超时重传**：RTO 到期后重传最早的未确认帧
//! - **快速重传**：收到 3 个重复 ACK 立即重传（不等超时）
//! - **SACK**：选择性确认，只重传真正丢失的帧

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// 默认初始 RTO（RFC 6298 推荐 1s）
pub const INITIAL_RTO: Duration = Duration::from_secs(1);
/// 最小 RTO
pub const MIN_RTO: Duration = Duration::from_millis(200);
/// 最大 RTO
pub const MAX_RTO: Duration = Duration::from_secs(60);
/// 快速重传阈值（重复 ACK 数）
pub const FAST_RETRANSMIT_THRESHOLD: u32 = 3;
/// 最大重传次数
pub const MAX_RETRANSMIT_COUNT: u32 = 10;
/// 默认发送窗口大小（帧数）
pub const DEFAULT_SEND_WINDOW: u32 = 64;

/// RTT 估算器（Jacobson/Karels 算法）
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// 平滑 RTT（SRTT）
    srtt: Option<Duration>,
    /// RTT 方差（RTTVAR）
    rttvar: Option<Duration>,
    /// 当前 RTO
    rto: Duration,
    /// 是否有正在计时的包（Karn 算法：重传的包不更新 RTT）
    timing_active: bool,
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            srtt: None,
            rttvar: None,
            rto: INITIAL_RTO,
            timing_active: false,
        }
    }

    /// 记录一个 RTT 采样值，更新 RTO
    ///
    /// 遵循 RFC 6298：
    /// - 首次：SRTT = R, RTTVAR = R/2, RTO = SRTT + 4*RTTVAR
    /// - 后续：RTTVAR = (1-β)*RTTVAR + β*|SRTT-R|, SRTT = (1-α)*SRTT + α*R
    ///   其中 α=1/8, β=1/4
    pub fn update(&mut self, rtt: Duration) {
        if self.timing_active {
            // Karn 算法：重传包的 RTT 不采样
            return;
        }

        match self.srtt {
            None => {
                // 首次测量
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2);
            }
            Some(srtt) => {
                let rttvar = self.rttvar.unwrap_or(rtt / 2);

                // RTTVAR = (1 - 1/4) * RTTVAR + (1/4) * |SRTT - R|
                let delta = if srtt > rtt { srtt - rtt } else { rtt - srtt };
                let new_rttvar = (rttvar * 3 + delta) / 4;

                // SRTT = (1 - 1/8) * SRTT + (1/8) * R
                let new_srtt = (srtt * 7 + rtt) / 8;

                self.srtt = Some(new_srtt);
                self.rttvar = Some(new_rttvar);
            }
        }

        // RTO = SRTT + 4 * RTTVAR
        let srtt = self.srtt.unwrap();
        let rttvar = self.rttvar.unwrap();
        self.rto = srtt + rttvar * 4;

        // 钳位
        if self.rto < MIN_RTO {
            self.rto = MIN_RTO;
        }
        if self.rto > MAX_RTO {
            self.rto = MAX_RTO;
        }
    }

    /// 获取当前 RTO
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// 超时后指数退避（RTO *= 2）
    pub fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(MAX_RTO);
    }

    /// 标记开始计时
    pub fn start_timing(&mut self) {
        self.timing_active = false; // 新包可以采样
    }

    /// 标记这是重传包（Karn 算法：不采样）
    pub fn mark_retransmit(&mut self) {
        self.timing_active = true;
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// 已发送帧的元数据
#[derive(Debug, Clone)]
pub struct SentFrameInfo {
    /// 序列号
    pub seq_num: u32,
    /// 发送时间
    pub sent_at: Instant,
    /// 重传次数
    pub retransmit_count: u32,
    /// 帧数据（用于重传）
    pub data: Vec<u8>,
    /// 帧大小（字节）
    pub size: u32,
    /// 是否是重传包
    pub is_retransmit: bool,
}

/// SACK 块：表示 [left, right] 范围内的帧已被确认
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlock {
    pub left: u32,   // 起始序列号（含）
    pub right: u32,  // 结束序列号（含）
}

/// 重传管理器
///
/// 跟踪每个流上已发送但未确认的帧，处理超时重传和快速重传。
pub struct RetransmissionManager {
    /// 每个流的发送缓冲区：seq_num -> SentFrameInfo
    send_buffers: HashMap<u32, BTreeMap<u32, SentFrameInfo>>,
    /// 每个流的已确认序列号（累计确认点）
    acked_seqs: HashMap<u32, u32>,
    /// 每个流的 SACK 块
    sack_blocks: HashMap<u32, Vec<SackBlock>>,
    /// 每个流的重复 ACK 计数
    dup_ack_counts: HashMap<u32, u32>,
    /// 每个流的 RTT 估算器
    rtt_estimators: HashMap<u32, RttEstimator>,
    /// 每个流的发送窗口（帧数）
    send_windows: HashMap<u32, u32>,
    /// 每个流的下一个序列号
    next_seqs: HashMap<u32, u32>,
    /// 统计
    pub stats: RetransmitStats,
}

/// 重传统计
#[derive(Debug, Clone, Default)]
pub struct RetransmitStats {
    /// 总发送帧数
    pub total_sent: u64,
    /// 总重传帧数
    pub total_retransmitted: u64,
    /// 快速重传次数
    pub fast_retransmits: u64,
    /// 超时重传次数
    pub timeout_retransmits: u64,
    /// 丢弃帧数（超过最大重传次数）
    pub dropped: u64,
}

/// 重传事件
#[derive(Debug)]
pub enum RetransmitEvent {
    /// 需要重传的帧（流 ID, 序列号, 数据）
    Retransmit {
        stream_id: u32,
        seq_num: u32,
        data: Vec<u8>,
    },
    /// 帧被丢弃（超过最大重传次数）
    Dropped {
        stream_id: u32,
        seq_num: u32,
    },
}

impl RetransmissionManager {
    pub fn new() -> Self {
        Self {
            send_buffers: HashMap::new(),
            acked_seqs: HashMap::new(),
            sack_blocks: HashMap::new(),
            dup_ack_counts: HashMap::new(),
            rtt_estimators: HashMap::new(),
            send_windows: HashMap::new(),
            next_seqs: HashMap::new(),
            stats: RetransmitStats::default(),
        }
    }

    /// 注册新流
    pub fn register_stream(&mut self, stream_id: u32, window_size: u32) {
        self.send_buffers.insert(stream_id, BTreeMap::new());
        self.acked_seqs.insert(stream_id, 0);
        self.sack_blocks.insert(stream_id, Vec::new());
        self.dup_ack_counts.insert(stream_id, 0);
        self.rtt_estimators.insert(stream_id, RttEstimator::new());
        self.send_windows.insert(stream_id, window_size);
        self.next_seqs.insert(stream_id, 1);
    }

    /// 注销流
    pub fn unregister_stream(&mut self, stream_id: u32) {
        self.send_buffers.remove(&stream_id);
        self.acked_seqs.remove(&stream_id);
        self.sack_blocks.remove(&stream_id);
        self.dup_ack_counts.remove(&stream_id);
        self.rtt_estimators.remove(&stream_id);
        self.send_windows.remove(&stream_id);
        self.next_seqs.remove(&stream_id);
    }

    /// 分配下一个序列号
    pub fn next_seq(&mut self, stream_id: u32) -> u32 {
        let seq = self.next_seqs.entry(stream_id).or_insert(1);
        let val = *seq;
        *seq += 1;
        val
    }

    /// 记录已发送帧
    pub fn on_frame_sent(&mut self, stream_id: u32, seq_num: u32, data: Vec<u8>) {
        let size = data.len() as u32;
        let info = SentFrameInfo {
            seq_num,
            sent_at: Instant::now(),
            retransmit_count: 0,
            data,
            size,
            is_retransmit: false,
        };

        if let Some(buffer) = self.send_buffers.get_mut(&stream_id) {
            buffer.insert(seq_num, info);
        }

        self.stats.total_sent += 1;

        // 启动 RTT 计时
        if let Some(estimator) = self.rtt_estimators.get_mut(&stream_id) {
            estimator.start_timing();
        }
    }

    /// 处理收到的 ACK
    ///
    /// 返回需要重传的事件列表
    pub fn on_ack_received(
        &mut self,
        stream_id: u32,
        ack_seq: u32,
        sack_blocks: Option<&[SackBlock]>,
    ) -> Vec<RetransmitEvent> {
        let mut events = Vec::new();

        let current_acked = *self.acked_seqs.get(&stream_id).unwrap_or(&0);

        if ack_seq > current_acked {
            // 新的累计确认 — 清除已确认的帧
            self.acked_seqs.insert(stream_id, ack_seq);
            self.dup_ack_counts.insert(stream_id, 0);

            if let Some(buffer) = self.send_buffers.get_mut(&stream_id) {
                // 删除所有 <= ack_seq 的帧
                let confirmed: Vec<u32> = buffer
                    .range(..=ack_seq)
                    .map(|(k, _)| *k)
                    .collect();

                for seq in confirmed {
                    // 更新 RTT（只对非重传帧）
                    if let Some(info) = buffer.get(&seq) {
                        if !info.is_retransmit {
                            let rtt = info.sent_at.elapsed();
                            if let Some(estimator) = self.rtt_estimators.get_mut(&stream_id) {
                                estimator.update(rtt);
                            }
                        }
                    }
                    buffer.remove(&seq);
                }
            }

            // 处理 SACK 块
            if let Some(blocks) = sack_blocks {
                self.process_sack(stream_id, blocks);
            }
        } else if ack_seq == current_acked {
            // 重复 ACK
            let count = self.dup_ack_counts.entry(stream_id).or_insert(0);
            *count += 1;

            if *count == FAST_RETRANSMIT_THRESHOLD {
                // 快速重传：重传 ack_seq + 1
                let retransmit_seq = ack_seq + 1;
                if let Some(buffer) = self.send_buffers.get_mut(&stream_id) {
                    if let Some(info) = buffer.get_mut(&retransmit_seq) {
                        info.retransmit_count += 1;
                        info.is_retransmit = true;
                        info.sent_at = Instant::now();

                        if let Some(estimator) = self.rtt_estimators.get_mut(&stream_id) {
                            estimator.mark_retransmit();
                        }

                        events.push(RetransmitEvent::Retransmit {
                            stream_id,
                            seq_num: retransmit_seq,
                            data: info.data.clone(),
                        });

                        self.stats.total_retransmitted += 1;
                        self.stats.fast_retransmits += 1;
                    }
                }
            }
        }

        events
    }

    /// 处理 SACK 块
    fn process_sack(&mut self, stream_id: u32, blocks: &[SackBlock]) {
        if let Some(buffer) = self.send_buffers.get_mut(&stream_id) {
            for block in blocks {
                // SACK 确认 [left, right] 范围内的帧
                let sack_acked: Vec<u32> = buffer
                    .range(block.left..=block.right)
                    .map(|(k, _)| *k)
                    .collect();

                for seq in sack_acked {
                    buffer.remove(&seq);
                }
            }
        }

        // 保存 SACK 块供后续使用
        self.sack_blocks.insert(stream_id, blocks.to_vec());
    }

    /// 检查超时，返回需要重传的帧
    ///
    /// 应定期调用（例如每 50ms 一次）
    pub fn check_timeouts(&mut self) -> Vec<RetransmitEvent> {
        let mut events = Vec::new();
        let now = Instant::now();

        let stream_ids: Vec<u32> = self.send_buffers.keys().cloned().collect();

        for stream_id in stream_ids {
            let rto = self
                .rtt_estimators
                .get(&stream_id)
                .map(|e| e.rto())
                .unwrap_or(INITIAL_RTO);

            let acked = *self.acked_seqs.get(&stream_id).unwrap_or(&0);

            if let Some(buffer) = self.send_buffers.get_mut(&stream_id) {
                // 找到最早的未确认帧
                let timed_out: Vec<(u32, bool)> = buffer
                    .iter()
                    .filter(|(seq, info)| {
                        **seq > acked && now.duration_since(info.sent_at) >= rto
                    })
                    .map(|(seq, info)| (*seq, info.retransmit_count >= MAX_RETRANSMIT_COUNT))
                    .collect();

                for (seq, should_drop) in timed_out {
                    if should_drop {
                        // 超过最大重传次数，丢弃
                        buffer.remove(&seq);
                        events.push(RetransmitEvent::Dropped { stream_id, seq_num: seq });
                        self.stats.dropped += 1;
                    } else if let Some(info) = buffer.get_mut(&seq) {
                        // 超时重传
                        info.retransmit_count += 1;
                        info.is_retransmit = true;
                        info.sent_at = now;

                        // 指数退避
                        if let Some(estimator) = self.rtt_estimators.get_mut(&stream_id) {
                            estimator.backoff();
                            estimator.mark_retransmit();
                        }

                        events.push(RetransmitEvent::Retransmit {
                            stream_id,
                            seq_num: seq,
                            data: info.data.clone(),
                        });

                        self.stats.total_retransmitted += 1;
                        self.stats.timeout_retransmits += 1;
                    }
                }
            }
        }

        events
    }

    /// 获取当前发送窗口是否已满
    pub fn is_window_full(&self, stream_id: u32) -> bool {
        let window = *self.send_windows.get(&stream_id).unwrap_or(&DEFAULT_SEND_WINDOW);
        let in_flight = self
            .send_buffers
            .get(&stream_id)
            .map(|b| b.len() as u32)
            .unwrap_or(0);
        in_flight >= window
    }

    /// 获取当前在途帧数
    pub fn in_flight(&self, stream_id: u32) -> u32 {
        self.send_buffers
            .get(&stream_id)
            .map(|b| b.len() as u32)
            .unwrap_or(0)
    }

    /// 获取当前 RTO
    pub fn current_rto(&self, stream_id: u32) -> Duration {
        self.rtt_estimators
            .get(&stream_id)
            .map(|e| e.rto())
            .unwrap_or(INITIAL_RTO)
    }

    /// 获取 SRTT
    pub fn srtt(&self, stream_id: u32) -> Option<Duration> {
        self.rtt_estimators.get(&stream_id).and_then(|e| e.srtt)
    }

    /// 更新发送窗口大小
    pub fn update_window(&mut self, stream_id: u32, new_window: u32) {
        self.send_windows.insert(stream_id, new_window);
    }

    /// 检查是否有未确认的帧
    pub fn has_unacked(&self, stream_id: u32) -> bool {
        self.send_buffers
            .get(&stream_id)
            .map(|b| !b.is_empty())
            .unwrap_or(false)
    }

    /// 等待所有帧被确认（用于关闭流前）
    pub fn all_acked(&self, stream_id: u32) -> bool {
        self.send_buffers
            .get(&stream_id)
            .map(|b| b.is_empty())
            .unwrap_or(true)
    }
}

impl Default for RetransmissionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_estimator_initial() {
        let mut est = RttEstimator::new();
        assert_eq!(est.rto(), INITIAL_RTO);

        // 首次采样
        est.update(Duration::from_millis(100));
        // SRTT=100ms, RTTVAR=50ms, RTO=100+200=300ms
        assert_eq!(est.rto(), Duration::from_millis(300));
    }

    #[test]
    fn test_rtt_estimator_subsequent() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(100));
        est.update(Duration::from_millis(120));

        // SRTT = (100*7 + 120)/8 = 102.5ms
        // RTTVAR = (50*3 + |100-120|)/4 = (150+20)/4 = 42.5ms
        // RTO = 102.5 + 4*42.5 = 272.5ms
        let rto = est.rto();
        assert!(rto >= Duration::from_millis(270));
        assert!(rto <= Duration::from_millis(275));
    }

    #[test]
    fn test_rtt_backoff() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(100));
        let rto_before = est.rto();
        est.backoff();
        assert_eq!(est.rto(), rto_before * 2);
    }

    #[test]
    fn test_rtt_min_clamp() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(1));
        // RTO 应该被钳位到 MIN_RTO
        assert_eq!(est.rto(), MIN_RTO);
    }

    #[test]
    fn test_retransmit_basic() {
        let mut mgr = RetransmissionManager::new();
        mgr.register_stream(1, 64);

        // 发送帧 1, 2, 3
        mgr.on_frame_sent(1, 1, vec![1, 2, 3]);
        mgr.on_frame_sent(1, 2, vec![4, 5, 6]);
        mgr.on_frame_sent(1, 3, vec![7, 8, 9]);

        assert_eq!(mgr.in_flight(1), 3);
        assert!(!mgr.all_acked(1));

        // 确认帧 1
        let events = mgr.on_ack_received(1, 1, None);
        assert!(events.is_empty());
        assert_eq!(mgr.in_flight(1), 2);

        // 确认帧 2, 3
        mgr.on_ack_received(1, 3, None);
        assert_eq!(mgr.in_flight(1), 0);
        assert!(mgr.all_acked(1));
    }

    #[test]
    fn test_fast_retransmit() {
        let mut mgr = RetransmissionManager::new();
        mgr.register_stream(1, 64);

        mgr.on_frame_sent(1, 1, vec![1]);
        mgr.on_frame_sent(1, 2, vec![2]);
        mgr.on_frame_sent(1, 3, vec![3]);

        // 收到 3 个重复 ACK（ack_seq=1，说明帧 2 丢了）
        mgr.on_ack_received(1, 1, None); // 正常确认
        mgr.on_ack_received(1, 1, None); // dup 1
        mgr.on_ack_received(1, 1, None); // dup 2
        let events = mgr.on_ack_received(1, 1, None); // dup 3 → 快速重传

        assert_eq!(events.len(), 1);
        match &events[0] {
            RetransmitEvent::Retransmit { seq_num, .. } => assert_eq!(*seq_num, 2),
            _ => panic!("Expected Retransmit event"),
        }
        assert_eq!(mgr.stats.fast_retransmits, 1);
    }

    #[test]
    fn test_sack() {
        let mut mgr = RetransmissionManager::new();
        mgr.register_stream(1, 64);

        mgr.on_frame_sent(1, 1, vec![1]);
        mgr.on_frame_sent(1, 2, vec![2]);
        mgr.on_frame_sent(1, 3, vec![3]);
        mgr.on_frame_sent(1, 4, vec![4]);

        // 累计确认到 1，SACK 确认 3-4
        let sack = vec![SackBlock { left: 3, right: 4 }];
        mgr.on_ack_received(1, 1, Some(&sack));

        // 帧 1 被累计确认，帧 3,4 被 SACK 确认，只剩帧 2
        assert_eq!(mgr.in_flight(1), 1);
    }

    #[test]
    fn test_window_full() {
        let mut mgr = RetransmissionManager::new();
        mgr.register_stream(1, 2); // 窗口大小 2

        mgr.on_frame_sent(1, 1, vec![1]);
        assert!(!mgr.is_window_full(1));

        mgr.on_frame_sent(1, 2, vec![2]);
        assert!(mgr.is_window_full(1));

        mgr.on_ack_received(1, 1, None);
        assert!(!mgr.is_window_full(1));
    }

    #[test]
    fn test_timeout_retransmit() {
        let mut mgr = RetransmissionManager::new();
        mgr.register_stream(1, 64);

        mgr.on_frame_sent(1, 1, vec![1, 2, 3]);

        // 手动把 sent_at 改到过去（模拟超时）
        if let Some(buffer) = mgr.send_buffers.get_mut(&1) {
            if let Some(info) = buffer.get_mut(&1) {
                info.sent_at = Instant::now() - Duration::from_secs(5);
            }
        }

        let events = mgr.check_timeouts();
        assert_eq!(events.len(), 1);
        match &events[0] {
            RetransmitEvent::Retransmit { seq_num, .. } => assert_eq!(*seq_num, 1),
            _ => panic!("Expected Retransmit event"),
        }
        assert_eq!(mgr.stats.timeout_retransmits, 1);
    }

    #[test]
    fn test_max_retransmit_drop() {
        let mut mgr = RetransmissionManager::new();
        mgr.register_stream(1, 64);

        mgr.on_frame_sent(1, 1, vec![1]);

        // 设置已重传 MAX_RETRANSMIT_COUNT 次
        if let Some(buffer) = mgr.send_buffers.get_mut(&1) {
            if let Some(info) = buffer.get_mut(&1) {
                info.retransmit_count = MAX_RETRANSMIT_COUNT;
                info.sent_at = Instant::now() - Duration::from_secs(5);
            }
        }

        let events = mgr.check_timeouts();
        assert_eq!(events.len(), 1);
        match &events[0] {
            RetransmitEvent::Dropped { seq_num, .. } => assert_eq!(*seq_num, 1),
            _ => panic!("Expected Dropped event"),
        }
        assert_eq!(mgr.stats.dropped, 1);
    }
}
