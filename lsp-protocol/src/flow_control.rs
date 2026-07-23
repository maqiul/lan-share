//! LSP v3.0 流量控制模块
//!
//! 实现基于滑动窗口的流量控制，防止发送方压垮接收方。
//!
//! ## 核心机制
//!
//! - **接收窗口（rwnd）**：接收方通告剩余缓冲区大小，发送方据此限速
//! - **发送窗口（cwnd）**：发送方维护，受 rwnd 和拥塞窗口共同约束
//! - **窗口更新**：接收方消费数据后发送 WINDOW_UPDATE 帧扩大窗口
//! - **背压传导**：窗口为 0 时发送方暂停，直到收到窗口更新
//! - **零窗口探测**：窗口为 0 时定期发送 1 字节探测，避免死锁
//!
//! ## 窗口约束
//!
//! 实际发送窗口 = min(cwnd, rwnd)
//! 在途字节数 <= 实际发送窗口

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 默认初始窗口大小（字节）
pub const DEFAULT_INITIAL_WINDOW: u32 = 1024 * 1024; // 1MB
/// 最大窗口大小
pub const MAX_WINDOW: u32 = 64 * 1024 * 1024; // 64MB
/// 最小窗口大小（低于此值触发零窗口探测）
pub const MIN_WINDOW: u32 = 1024; // 1KB
/// 零窗口探测间隔
pub const ZERO_WINDOW_PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// 零窗口探测最大间隔（指数退避上限）
pub const ZERO_WINDOW_MAX_INTERVAL: Duration = Duration::from_secs(30);
/// 窗口缩放因子（用于大带宽场景）
pub const WINDOW_SCALE_FACTOR: u32 = 1;

/// 接收方流控状态
#[derive(Debug, Clone)]
pub struct ReceiverFlowControl {
    /// 接收缓冲区总大小
    buffer_capacity: u32,
    /// 当前已缓冲的字节数
    buffered_bytes: u32,
    /// 上次发送窗口更新的时间
    last_window_update: Instant,
    /// 窗口更新阈值（缓冲消费超过此比例时发送更新）
    update_threshold: f64,
}

impl ReceiverFlowControl {
    pub fn new(buffer_capacity: u32) -> Self {
        Self {
            buffer_capacity,
            buffered_bytes: 0,
            last_window_update: Instant::now(),
            update_threshold: 0.25, // 消费 25% 后发送更新
        }
    }

    /// 数据到达，增加缓冲占用
    pub fn on_data_received(&mut self, bytes: u32) {
        self.buffered_bytes = (self.buffered_bytes + bytes).min(self.buffer_capacity);
    }

    /// 应用层消费了数据，释放缓冲
    ///
    /// 返回是否需要发送窗口更新
    pub fn on_data_consumed(&mut self, bytes: u32) -> bool {
        let before = self.buffered_bytes;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(bytes);

        // 如果消费超过阈值，触发窗口更新
        let consumed_ratio = if before > 0 {
            (before - self.buffered_bytes) as f64 / self.buffer_capacity as f64
        } else {
            0.0
        };

        if consumed_ratio >= self.update_threshold {
            self.last_window_update = Instant::now();
            true
        } else {
            false
        }
    }

    /// 获取当前可用窗口（通告给发送方）
    pub fn available_window(&self) -> u32 {
        self.buffer_capacity.saturating_sub(self.buffered_bytes)
    }

    /// 是否应该发送窗口更新
    pub fn should_send_window_update(&self) -> bool {
        self.available_window() > 0
            && self.last_window_update.elapsed() >= Duration::from_millis(100)
    }

    /// 缓冲区是否已满
    pub fn is_buffer_full(&self) -> bool {
        self.buffered_bytes >= self.buffer_capacity
    }

    /// 获取缓冲使用率
    pub fn buffer_usage(&self) -> f64 {
        if self.buffer_capacity == 0 {
            return 1.0;
        }
        self.buffered_bytes as f64 / self.buffer_capacity as f64
    }
}

/// 发送方流控状态
#[derive(Debug, Clone)]
pub struct SenderFlowControl {
    /// 接收方通告的窗口（rwnd）
    remote_window: u32,
    /// 拥塞窗口（cwnd）— 由拥塞控制模块管理
    congestion_window: u32,
    /// 当前在途字节数
    bytes_in_flight: u32,
    /// 零窗口探测状态
    zero_window_probe: Option<ZeroWindowProbe>,
    /// 窗口缩放因子
    scale_factor: u32,
}

/// 零窗口探测状态
#[derive(Debug, Clone)]
struct ZeroWindowProbe {
    /// 上次探测时间
    last_probe: Instant,
    /// 当前探测间隔
    interval: Duration,
    /// 探测次数
    probe_count: u32,
}

impl SenderFlowControl {
    pub fn new(initial_window: u32) -> Self {
        Self {
            remote_window: initial_window,
            congestion_window: initial_window,
            bytes_in_flight: 0,
            zero_window_probe: None,
            scale_factor: WINDOW_SCALE_FACTOR,
        }
    }

    /// 获取实际可用发送窗口
    ///
    /// 实际窗口 = min(rwnd, cwnd)
    pub fn effective_window(&self) -> u32 {
        self.remote_window.min(self.congestion_window)
    }

    /// 获取剩余可发送字节数
    pub fn available_bytes(&self) -> u32 {
        self.effective_window().saturating_sub(self.bytes_in_flight)
    }

    /// 是否可以发送数据
    pub fn can_send(&self) -> bool {
        self.available_bytes() > 0
    }

    /// 是否可以发送指定大小的数据
    pub fn can_send_bytes(&self, size: u32) -> bool {
        self.available_bytes() >= size
    }

    /// 记录发送了数据
    pub fn on_data_sent(&mut self, bytes: u32) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    /// 收到 ACK，释放在途字节
    pub fn on_ack_received(&mut self, bytes_acked: u32) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        // 如果之前是零窗口，现在恢复了
        if self.bytes_in_flight < self.effective_window() {
            self.zero_window_probe = None;
        }
    }

    /// 更新接收方通告的窗口
    pub fn update_remote_window(&mut self, window: u32) {
        let scaled = window.saturating_mul(self.scale_factor).min(MAX_WINDOW);
        let was_zero = self.remote_window == 0;
        self.remote_window = scaled;

        // 从零窗口恢复
        if was_zero && scaled > 0 {
            self.zero_window_probe = None;
        }
    }

    /// 更新拥塞窗口（由拥塞控制模块调用）
    pub fn update_congestion_window(&mut self, cwnd: u32) {
        self.congestion_window = cwnd.min(MAX_WINDOW);
    }

    /// 获取拥塞窗口
    pub fn congestion_window(&self) -> u32 {
        self.congestion_window
    }

    /// 获取接收方窗口
    pub fn remote_window(&self) -> u32 {
        self.remote_window
    }

    /// 获取在途字节数
    pub fn bytes_in_flight(&self) -> u32 {
        self.bytes_in_flight
    }

    /// 检查是否需要发送零窗口探测
    ///
    /// 当 rwnd == 0 时，发送方不能发数据，但需要定期探测
    /// 看接收方是否恢复了窗口
    pub fn should_probe_zero_window(&mut self) -> bool {
        if self.remote_window > 0 {
            return false;
        }

        match &mut self.zero_window_probe {
            None => {
                // 首次进入零窗口状态
                self.zero_window_probe = Some(ZeroWindowProbe {
                    last_probe: Instant::now(),
                    interval: ZERO_WINDOW_PROBE_INTERVAL,
                    probe_count: 0,
                });
                true // 立即发送第一次探测
            }
            Some(probe) => {
                if probe.last_probe.elapsed() >= probe.interval {
                    probe.last_probe = Instant::now();
                    probe.probe_count += 1;
                    // 指数退避
                    probe.interval = (probe.interval * 2).min(ZERO_WINDOW_MAX_INTERVAL);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// 是否处于零窗口状态
    pub fn is_zero_window(&self) -> bool {
        self.remote_window == 0
    }

    /// 获取窗口使用率
    pub fn window_usage(&self) -> f64 {
        let window = self.effective_window();
        if window == 0 {
            return 1.0;
        }
        self.bytes_in_flight as f64 / window as f64
    }
}

/// 流控管理器 — 管理所有流的流控状态
pub struct FlowControlManager {
    /// 每个流的发送方流控
    senders: HashMap<u32, SenderFlowControl>,
    /// 每个流的接收方流控
    receivers: HashMap<u32, ReceiverFlowControl>,
    /// 默认缓冲区大小
    default_buffer_size: u32,
}

impl FlowControlManager {
    pub fn new(default_buffer_size: u32) -> Self {
        Self {
            senders: HashMap::new(),
            receivers: HashMap::new(),
            default_buffer_size,
        }
    }

    /// 注册新流
    pub fn register_stream(&mut self, stream_id: u32, initial_window: u32) {
        self.senders
            .insert(stream_id, SenderFlowControl::new(initial_window));
        self.receivers
            .insert(stream_id, ReceiverFlowControl::new(self.default_buffer_size));
    }

    /// 注销流
    pub fn unregister_stream(&mut self, stream_id: u32) {
        self.senders.remove(&stream_id);
        self.receivers.remove(&stream_id);
    }

    /// 获取发送方流控（可变引用）
    pub fn sender_mut(&mut self, stream_id: u32) -> Option<&mut SenderFlowControl> {
        self.senders.get_mut(&stream_id)
    }

    /// 获取接收方流控（可变引用）
    pub fn receiver_mut(&mut self, stream_id: u32) -> Option<&mut ReceiverFlowControl> {
        self.receivers.get_mut(&stream_id)
    }

    /// 获取发送方流控（只读）
    pub fn sender(&self, stream_id: u32) -> Option<&SenderFlowControl> {
        self.senders.get(&stream_id)
    }

    /// 获取接收方流控（只读）
    pub fn receiver(&self, stream_id: u32) -> Option<&ReceiverFlowControl> {
        self.receivers.get(&stream_id)
    }

    /// 检查某流是否可以发送
    pub fn can_send(&self, stream_id: u32) -> bool {
        self.senders
            .get(&stream_id)
            .map(|s| s.can_send())
            .unwrap_or(false)
    }

    /// 获取某流的可用发送字节数
    pub fn available_bytes(&self, stream_id: u32) -> u32 {
        self.senders
            .get(&stream_id)
            .map(|s| s.available_bytes())
            .unwrap_or(0)
    }

    /// 记录发送数据
    pub fn on_data_sent(&mut self, stream_id: u32, bytes: u32) {
        if let Some(sender) = self.senders.get_mut(&stream_id) {
            sender.on_data_sent(bytes);
        }
    }

    /// 处理 ACK
    pub fn on_ack(&mut self, stream_id: u32, bytes_acked: u32) {
        if let Some(sender) = self.senders.get_mut(&stream_id) {
            sender.on_ack_received(bytes_acked);
        }
    }

    /// 处理窗口更新
    pub fn on_window_update(&mut self, stream_id: u32, new_window: u32) {
        if let Some(sender) = self.senders.get_mut(&stream_id) {
            sender.update_remote_window(new_window);
        }
    }

    /// 接收方收到数据
    pub fn on_data_received(&mut self, stream_id: u32, bytes: u32) {
        if let Some(receiver) = self.receivers.get_mut(&stream_id) {
            receiver.on_data_received(bytes);
        }
    }

    /// 接收方消费数据，返回是否需要发送窗口更新
    pub fn on_data_consumed(&mut self, stream_id: u32, bytes: u32) -> bool {
        if let Some(receiver) = self.receivers.get_mut(&stream_id) {
            receiver.on_data_consumed(bytes)
        } else {
            false
        }
    }

    /// 获取接收方当前可用窗口（用于发送 WINDOW_UPDATE）
    pub fn receiver_window(&self, stream_id: u32) -> u32 {
        self.receivers
            .get(&stream_id)
            .map(|r| r.available_window())
            .unwrap_or(0)
    }

    /// 检查所有流中是否有需要零窗口探测的
    pub fn check_zero_window_probes(&mut self) -> Vec<u32> {
        let mut probes = Vec::new();
        for (stream_id, sender) in &mut self.senders {
            if sender.should_probe_zero_window() {
                probes.push(*stream_id);
            }
        }
        probes
    }
}

impl Default for FlowControlManager {
    fn default() -> Self {
        Self::new(DEFAULT_INITIAL_WINDOW)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receiver_flow_control() {
        let mut rfc = ReceiverFlowControl::new(1000);
        assert_eq!(rfc.available_window(), 1000);

        rfc.on_data_received(300);
        assert_eq!(rfc.available_window(), 700);
        assert!(!rfc.is_buffer_full());

        rfc.on_data_received(700);
        assert_eq!(rfc.available_window(), 0);
        assert!(rfc.is_buffer_full());

        // 消费 250 字节（25%），应触发窗口更新
        let should_update = rfc.on_data_consumed(250);
        assert!(should_update);
        assert_eq!(rfc.available_window(), 250);
    }

    #[test]
    fn test_sender_flow_control() {
        let mut sfc = SenderFlowControl::new(1000);
        assert_eq!(sfc.effective_window(), 1000);
        assert!(sfc.can_send());

        sfc.on_data_sent(500);
        assert_eq!(sfc.available_bytes(), 500);
        assert_eq!(sfc.bytes_in_flight(), 500);

        sfc.on_ack_received(200);
        assert_eq!(sfc.bytes_in_flight(), 300);
        assert_eq!(sfc.available_bytes(), 700);
    }

    #[test]
    fn test_effective_window_min() {
        let mut sfc = SenderFlowControl::new(1000);
        sfc.update_congestion_window(500);
        // effective = min(rwnd=1000, cwnd=500) = 500
        assert_eq!(sfc.effective_window(), 500);

        sfc.update_remote_window(200);
        // effective = min(rwnd=200, cwnd=500) = 200
        assert_eq!(sfc.effective_window(), 200);
    }

    #[test]
    fn test_zero_window_probe() {
        let mut sfc = SenderFlowControl::new(1000);
        sfc.update_remote_window(0);
        assert!(sfc.is_zero_window());

        // 首次应该立即探测
        assert!(sfc.should_probe_zero_window());
        // 第二次不应该（间隔未到）
        assert!(!sfc.should_probe_zero_window());

        // 窗口恢复
        sfc.update_remote_window(1000);
        assert!(!sfc.is_zero_window());
        assert!(!sfc.should_probe_zero_window());
    }

    #[test]
    fn test_flow_control_manager() {
        let mut mgr = FlowControlManager::new(10000);
        mgr.register_stream(1, 5000);

        assert!(mgr.can_send(1));
        assert_eq!(mgr.available_bytes(1), 5000);

        mgr.on_data_sent(1, 3000);
        assert_eq!(mgr.available_bytes(1), 2000);

        mgr.on_ack(1, 1000);
        assert_eq!(mgr.available_bytes(1), 3000);

        mgr.on_window_update(1, 8000);
        // effective_window = min(rwnd=8000, cwnd=5000) = 5000
        // available = 5000 - 2000 = 3000
        assert_eq!(mgr.available_bytes(1), 3000);
    }

    #[test]
    fn test_receiver_window_update() {
        let mut mgr = FlowControlManager::new(1000);
        mgr.register_stream(1, 1000);

        mgr.on_data_received(1, 800);
        assert_eq!(mgr.receiver_window(1), 200);

        // 消费 300 字节（30% > 25% 阈值），应触发更新
        let should_update = mgr.on_data_consumed(1, 300);
        assert!(should_update);
        assert_eq!(mgr.receiver_window(1), 500);
    }

    #[test]
    fn test_window_usage() {
        let mut sfc = SenderFlowControl::new(1000);
        assert_eq!(sfc.window_usage(), 0.0);

        sfc.on_data_sent(500);
        assert!((sfc.window_usage() - 0.5).abs() < 0.01);

        sfc.on_data_sent(500);
        assert!((sfc.window_usage() - 1.0).abs() < 0.01);
    }
}
