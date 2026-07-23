//! LSP v3.0 拥塞控制模块
//!
//! 实现 TCP 风格的拥塞控制算法，防止网络过载。
//!
//! ## 算法
//!
//! ### 慢启动（Slow Start）
//! - 初始 cwnd = 10 * MSS（或配置的初始值）
//! - 每收到一个 ACK，cwnd += MSS（指数增长）
//! - 达到 ssthresh 后进入拥塞避免
//!
//! ### 拥塞避免（Congestion Avoidance）
//! - 每个 RTT，cwnd += MSS（线性增长）
//! - 即每收到一个 ACK，cwnd += MSS * MSS / cwnd
//!
//! ### 快速恢复（Fast Recovery）
//! - 收到 3 个重复 ACK → ssthresh = cwnd/2, cwnd = ssthresh + 3*MSS
//! - 每收到一个重复 ACK，cwnd += MSS
//! - 收到新 ACK → cwnd = ssthresh，进入拥塞避免
//!
//! ### 超时处理
//! - ssthresh = cwnd/2
//! - cwnd = 1 * MSS（回到慢启动）
//!
//! ## 参考
//!
//! - RFC 5681: TCP Congestion Control
//! - RFC 6582: The NewReno Modification to TCP's Fast Recovery Algorithm

use std::time::Duration;

/// 最大段大小（字节）— 对应一个数据帧的载荷
pub const MSS: u32 = 64 * 1024; // 64KB，与 DEFAULT_CHUNK_SIZE 一致
/// 初始拥塞窗口（段数）
pub const INITIAL_CWND_SEGMENTS: u32 = 10;
/// 初始 ssthresh
pub const INITIAL_SSTHRESH: u32 = u32::MAX;
/// 最小 cwnd（段数）
pub const MIN_CWND_SEGMENTS: u32 = 2;

/// 拥塞控制状态机
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// 慢启动
    SlowStart,
    /// 拥塞避免
    CongestionAvoidance,
    /// 快速恢复
    FastRecovery,
}

/// 拥塞控制器
///
/// 每个流一个实例，管理该流的拥塞窗口。
#[derive(Debug, Clone)]
pub struct CongestionController {
    /// 当前拥塞窗口（字节）
    cwnd: u32,
    /// 慢启动阈值（字节）
    ssthresh: u32,
    /// 当前状态
    state: CongestionState,
    /// 最大段大小
    mss: u32,
    /// 当前 RTT 估算（用于计算拥塞避免增量）
    srtt: Duration,
    /// 进入快速恢复时的恢复点（触发快速重传的 seq）
    recovery_seq: u32,
    /// 统计
    pub stats: CongestionStats,
}

/// 拥塞控制统计
#[derive(Debug, Clone, Default)]
pub struct CongestionStats {
    /// 慢启动次数
    pub slow_start_count: u64,
    /// 拥塞避免进入次数
    pub congestion_avoidance_count: u64,
    /// 快速恢复次数
    pub fast_recovery_count: u64,
    /// 超时次数
    pub timeout_count: u64,
    /// cwnd 历史最大值
    pub max_cwnd: u32,
    /// cwnd 历史最小值
    pub min_cwnd: u32,
}

impl CongestionController {
    pub fn new(mss: u32) -> Self {
        let initial_cwnd = INITIAL_CWND_SEGMENTS * mss;
        Self {
            cwnd: initial_cwnd,
            ssthresh: INITIAL_SSTHRESH,
            state: CongestionState::SlowStart,
            mss,
            srtt: Duration::from_millis(100), // 默认 100ms
            recovery_seq: 0,
            stats: CongestionStats {
                max_cwnd: initial_cwnd,
                min_cwnd: initial_cwnd,
                ..Default::default()
            },
        }
    }

    /// 使用默认 MSS 创建
    pub fn default_mss() -> Self {
        Self::new(MSS)
    }

    /// 获取当前拥塞窗口（字节）
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// 获取当前拥塞窗口（段数）
    pub fn cwnd_segments(&self) -> u32 {
        self.cwnd / self.mss
    }

    /// 获取 ssthresh
    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// 获取当前状态
    pub fn state(&self) -> CongestionState {
        self.state
    }

    /// 更新 SRTT（由 RTT 估算器提供）
    pub fn update_srtt(&mut self, srtt: Duration) {
        self.srtt = srtt;
    }

    /// 收到 ACK 时调用
    ///
    /// - `bytes_acked`: 本次 ACK 确认的字节数
    /// - `is_dup_ack`: 是否是重复 ACK
    /// - `seq_num`: ACK 确认的序列号
    pub fn on_ack(&mut self, bytes_acked: u32, is_dup_ack: bool, seq_num: u32) {
        match self.state {
            CongestionState::SlowStart => {
                if is_dup_ack {
                    // 慢启动期间收到重复 ACK，不处理
                    return;
                }

                // 慢启动：cwnd += bytes_acked（指数增长）
                self.cwnd = self.cwnd.saturating_add(bytes_acked);

                // 达到 ssthresh，切换到拥塞避免
                if self.cwnd >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                    self.stats.congestion_avoidance_count += 1;
                }
            }

            CongestionState::CongestionAvoidance => {
                if is_dup_ack {
                    // 拥塞避免期间收到重复 ACK
                    // 第一个和第二个重复 ACK：cwnd += MSS（允许额外数据进入网络）
                    // 第三个重复 ACK 由 on_triple_dup_ack 处理
                    self.cwnd = self.cwnd.saturating_add(self.mss);
                    return;
                }

                // 拥塞避免：cwnd += MSS * bytes_acked / cwnd（线性增长）
                // 等效于每个 RTT 增加一个 MSS
                let increment = (self.mss as u64 * bytes_acked as u64 / self.cwnd as u64) as u32;
                self.cwnd = self.cwnd.saturating_add(increment.max(1));
            }

            CongestionState::FastRecovery => {
                if is_dup_ack {
                    // 快速恢复期间收到重复 ACK：cwnd += MSS
                    self.cwnd = self.cwnd.saturating_add(self.mss);
                    return;
                }

                // 收到新 ACK（确认了恢复点之后的数据）
                // 退出快速恢复，进入拥塞避免
                if seq_num > self.recovery_seq {
                    self.cwnd = self.ssthresh;
                    self.state = CongestionState::CongestionAvoidance;
                    self.stats.congestion_avoidance_count += 1;
                }
            }
        }

        self.update_stats();
    }

    /// 收到 3 个重复 ACK（触发快速重传）
    ///
    /// 进入快速恢复：
    /// - ssthresh = max(cwnd/2, 2*MSS)
    /// - cwnd = ssthresh + 3*MSS
    pub fn on_triple_dup_ack(&mut self, seq_num: u32) {
        // 如果已经在快速恢复中，不重复进入
        if self.state == CongestionState::FastRecovery {
            return;
        }

        self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh + 3 * self.mss;
        self.state = CongestionState::FastRecovery;
        self.recovery_seq = seq_num;
        self.stats.fast_recovery_count += 1;

        self.update_stats();
    }

    /// 超时事件
    ///
    /// - ssthresh = max(cwnd/2, 2*MSS)
    /// - cwnd = 1 * MSS（回到慢启动起点）
    pub fn on_timeout(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.state = CongestionState::SlowStart;
        self.stats.timeout_count += 1;
        self.stats.slow_start_count += 1;

        self.update_stats();
    }

    /// 更新统计
    fn update_stats(&mut self) {
        if self.cwnd > self.stats.max_cwnd {
            self.stats.max_cwnd = self.cwnd;
        }
        if self.cwnd < self.stats.min_cwnd {
            self.stats.min_cwnd = self.cwnd;
        }
    }

    /// 获取当前允许发送的最大字节数
    pub fn allowed_bytes(&self) -> u32 {
        self.cwnd
    }

    /// 是否处于慢启动
    pub fn is_slow_start(&self) -> bool {
        self.state == CongestionState::SlowStart
    }

    /// 是否处于快速恢复
    pub fn is_fast_recovery(&self) -> bool {
        self.state == CongestionState::FastRecovery
    }
}

/// 拥塞控制管理器 — 管理所有流的拥塞控制器
pub struct CongestionManager {
    controllers: std::collections::HashMap<u32, CongestionController>,
    mss: u32,
}

impl CongestionManager {
    pub fn new(mss: u32) -> Self {
        Self {
            controllers: std::collections::HashMap::new(),
            mss,
        }
    }

    /// 注册新流
    pub fn register_stream(&mut self, stream_id: u32) {
        self.controllers
            .insert(stream_id, CongestionController::new(self.mss));
    }

    /// 注销流
    pub fn unregister_stream(&mut self, stream_id: u32) {
        self.controllers.remove(&stream_id);
    }

    /// 获取控制器
    pub fn get(&self, stream_id: u32) -> Option<&CongestionController> {
        self.controllers.get(&stream_id)
    }

    /// 获取可变控制器
    pub fn get_mut(&mut self, stream_id: u32) -> Option<&mut CongestionController> {
        self.controllers.get_mut(&stream_id)
    }

    /// 获取某流的 cwnd
    pub fn cwnd(&self, stream_id: u32) -> u32 {
        self.controllers
            .get(&stream_id)
            .map(|c| c.cwnd())
            .unwrap_or(0)
    }

    /// 处理 ACK
    pub fn on_ack(&mut self, stream_id: u32, bytes_acked: u32, is_dup_ack: bool, seq_num: u32) {
        if let Some(ctrl) = self.controllers.get_mut(&stream_id) {
            ctrl.on_ack(bytes_acked, is_dup_ack, seq_num);
        }
    }

    /// 处理三重重复 ACK
    pub fn on_triple_dup_ack(&mut self, stream_id: u32, seq_num: u32) {
        if let Some(ctrl) = self.controllers.get_mut(&stream_id) {
            ctrl.on_triple_dup_ack(seq_num);
        }
    }

    /// 处理超时
    pub fn on_timeout(&mut self, stream_id: u32) {
        if let Some(ctrl) = self.controllers.get_mut(&stream_id) {
            ctrl.on_timeout();
        }
    }

    /// 更新 SRTT
    pub fn update_srtt(&mut self, stream_id: u32, srtt: Duration) {
        if let Some(ctrl) = self.controllers.get_mut(&stream_id) {
            ctrl.update_srtt(srtt);
        }
    }
}

impl Default for CongestionManager {
    fn default() -> Self {
        Self::new(MSS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let cc = CongestionController::new(MSS);
        assert_eq!(cc.cwnd(), INITIAL_CWND_SEGMENTS * MSS);
        assert_eq!(cc.state(), CongestionState::SlowStart);
        assert_eq!(cc.ssthresh(), INITIAL_SSTHRESH);
    }

    #[test]
    fn test_slow_start_growth() {
        let mut cc = CongestionController::new(1000);
        let initial = cc.cwnd();

        // 慢启动：每个 ACK 增加 bytes_acked
        cc.on_ack(1000, false, 1);
        assert_eq!(cc.cwnd(), initial + 1000);

        cc.on_ack(1000, false, 2);
        assert_eq!(cc.cwnd(), initial + 2000);

        assert!(cc.is_slow_start());
    }

    #[test]
    fn test_slow_start_to_congestion_avoidance() {
        let mut cc = CongestionController::new(1000);
        cc.ssthresh = 15000; // 设置较低的阈值

        // 慢启动到 ssthresh
        for i in 0..5 {
            cc.on_ack(1000, false, i + 1);
        }
        // cwnd = 10000 + 5000 = 15000 >= ssthresh
        assert_eq!(cc.state(), CongestionState::CongestionAvoidance);
    }

    #[test]
    fn test_congestion_avoidance_linear_growth() {
        let mut cc = CongestionController::new(1000);
        cc.cwnd = 20000;
        cc.ssthresh = 10000;
        cc.state = CongestionState::CongestionAvoidance;

        let before = cc.cwnd();
        // 拥塞避免：cwnd += MSS * bytes_acked / cwnd
        // = 1000 * 1000 / 20000 = 50
        cc.on_ack(1000, false, 1);
        let after = cc.cwnd();

        // 增长应该是线性的（远小于慢启动的指数增长）
        assert!(after > before);
        assert!(after - before < 1000); // 小于一个 MSS
    }

    #[test]
    fn test_triple_dup_ack_fast_recovery() {
        let mut cc = CongestionController::new(1000);
        cc.cwnd = 20000;
        cc.state = CongestionState::CongestionAvoidance;

        cc.on_triple_dup_ack(5);

        // ssthresh = max(20000/2, 2000) = 10000
        assert_eq!(cc.ssthresh(), 10000);
        // cwnd = ssthresh + 3*MSS = 10000 + 3000 = 13000
        assert_eq!(cc.cwnd(), 13000);
        assert_eq!(cc.state(), CongestionState::FastRecovery);
        assert_eq!(cc.stats.fast_recovery_count, 1);
    }

    #[test]
    fn test_fast_recovery_exit() {
        let mut cc = CongestionController::new(1000);
        cc.cwnd = 20000;
        cc.state = CongestionState::CongestionAvoidance;

        cc.on_triple_dup_ack(5);
        assert_eq!(cc.state(), CongestionState::FastRecovery);

        // 快速恢复期间收到重复 ACK：cwnd += MSS
        cc.on_ack(1000, true, 5);
        assert_eq!(cc.cwnd(), 14000); // 13000 + 1000

        // 收到新 ACK（seq > recovery_seq=5），退出快速恢复
        cc.on_ack(1000, false, 6);
        assert_eq!(cc.state(), CongestionState::CongestionAvoidance);
        assert_eq!(cc.cwnd(), 10000); // cwnd = ssthresh
    }

    #[test]
    fn test_timeout() {
        let mut cc = CongestionController::new(1000);
        cc.cwnd = 20000;
        cc.state = CongestionState::CongestionAvoidance;

        cc.on_timeout();

        // ssthresh = max(20000/2, 2000) = 10000
        assert_eq!(cc.ssthresh(), 10000);
        // cwnd = 1 * MSS = 1000
        assert_eq!(cc.cwnd(), 1000);
        assert_eq!(cc.state(), CongestionState::SlowStart);
        assert_eq!(cc.stats.timeout_count, 1);
    }

    #[test]
    fn test_min_cwnd() {
        let mut cc = CongestionController::new(1000);
        cc.cwnd = 1000; // 已经很小了

        cc.on_timeout();
        // cwnd = max(1*MSS, ...) = 1000
        assert_eq!(cc.cwnd(), 1000);

        // ssthresh = max(1000/2, 2000) = 2000
        assert_eq!(cc.ssthresh(), 2000);
    }

    #[test]
    fn test_congestion_manager() {
        let mut mgr = CongestionManager::new(1000);
        mgr.register_stream(1);
        mgr.register_stream(2);

        assert_eq!(mgr.cwnd(1), INITIAL_CWND_SEGMENTS * 1000);
        assert_eq!(mgr.cwnd(2), INITIAL_CWND_SEGMENTS * 1000);

        mgr.on_ack(1, 1000, false, 1);
        assert!(mgr.cwnd(1) > INITIAL_CWND_SEGMENTS * 1000);
        assert_eq!(mgr.cwnd(2), INITIAL_CWND_SEGMENTS * 1000); // 不受影响

        mgr.on_timeout(1);
        assert_eq!(mgr.cwnd(1), 1000);

        mgr.unregister_stream(1);
        assert_eq!(mgr.cwnd(1), 0); // 已注销
    }

    #[test]
    fn test_dup_ack_in_congestion_avoidance() {
        let mut cc = CongestionController::new(1000);
        cc.cwnd = 20000;
        cc.state = CongestionState::CongestionAvoidance;

        let before = cc.cwnd();
        // 重复 ACK 在拥塞避免中：cwnd += MSS
        cc.on_ack(1000, true, 5);
        assert_eq!(cc.cwnd(), before + 1000);
    }
}
