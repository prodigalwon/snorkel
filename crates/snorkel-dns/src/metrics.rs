use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub queries_total: AtomicU64,
    pub drop_inflight_cap: AtomicU64,
    pub drop_penalty_backoff: AtomicU64,
    pub drop_src_rate_limit: AtomicU64,
    pub drop_zone_rate_limit: AtomicU64,
    pub drop_parse_error: AtomicU64,
    pub resp_noerror: AtomicU64,
    pub resp_nxdomain: AtomicU64,
    pub resp_notimp: AtomicU64,
    pub resp_refused: AtomicU64,
    pub neg_cache_hit: AtomicU64,
    pub first_seen_hit: AtomicU64,
    pub first_seen_miss: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn log_snapshot(&self) {
        println!(
            "metrics: total={} drop_inflight={} drop_penalty={} drop_src={} drop_zone={} drop_parse={} \
             resp_ok={} resp_nx={} resp_notimp={} resp_refused={} neg_hit={} first_seen_hit={} first_seen_miss={}",
            self.queries_total.load(Ordering::Relaxed),
            self.drop_inflight_cap.load(Ordering::Relaxed),
            self.drop_penalty_backoff.load(Ordering::Relaxed),
            self.drop_src_rate_limit.load(Ordering::Relaxed),
            self.drop_zone_rate_limit.load(Ordering::Relaxed),
            self.drop_parse_error.load(Ordering::Relaxed),
            self.resp_noerror.load(Ordering::Relaxed),
            self.resp_nxdomain.load(Ordering::Relaxed),
            self.resp_notimp.load(Ordering::Relaxed),
            self.resp_refused.load(Ordering::Relaxed),
            self.neg_cache_hit.load(Ordering::Relaxed),
            self.first_seen_hit.load(Ordering::Relaxed),
            self.first_seen_miss.load(Ordering::Relaxed),
        );
    }
}
