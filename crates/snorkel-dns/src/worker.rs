use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use socket2::{Domain, Socket, Type};

use crate::builder::{
    build_error_header, build_response, RCODE_NOTIMP, RCODE_REFUSED, ResponseKind,
};
use crate::dispatch::{CacheLookup, Dispatcher, strip_zone_suffix};
use crate::metrics::Metrics;
use crate::negcache::NegCache;
use crate::parser::{ParseError, extract_query_id, parse_query};
use crate::penalty::PenaltyTracker;
use crate::ratelimit::{SourceRateLimiter, ZoneRateLimiter, subnet_key};

const BUF_SIZE: usize = 512;
const QUEUE_CAPACITY: usize = 1024;

pub struct InFlightCap {
    current: AtomicU64,
    max: u64,
}

impl InFlightCap {
    pub fn new(max: u64) -> Self {
        Self {
            current: AtomicU64::new(0),
            max,
        }
    }

    pub fn try_acquire(&self) -> bool {
        let prev = self.current.fetch_add(1, Ordering::Relaxed);
        if prev >= self.max {
            self.current.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub fn release(&self) {
        self.current.fetch_sub(1, Ordering::Relaxed);
    }
}

struct QueuedResponse {
    send_at_micros: u64,
    bytes: [u8; BUF_SIZE],
    len: usize,
    dest: SocketAddr,
}

pub struct WorkerShared<'a, L: CacheLookup + Sync> {
    pub dispatcher: &'a Dispatcher<'a, L>,
    pub metrics: &'a Metrics,
    pub inflight: &'a InFlightCap,
    pub min_response_micros: u64,
}

struct WorkerLocal {
    src_rl: SourceRateLimiter,
    zone_rl: ZoneRateLimiter,
    penalty: PenaltyTracker,
    neg_cache: NegCache,
    queue: VecDeque<QueuedResponse>,
    started: Instant,
}

impl WorkerLocal {
    fn new() -> Self {
        Self {
            src_rl: SourceRateLimiter::new(),
            zone_rl: ZoneRateLimiter::new(),
            penalty: PenaltyTracker::new(),
            neg_cache: NegCache::new(),
            queue: VecDeque::with_capacity(QUEUE_CAPACITY),
            started: Instant::now(),
        }
    }

    fn now_micros(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

pub fn create_worker_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, None)?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

pub fn worker_loop<L: CacheLookup + Sync>(
    socket: UdpSocket,
    shared: WorkerShared<'_, L>,
) {
    let mut local = WorkerLocal::new();
    let mut recv_buf = [0_u8; BUF_SIZE];

    loop {
        let now = local.now_micros();
        drain_ready(&socket, &mut local.queue, now, shared.inflight);

        let timeout = next_timeout(&local.queue, now);
        let _ = socket.set_read_timeout(Some(timeout));

        match socket.recv_from(&mut recv_buf) {
            Ok((n, src)) => {
                shared.metrics.queries_total.fetch_add(1, Ordering::Relaxed);
                process_query(&recv_buf, n, src, &socket, &shared, &mut local);
            }
            Err(e)
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => continue,
        }
    }
}

fn next_timeout(queue: &VecDeque<QueuedResponse>, now_micros: u64) -> Duration {
    match queue.front() {
        Some(front) => {
            let remaining = front.send_at_micros.saturating_sub(now_micros);
            Duration::from_micros(remaining.max(100))
        }
        None => Duration::from_secs(1),
    }
}

fn drain_ready(
    socket: &UdpSocket,
    queue: &mut VecDeque<QueuedResponse>,
    now_micros: u64,
    inflight: &InFlightCap,
) {
    while let Some(front) = queue.front() {
        if front.send_at_micros > now_micros {
            break;
        }
        if let Some(entry) = queue.pop_front() {
            if let Some(slice) = entry.bytes.get(..entry.len) {
                let _ = socket.send_to(slice, entry.dest);
            }
            inflight.release();
        }
    }
}

fn process_query<L: CacheLookup + Sync>(
    recv_buf: &[u8; BUF_SIZE],
    n: usize,
    src: SocketAddr,
    socket: &UdpSocket,
    shared: &WorkerShared<'_, L>,
    local: &mut WorkerLocal,
) {
    let now_micros = local.now_micros();
    let subnet = subnet_key(src.ip());

    if local.penalty.is_penalized(&subnet, now_micros) {
        shared
            .metrics
            .drop_penalty_backoff
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    if !local.src_rl.check_and_consume(subnet, now_micros) {
        shared
            .metrics
            .drop_src_rate_limit
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    let Some(query) = recv_buf.get(..n) else {
        shared
            .metrics
            .drop_parse_error
            .fetch_add(1, Ordering::Relaxed);
        return;
    };

    let parsed = match parse_query(query, shared.dispatcher.zone) {
        Ok(p) => p,
        Err(ParseError::UnsupportedQtype) => {
            shared
                .metrics
                .drop_parse_error
                .fetch_add(1, Ordering::Relaxed);
            if let Some(id) = extract_query_id(query) {
                send_error_response(socket, src, id, RCODE_NOTIMP);
                shared.metrics.resp_notimp.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        Err(ParseError::QnameNotInZone) => {
            shared
                .metrics
                .drop_parse_error
                .fetch_add(1, Ordering::Relaxed);
            if let Some(id) = extract_query_id(query) {
                send_error_response(socket, src, id, RCODE_REFUSED);
                shared.metrics.resp_refused.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        Err(_) => {
            shared
                .metrics
                .drop_parse_error
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let Some(local_label) = strip_zone_suffix(&parsed.question.qname, shared.dispatcher.zone)
    else {
        return;
    };

    if !local.zone_rl.check_and_consume(local_label, now_micros) {
        shared
            .metrics
            .drop_zone_rate_limit
            .fetch_add(1, Ordering::Relaxed);
        local.penalty.record_strike(subnet, now_micros);
        return;
    }

    if !shared.inflight.try_acquire() {
        shared
            .metrics
            .drop_inflight_cap
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    if local.neg_cache.is_negative(local_label) {
        shared.metrics.neg_cache_hit.fetch_add(1, Ordering::Relaxed);
        let mut resp_buf = [0_u8; BUF_SIZE];
        match build_response(
            &mut resp_buf,
            parsed.id,
            &parsed.question,
            ResponseKind::NxDomain,
        ) {
            Ok(len) => {
                enqueue_or_send(local, shared, socket, resp_buf, len, src, now_micros);
            }
            Err(_) => shared.inflight.release(),
        }
        return;
    }

    let record = shared.dispatcher.cache.lookup(local_label);
    let kind = shared
        .dispatcher
        .resolve(parsed.question.qtype, record.as_ref());

    if matches!(kind, ResponseKind::NxDomain) {
        if local.neg_cache.observe_nxdomain(local_label, now_micros) {
            shared.metrics.first_seen_hit.fetch_add(1, Ordering::Relaxed);
        } else {
            shared
                .metrics
                .first_seen_miss
                .fetch_add(1, Ordering::Relaxed);
        }
        shared.metrics.resp_nxdomain.fetch_add(1, Ordering::Relaxed);
    } else {
        shared.metrics.resp_noerror.fetch_add(1, Ordering::Relaxed);
    }

    let mut resp_buf = [0_u8; BUF_SIZE];
    match build_response(&mut resp_buf, parsed.id, &parsed.question, kind) {
        Ok(len) => {
            enqueue_or_send(local, shared, socket, resp_buf, len, src, now_micros);
        }
        Err(_) => shared.inflight.release(),
    }
}

fn enqueue_or_send<L: CacheLookup + Sync>(
    local: &mut WorkerLocal,
    shared: &WorkerShared<'_, L>,
    socket: &UdpSocket,
    bytes: [u8; BUF_SIZE],
    len: usize,
    dest: SocketAddr,
    now_micros: u64,
) {
    if shared.min_response_micros == 0 {
        if let Some(slice) = bytes.get(..len) {
            let _ = socket.send_to(slice, dest);
        }
        shared.inflight.release();
        return;
    }

    if local.queue.len() >= QUEUE_CAPACITY {
        shared.inflight.release();
        return;
    }

    let send_at_micros = now_micros.saturating_add(shared.min_response_micros);
    local.queue.push_back(QueuedResponse {
        send_at_micros,
        bytes,
        len,
        dest,
    });
}

fn send_error_response(socket: &UdpSocket, dest: SocketAddr, query_id: u16, rcode: u8) {
    let mut resp_buf = [0_u8; 12];
    if let Ok(len) = build_error_header(&mut resp_buf, query_id, rcode) {
        if let Some(slice) = resp_buf.get(..len) {
            let _ = socket.send_to(slice, dest);
        }
    }
}
