//! One admission budget per HTTP origin, shared by all Core clients/tasks.
//!
//! Bounded startup dispatch followed by smooth steady-state admission prevents
//! address probes from exhausting a reverse proxy's burst allowance. Queued
//! calls remain cancellable and operation deadlines must include admission.
//! This is process/WASM-instance local, not a cross-device or cross-IP quota.

use esplora_client::Sleeper;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use web_time::Instant;

// Four immediate requests, then ~29/s for at most 128 total startup requests.
// This uses a bounded fraction of the deployed 30/s + 120 Esplora and
// 20/s + 100 Ord burst budgets; steady state remains ~15/s. It is NOT a
// continuously refilling token bucket. Only 60 seconds without dispatches or
// responses rearms startup. Wallet/account changes never reset the origin.
const SPACING: Duration = Duration::from_millis(67);
const STARTUP_SPACING: Duration = Duration::from_millis(34);
const STARTUP_REQUESTS: u16 = 128;
const IMMEDIATE_REQUESTS: u8 = 4;
const IDLE_RESET: Duration = Duration::from_secs(60);
const MAX_ORIGINS: usize = 128;

struct Schedule {
    next: Option<Instant>,
    cooldown: Option<Instant>,
    overloads: u32,
    startup_remaining: u16,
    immediate_remaining: u8,
    last_activity: Option<Instant>,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            next: None,
            cooldown: None,
            overloads: 0,
            startup_remaining: STARTUP_REQUESTS,
            immediate_remaining: IMMEDIATE_REQUESTS,
            last_activity: None,
        }
    }
}

impl Schedule {
    fn wait(&self, now: Instant) -> Duration {
        // Overload cooldown is never bypassed, including by immediate credit.
        self.next
            .filter(|_| self.immediate_remaining == 0)
            .into_iter()
            .chain(self.cooldown)
            .max()
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
    }

    fn admit(&mut self, now: Instant) -> Duration {
        if self.overloads == 0
            && self
                .last_activity
                .is_some_and(|last| now.saturating_duration_since(last) >= IDLE_RESET)
            && self.cooldown.is_none_or(|until| until <= now)
        {
            self.startup_remaining = STARTUP_REQUESTS;
            self.immediate_remaining = IMMEDIATE_REQUESTS;
            self.next = None;
        }
        let wait = self.wait(now);
        if wait.is_zero() {
            let spacing = if self.startup_remaining > 0 {
                STARTUP_SPACING
            } else {
                SPACING
            };
            self.startup_remaining = self.startup_remaining.saturating_sub(1);
            self.immediate_remaining = self.immediate_remaining.saturating_sub(1);
            self.next = Some(now + spacing);
            self.last_activity = Some(now);
        }
        wait
    }

    fn observe(&mut self, now: Instant, status: u16, retry_after: Option<&str>) {
        self.last_activity = Some(now);
        if matches!(status, 429 | 503) {
            // Never retry an overloaded provider with startup credit, even
            // after a long Retry-After. Resume at the conservative steady rate.
            self.startup_remaining = 0;
            self.immediate_remaining = 0;
            // Concurrent failures from the same wave share one backoff step.
            if self.cooldown.is_none_or(|until| until <= now) {
                self.overloads = self.overloads.saturating_add(1).min(5);
            }
            let backoff = Duration::from_secs((1u64 << self.overloads).min(30));
            let requested = crate::backend_error::parse_retry_after_ms(retry_after)
                .map(Duration::from_millis)
                .unwrap_or_default();
            let until = now + backoff.max(requested);
            self.cooldown = Some(self.cooldown.map_or(until, |old| old.max(until)));
        } else if (200..300).contains(&status) && self.cooldown.is_none_or(|until| until <= now) {
            // A success already in flight must not erase a newer overload.
            self.overloads = 0;
            self.cooldown = None;
        }
    }
}

#[derive(Default)]
struct Origin {
    turn: futures_util::lock::Mutex<()>,
    schedule: Mutex<Schedule>,
}

#[derive(Default)]
struct Registry {
    origins: HashMap<String, Arc<Origin>>,
    // Bound memory even for callers creating arbitrary custom origins. Overflow
    // shares a conservative budget instead of silently bypassing pacing.
    overflow: Arc<Origin>,
}

impl Registry {
    fn get(&mut self, url: &str) -> Arc<Origin> {
        let Ok(url) = reqwest::Url::parse(url) else {
            return self.overflow.clone();
        };
        let key = url.origin().ascii_serialization();
        if let Some(origin) = self.origins.get(&key) {
            return origin.clone();
        }
        if self.origins.len() == MAX_ORIGINS {
            return self.overflow.clone();
        }
        self.origins.entry(key).or_default().clone()
    }
}

fn origin(url: &str) -> Arc<Origin> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(url)
}

impl Origin {
    async fn acquire(&self) {
        let _turn = self.turn.lock().await;
        loop {
            let wait = {
                let mut state = self.schedule.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                state.admit(now)
            };
            if wait.is_zero() {
                return;
            }
            // No slot is reserved while waiting. Cancellation drops the lock and
            // cannot leave phantom reservations delaying a later wallet request.
            crate::builder::SyncSleeper::sleep(wait).await;
        }
    }
}

pub(crate) async fn before_request(url: &str) {
    origin(url).acquire().await;
}

pub fn after_response(url: &str, status: u16, retry_after: Option<&str>) {
    origin(url)
        .schedule
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .observe(Instant::now(), status, retry_after);
}

/// Non-blocking admission for shell HTTP requests. Zero admits exactly one
/// request; a positive value is a delay to wait before asking again (not a
/// reservation). Shells pass origins only, through their existing trusted RPC.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
pub fn backend_request_delay(url: &str) -> u32 {
    let origin = origin(url);
    let mut state = origin.schedule.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let wait = state.admit(now);
    if wait.is_zero() {
        0
    } else {
        wait.as_millis().saturating_add(1).min(u128::from(u32::MAX)) as u32
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
pub fn backend_response_observed(url: &str, status: u16, retry_after: Option<String>) {
    after_response(url, status, retry_after.as_deref());
}

/// Dispatch exactly once through Core's shared pacing policy. Use for raw
/// discovery/Ord/fee HTTP calls; Esplora (including BDK) uses SyncSleeper hooks.
/// No retries, redirects beyond reqwest's policy, or provider changes are added.
pub async fn send(builder: reqwest::RequestBuilder) -> Result<reqwest::Response, reqwest::Error> {
    let (client, request) = builder.build_split();
    let request = request?;
    let url = request.url().to_string();
    before_request(&url).await;
    let response = client.execute(request).await?;
    after_response(
        &url,
        response.status().as_u16(),
        response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_budget_ignores_path_credentials_and_default_port() {
        let mut registry = Registry::default();
        let a = registry.get("https://example.com/address/a");
        assert!(Arc::ptr_eq(
            &a,
            &registry.get("https://user:secret@example.com:443/tx/b?token=private")
        ));
        assert!(!Arc::ptr_eq(
            &a,
            &registry.get("https://example.com:444/tx/b")
        ));
        assert_eq!(
            registry.origins.keys().next().unwrap().contains("secret"),
            false
        );
    }

    #[test]
    fn registry_is_bounded_without_unpaced_overflow() {
        let mut registry = Registry::default();
        for i in 0..MAX_ORIGINS {
            registry.get(&format!("https://host{i}.invalid"));
        }
        assert!(Arc::ptr_eq(
            &registry.get("https://overflow-a.invalid"),
            &registry.get("https://overflow-b.invalid")
        ));
        assert_eq!(registry.origins.len(), MAX_ORIGINS);
    }

    #[test]
    fn cooldown_coalesces_honors_retry_after_and_survives_inflight_success() {
        let now = Instant::now();
        let mut s = Schedule::default();
        s.observe(now, 503, None);
        s.observe(now, 429, Some("12"));
        s.observe(now, 200, None);
        assert_eq!(s.overloads, 1);
        assert_eq!(s.wait(now), Duration::from_secs(12));
        s.observe(now + Duration::from_secs(12), 503, None);
        assert_eq!(
            s.wait(now + Duration::from_secs(12)),
            Duration::from_secs(4)
        );
        s.observe(now + Duration::from_secs(16), 200, None);
        assert_eq!(s.wait(now + Duration::from_secs(16)), Duration::ZERO);
        assert_eq!(s.overloads, 0);
        s.observe(now, 429, Some("999999"));
        assert_eq!(s.wait(now), Duration::from_secs(300));
    }

    #[tokio::test]
    async fn concurrent_clients_share_admission_and_cancellation_leaves_no_debt() {
        let origin = Origin::default();
        let start = Instant::now();
        futures_util::future::join_all((0..6).map(|_| origin.acquire())).await;
        assert!(start.elapsed() >= STARTUP_SPACING * 2);
        // Timeout a queued caller; only the last dispatched request owns a slot.
        assert!(
            tokio::time::timeout(Duration::from_millis(1), origin.acquire())
                .await
                .is_err()
        );
        let next = origin.schedule.lock().unwrap().next.unwrap();
        assert!(next <= Instant::now() + SPACING);
    }

    #[test]
    fn startup_is_bounded_and_only_real_idle_rearms_it() {
        let now = Instant::now();
        let mut s = Schedule::default();
        for _ in 0..IMMEDIATE_REQUESTS {
            assert!(s.admit(now).is_zero());
        }
        assert_eq!(s.admit(now), STARTUP_SPACING);
        // Asking again while queued does not consume credit or reserve a slot.
        assert_eq!(
            s.startup_remaining,
            STARTUP_REQUESTS - u16::from(IMMEDIATE_REQUESTS)
        );
        let mut time = now;
        for _ in IMMEDIATE_REQUESTS as u16..STARTUP_REQUESTS {
            time += STARTUP_SPACING;
            assert!(s.admit(time).is_zero());
        }
        time += STARTUP_SPACING;
        assert!(s.admit(time).is_zero());
        assert_eq!(s.admit(time), SPACING);
        time += SPACING;
        assert!(s.admit(time).is_zero());
        assert_eq!(s.startup_remaining, 0);
        // A normal gap/account transition cannot refill startup credit.
        time += IDLE_RESET - Duration::from_millis(1);
        assert!(s.admit(time).is_zero());
        assert_eq!(s.startup_remaining, 0);
        time += IDLE_RESET;
        assert!(s.admit(time).is_zero());
        assert_eq!(s.startup_remaining, STARTUP_REQUESTS - 1);
        assert_eq!(s.immediate_remaining, IMMEDIATE_REQUESTS - 1);
    }

    #[test]
    fn overload_drops_all_startup_credit_and_response_activity_prevents_refill() {
        let now = Instant::now();
        let mut s = Schedule::default();
        assert!(s.admit(now).is_zero());
        s.observe(now, 429, Some("120"));
        assert_eq!(s.startup_remaining, 0);
        assert_eq!(s.immediate_remaining, 0);
        assert_eq!(s.admit(now + IDLE_RESET), IDLE_RESET);
        assert!(s.admit(now + Duration::from_secs(120)).is_zero());
        assert_eq!(s.admit(now + Duration::from_secs(120)), SPACING);
        s.observe(now + Duration::from_secs(120), 200, None);
        assert_eq!(s.startup_remaining, 0);
        s.observe(now + Duration::from_secs(179), 200, None);
        assert!(s.admit(now + Duration::from_secs(180)).is_zero());
        assert_eq!(s.startup_remaining, 0);
    }

    #[test]
    fn bounded_startup_fits_deployed_ord_and_tight_esplora_budgets() {
        for (rate, capacity) in [(20.0, 100.0), (30.0, 5.0)] {
            let mut time = Instant::now();
            let mut last = time;
            let mut tokens = capacity;
            let mut s = Schedule::default();
            for cycle in 0..3 {
                if cycle > 0 {
                    time += IDLE_RESET;
                }
                for _ in 0..500 {
                    let wait = s.admit(time);
                    if !wait.is_zero() {
                        time += wait;
                        assert!(s.admit(time).is_zero());
                    }
                    tokens = (tokens + time.saturating_duration_since(last).as_secs_f64() * rate)
                        .min(capacity);
                    assert!(
                        tokens >= 1.0,
                        "startup exceeds modeled provider burst budget"
                    );
                    tokens -= 1.0;
                    last = time;
                }
                assert_eq!(s.startup_remaining, 0);
            }
        }
    }

    #[tokio::test]
    async fn raw_and_bdk_clients_share_budget_and_errors_are_not_replayed() {
        let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
        // Drain the shared startup allowance, without issuing HTTP traffic,
        // so this transport test exercises steady-state shared admission.
        for _ in 0..STARTUP_REQUESTS {
            origin(&server.url()).acquire().await;
        }
        let tip = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("100")
            .expect(1)
            .create_async()
            .await;
        let failure = server
            .mock("GET", "/address/a")
            .with_status(503)
            .with_header("Retry-After", "2")
            .expect(1)
            .create_async()
            .await;
        let client = crate::builder::configured_esplora_client(&server.url()).unwrap();
        client.get_height().await.unwrap();
        let start = Instant::now();
        let result = send(reqwest::Client::new().get(format!("{}/address/a", server.url())))
            .await
            .unwrap();
        assert_eq!(result.status(), 503);
        assert!(start.elapsed() >= Duration::from_millis(45));
        assert!(
            origin(&server.url())
                .schedule
                .lock()
                .unwrap()
                .wait(Instant::now())
                > Duration::from_secs(1)
        );
        tip.assert_async().await;
        failure.assert_async().await;
    }
}
