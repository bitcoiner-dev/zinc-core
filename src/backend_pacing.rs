//! One admission budget per HTTP origin, shared by all Core clients/tasks.
//!
//! Smooth dispatch (not merely concurrent-request limiting) prevents fast
//! address probes from exhausting a reverse proxy's burst allowance. Queued
//! calls remain cancellable and operation deadlines must include admission.
//! This is process/WASM-instance local, not a cross-device or cross-IP quota.

use esplora_client::Sleeper;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use web_time::Instant;

// ~15/s, one immediate request: headroom below our 30/s Esplora and 20/s Ord
// limits. No accumulated tokens, so idle time cannot create a new burst.
const SPACING: Duration = Duration::from_millis(67);
const MAX_ORIGINS: usize = 128;

#[derive(Default)]
struct Schedule {
    next: Option<Instant>,
    cooldown: Option<Instant>,
    overloads: u32,
}

impl Schedule {
    fn wait(&self, now: Instant) -> Duration {
        self.next
            .into_iter()
            .chain(self.cooldown)
            .max()
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
    }

    fn observe(&mut self, now: Instant, status: u16, retry_after: Option<&str>) {
        if matches!(status, 429 | 503) {
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
                let wait = state.wait(now);
                if wait.is_zero() {
                    state.next = Some(now + SPACING);
                }
                wait
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
    let wait = state.wait(now);
    if wait.is_zero() {
        state.next = Some(now + SPACING);
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
        let (_, _, _) = futures_util::join!(origin.acquire(), origin.acquire(), origin.acquire());
        assert!(start.elapsed() >= SPACING * 2);
        // Timeout a queued caller; only the last dispatched request owns a slot.
        assert!(
            tokio::time::timeout(Duration::from_millis(1), origin.acquire())
                .await
                .is_err()
        );
        let next = origin.schedule.lock().unwrap().next.unwrap();
        assert!(next <= Instant::now() + SPACING);
    }

    #[tokio::test]
    async fn raw_and_bdk_clients_share_budget_and_errors_are_not_replayed() {
        let mut server = mockito::Server::new_with_opts_async(Default::default()).await;
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
