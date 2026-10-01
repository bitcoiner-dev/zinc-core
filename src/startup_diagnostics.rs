//! Explicit local WASM benchmark sink. No storage, console or network output.
//! Native execution is unchanged; its harness can observe phase futures directly.

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    InitialTip,
    Coverage,
    Funding,
    Validation,
    FinalTip,
    Apply,
}
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::InitialTip => "initial-tip",
            Self::Coverage => "coverage",
            Self::Funding => "funding",
            Self::Validation => "validation",
            Self::FinalTip => "final-tip",
            Self::Apply => "apply",
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    event: &'static str,
    phase: &'static str,
    started_at_ms: f64,
    at: f64,
    duration_ms: f64,
    aborted: bool,
}

/// Holds only numeric timing and static categories, never request/wallet data.
/// Dropping a failed or cancelled future records an aborted interval.
pub(crate) struct Span {
    event: &'static str,
    phase: &'static str,
    started: Option<web_time::Instant>,
    started_at_ms: f64,
}
impl Span {
    pub(crate) fn phase(phase: Phase) -> Self {
        Self::start("core-phase", phase.name())
    }
    pub(crate) fn admission(url: &str) -> Self {
        // The URL is inspected only to choose a fixed category; never retained.
        Self::start("core-admission", endpoint(url))
    }
    fn start(event: &'static str, phase: &'static str) -> Self {
        #[cfg(target_arch = "wasm32")]
        let (started, started_at_ms) = if sink().is_some() {
            (Some(web_time::Instant::now()), js_sys::Date::now())
        } else {
            (None, 0.0)
        };
        #[cfg(not(target_arch = "wasm32"))]
        let (started, started_at_ms) = (None, 0.0);
        Self {
            event,
            phase,
            started,
            started_at_ms,
        }
    }
    pub(crate) fn finish(mut self) {
        self.emit(false);
    }
    fn emit(&mut self, aborted: bool) {
        let Some(started) = self.started.take() else {
            return;
        };
        let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
        let entry = Entry {
            event: self.event,
            phase: self.phase,
            started_at_ms: self.started_at_ms,
            at: self.started_at_ms + duration_ms,
            duration_ms,
            aborted,
        };
        #[cfg(target_arch = "wasm32")]
        if let (Some(sink), Ok(value)) = (sink(), serde_wasm_bindgen::to_value(&entry)) {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static EMITTED: AtomicUsize = AtomicUsize::new(0);
            // Hard bound per WASM realm, even if the installed sink is unbounded.
            if EMITTED
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    (n < 4096).then_some(n + 1)
                })
                .is_err()
            {
                return;
            }
            // Exceptions from the explicit diagnostic callback cannot affect sync.
            let _ = sink.call1(&wasm_bindgen::JsValue::UNDEFINED, &value);
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = entry;
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        self.emit(true);
    }
}

#[cfg(target_arch = "wasm32")]
fn sink() -> Option<js_sys::Function> {
    use wasm_bindgen::JsCast;
    js_sys::Reflect::get(&js_sys::global(), &"__zincStartupDiagnostic".into())
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()
}

fn endpoint(url: &str) -> &'static str {
    let Ok(url) = reqwest::Url::parse(url) else {
        return "other";
    };
    let path = url.path();
    if path.ends_with("/blocks/tip/hash") {
        "tip"
    } else if path.contains("/scripthash/") {
        if path.ends_with("/utxo") {
            "utxo"
        } else {
            "script"
        }
    } else if path.contains("/tx/") || path == "/txs/outspends" {
        if path.contains("/outspend/") || path == "/txs/outspends" {
            "outspend"
        } else {
            "transaction"
        }
    } else if path.contains("/address/") {
        "address"
    } else if path.contains("/block-height/") {
        "block-hash"
    } else if path.contains("/blocks") {
        "blocks"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn categories_never_echo_identifiers_or_queries() {
        for (path, expected) in [
            ("scripthash/private?secret=x", "script"),
            ("scripthash/private/utxo", "utxo"),
            ("tx/private/outspend/123", "outspend"),
            ("txs/outspends?txids=private", "outspend"),
            ("tx/private", "transaction"),
            ("blocks/tip/hash", "tip"),
            ("block-height/42", "block-hash"),
            ("blocks", "blocks"),
            ("private", "other"),
        ] {
            assert_eq!(
                endpoint(&format!("https://private.invalid/{path}")),
                expected
            );
        }
        assert_eq!(endpoint("not a URL with private data"), "other");
    }
    #[test]
    fn schema_is_closed_and_numeric() {
        let value = serde_json::to_value(Entry {
            event: "core-phase",
            phase: Phase::Coverage.name(),
            started_at_ms: 1.0,
            at: 2.0,
            duration_ms: 1.0,
            aborted: true,
        })
        .unwrap();
        let keys: std::collections::BTreeSet<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "event",
                "phase",
                "startedAtMs",
                "at",
                "durationMs",
                "aborted"
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(value["aborted"], true);
    }
}
