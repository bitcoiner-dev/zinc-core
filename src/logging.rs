use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogLevel {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl LogLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    #[must_use]
    pub const fn from_u8(level: u8) -> Option<Self> {
        match level {
            0 => Some(Self::Off),
            1 => Some(Self::Error),
            2 => Some(Self::Warn),
            3 => Some(Self::Info),
            4 => Some(Self::Debug),
            5 => Some(Self::Trace),
            _ => None,
        }
    }
}

#[cfg(feature = "debug")]
pub const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Debug;

#[cfg(not(feature = "debug"))]
pub const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Warn;

static LOGGING_ENABLED: AtomicBool = AtomicBool::new(true);
static LOG_LEVEL: AtomicU8 = AtomicU8::new(DEFAULT_LOG_LEVEL as u8);

#[must_use]
pub fn parse_level(level: &str) -> Option<LogLevel> {
    match level.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LogLevel::Off),
        "error" => Some(LogLevel::Error),
        "warn" | "warning" => Some(LogLevel::Warn),
        "info" => Some(LogLevel::Info),
        "debug" => Some(LogLevel::Debug),
        "trace" => Some(LogLevel::Trace),
        _ => None,
    }
}

pub fn set_log_level(level: LogLevel) {
    LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

#[must_use]
pub fn get_log_level() -> LogLevel {
    let raw = LOG_LEVEL.load(Ordering::Relaxed);
    LogLevel::from_u8(raw).unwrap_or(DEFAULT_LOG_LEVEL)
}

pub fn set_logging_enabled(enabled: bool) {
    LOGGING_ENABLED.store(enabled, Ordering::Relaxed);
}

#[must_use]
pub fn logging_enabled() -> bool {
    LOGGING_ENABLED.load(Ordering::Relaxed)
}

#[must_use]
pub fn should_log(level: LogLevel) -> bool {
    if !logging_enabled() {
        return false;
    }

    let current = get_log_level() as u8;
    current >= level as u8 && level != LogLevel::Off
}

#[must_use]
pub fn redact_identifier(value: &str) -> String {
    format!("<redacted:{} chars>", value.chars().count())
}

#[must_use]
pub fn redacted_field(name: &str, value: &str) -> String {
    format!("{name}={}", redact_identifier(value))
}

macro_rules! zinc_log_error {
    (target: $target:expr, $($arg:tt)+) => {{
        if $crate::logging::should_log($crate::logging::LogLevel::Error) {
            tracing::error!(target: $target, $($arg)+);
        }
    }};
    ($($arg:tt)+) => {
        zinc_log_error!(target: "zinc_core", $($arg)+)
    };
}

macro_rules! zinc_log_warn {
    (target: $target:expr, $($arg:tt)+) => {{
        if $crate::logging::should_log($crate::logging::LogLevel::Warn) {
            tracing::warn!(target: $target, $($arg)+);
        }
    }};
    ($($arg:tt)+) => {
        zinc_log_warn!(target: "zinc_core", $($arg)+)
    };
}

macro_rules! zinc_log_info {
    (target: $target:expr, $($arg:tt)+) => {{
        if $crate::logging::should_log($crate::logging::LogLevel::Info) {
            tracing::info!(target: $target, $($arg)+);
        }
    }};
    ($($arg:tt)+) => {
        zinc_log_info!(target: "zinc_core", $($arg)+)
    };
}

macro_rules! zinc_log_debug {
    (target: $target:expr, $($arg:tt)+) => {{
        if $crate::logging::should_log($crate::logging::LogLevel::Debug) {
            tracing::debug!(target: $target, $($arg)+);
        }
    }};
    ($($arg:tt)+) => {
        zinc_log_debug!(target: "zinc_core", $($arg)+)
    };
}

macro_rules! zinc_log_trace {
    (target: $target:expr, $($arg:tt)+) => {{
        if $crate::logging::should_log($crate::logging::LogLevel::Trace) {
            tracing::trace!(target: $target, $($arg)+);
        }
    }};
    ($($arg:tt)+) => {
        zinc_log_trace!(target: "zinc_core", $($arg)+)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LOG_STATE_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_level_supports_known_values() {
        assert_eq!(parse_level("off"), Some(LogLevel::Off));
        assert_eq!(parse_level("error"), Some(LogLevel::Error));
        assert_eq!(parse_level("warn"), Some(LogLevel::Warn));
        assert_eq!(parse_level("warning"), Some(LogLevel::Warn));
        assert_eq!(parse_level("info"), Some(LogLevel::Info));
        assert_eq!(parse_level("debug"), Some(LogLevel::Debug));
        assert_eq!(parse_level("trace"), Some(LogLevel::Trace));
        assert_eq!(parse_level(" TRACE "), Some(LogLevel::Trace));
        assert_eq!(parse_level("verbose"), None);
    }

    #[test]
    fn redaction_helpers_never_leak_identifier() {
        let raw = "bc1p1234567890abcdefghijklmnop";
        let redacted = redact_identifier(raw);
        assert!(!redacted.contains(raw));
        assert!(redacted.contains("redacted"));

        let field = redacted_field("address", raw);
        assert!(field.starts_with("address="));
        assert!(!field.contains(raw));
    }

    #[test]
    fn should_log_respects_runtime_level_and_toggle() {
        let _guard = LOG_STATE_LOCK.lock().unwrap();

        set_logging_enabled(true);
        set_log_level(LogLevel::Warn);

        assert!(should_log(LogLevel::Error));
        assert!(should_log(LogLevel::Warn));
        assert!(!should_log(LogLevel::Info));

        set_log_level(LogLevel::Debug);
        assert!(should_log(LogLevel::Info));
        assert!(should_log(LogLevel::Debug));
        assert!(!should_log(LogLevel::Trace));

        set_logging_enabled(false);
        assert!(!should_log(LogLevel::Error));
        assert!(!should_log(LogLevel::Debug));

        set_logging_enabled(true);
        set_log_level(DEFAULT_LOG_LEVEL);
    }

    #[test]
    fn as_str_round_trips_through_parse_level() {
        for lvl in [
            LogLevel::Off,
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ] {
            assert_eq!(parse_level(lvl.as_str()), Some(lvl));
        }
    }

    #[test]
    fn from_u8_maps_valid_levels_and_rejects_others() {
        assert_eq!(LogLevel::from_u8(0), Some(LogLevel::Off));
        assert_eq!(LogLevel::from_u8(1), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_u8(5), Some(LogLevel::Trace));
        assert_eq!(LogLevel::from_u8(6), None);
        assert_eq!(LogLevel::from_u8(255), None);
    }

    #[test]
    fn off_target_level_is_never_logged_even_at_max_verbosity() {
        let _guard = LOG_STATE_LOCK.lock().unwrap();
        set_logging_enabled(true);
        set_log_level(LogLevel::Trace);
        // Asking whether to emit an `Off`-level record must always be false.
        assert!(!should_log(LogLevel::Off));
        set_log_level(DEFAULT_LOG_LEVEL);
    }
}
