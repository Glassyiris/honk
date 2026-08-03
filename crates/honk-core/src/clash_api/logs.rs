//! Log streaming support for the clash API `/logs` endpoint.
//!
//! A custom tracing [`Layer`] formats every event into a single-line
//! payload and broadcasts it on a `tokio::sync::broadcast` channel. The
//! channel has a bounded capacity; slow subscribers hit `Lagged` and
//! simply skip ahead (log streaming is best-effort). With no subscribers
//! the layer skips formatting entirely, so subscribers see events from
//! their subscription time onward, not a replayed history.

use std::fmt::Write as _;
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer};

/// Bounded broadcast capacity; overflow drops the oldest entries.
pub const LOG_CHANNEL_CAPACITY: usize = 256;

/// One formatted log event distributed to `/logs` subscribers.
#[derive(Debug, Clone)]
pub struct LogEvent {
    pub level: tracing::Level,
    pub payload: String,
}

/// Tracing layer that broadcasts formatted events. Construct via [`layer`].
pub struct ClashLogLayer {
    tx: broadcast::Sender<LogEvent>,
}

/// Create the layer and the sender half handed to the clash API state.
pub fn layer() -> (ClashLogLayer, broadcast::Sender<LogEvent>) {
    let (tx, _) = broadcast::channel(LOG_CHANNEL_CAPACITY);
    (ClashLogLayer { tx: tx.clone() }, tx)
}

/// Filter selected by a clash `?level=` query value.
pub enum LogFilter {
    Level(tracing::Level),
    Off,
}

/// Parse a clash `?level=` query value into a log filter.
/// Returns `None` for unknown names (the endpoint maps that to a 400).
pub fn parse_level(level: &str) -> Option<LogFilter> {
    if level.eq_ignore_ascii_case("trace") {
        Some(LogFilter::Level(tracing::Level::TRACE))
    } else if level.eq_ignore_ascii_case("debug") {
        Some(LogFilter::Level(tracing::Level::DEBUG))
    } else if level.eq_ignore_ascii_case("info") {
        Some(LogFilter::Level(tracing::Level::INFO))
    } else if level.eq_ignore_ascii_case("warn") || level.eq_ignore_ascii_case("warning") {
        Some(LogFilter::Level(tracing::Level::WARN))
    } else if level.eq_ignore_ascii_case("error")
        || level.eq_ignore_ascii_case("fatal")
        || level.eq_ignore_ascii_case("panic")
    {
        Some(LogFilter::Level(tracing::Level::ERROR))
    } else if level.eq_ignore_ascii_case("silent") {
        Some(LogFilter::Off)
    } else {
        None
    }
}

/// Field collector: `message` becomes the payload head, remaining fields
/// are appended as ` key=value` pairs on the same line.
#[derive(Default)]
struct EventFields {
    message: String,
    extra: String,
}

impl Visit for EventFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            let _ = write!(self.extra, " {}={}", field.name(), value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            let _ = write!(self.extra, " {}={:?}", field.name(), value);
        }
    }
}

impl<S> Layer<S> for ClashLogLayer
where
    S: tracing::Subscriber,
{
    fn enabled(&self, _metadata: &tracing::Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        // Must stay unconditionally true: `Layered::enabled` short-circuits
        // the whole stack when any layer answers false, so gating on the
        // subscriber count here would silence every other layer (console
        // fmt output included) whenever no `/logs` client is attached. The
        // formatting skip lives in `on_event` below.
        true
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        // A receiver may disconnect after `enabled`; retain this guard so
        // formatting is never paid after the final subscriber leaves.
        if self.tx.receiver_count() == 0 {
            return;
        }
        let mut fields = EventFields::default();
        event.record(&mut fields);
        let payload = if fields.message.is_empty() {
            format!("{}{}", event.metadata().target(), fields.extra)
        } else {
            format!("{}{}", fields.message, fields.extra)
        };
        let _ = self.tx.send(LogEvent {
            level: *event.metadata().level(),
            payload,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{LogFilter, parse_level};

    fn assert_level(input: &str, expected: tracing::Level) {
        assert!(
            matches!(parse_level(input), Some(LogFilter::Level(actual)) if actual == expected),
            "unexpected filter for {input:?}"
        );
    }

    #[test]
    fn parses_level_names_and_aliases_case_insensitively() {
        for (name, expected) in [
            ("trace", tracing::Level::TRACE),
            ("debug", tracing::Level::DEBUG),
            ("info", tracing::Level::INFO),
            ("warn", tracing::Level::WARN),
            ("warning", tracing::Level::WARN),
            ("error", tracing::Level::ERROR),
            ("fatal", tracing::Level::ERROR),
            ("panic", tracing::Level::ERROR),
        ] {
            assert_level(name, expected);
            assert_level(&name.to_ascii_uppercase(), expected);
        }
    }

    #[test]
    fn parses_silent_as_off_case_insensitively() {
        for name in ["silent", "SILENT", "SiLeNt"] {
            assert!(matches!(parse_level(name), Some(LogFilter::Off)));
        }
    }

    #[test]
    fn rejects_unknown_names() {
        for name in ["", "off", "verbose", " warning"] {
            assert!(
                parse_level(name).is_none(),
                "unexpected filter for {name:?}"
            );
        }
    }
}
