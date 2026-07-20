//! Log streaming support for the clash API `/logs` endpoint.
//!
//! A custom tracing [`Layer`] formats every event into a single-line
//! payload and broadcasts it on a `tokio::sync::broadcast` channel. The
//! layer is installed unconditionally at tracing init (before the config is
//! even loaded), so early startup logs are available to WS subscribers.
//! The channel has a bounded capacity; slow subscribers hit `Lagged` and
//! simply skip ahead (log streaming is best-effort).

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

/// Parse a clash `?level=` query value into a tracing level.
/// Returns `None` for unknown names (the endpoint maps that to a 400).
pub fn parse_level(level: &str) -> Option<tracing::Level> {
    match level.to_ascii_lowercase().as_str() {
        "trace" => Some(tracing::Level::TRACE),
        "debug" => Some(tracing::Level::DEBUG),
        "info" => Some(tracing::Level::INFO),
        "warn" | "warning" => Some(tracing::Level::WARN),
        "error" => Some(tracing::Level::ERROR),
        _ => None,
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
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = EventFields::default();
        event.record(&mut fields);
        let payload = if fields.message.is_empty() {
            format!("{}{}", event.metadata().target(), fields.extra)
        } else {
            format!("{}{}", fields.message, fields.extra)
        };
        // No active receivers (or lagging ones) is fine: log streaming is
        // best-effort and must never block the data path.
        let _ = self.tx.send(LogEvent {
            level: *event.metadata().level(),
            payload,
        });
    }
}
