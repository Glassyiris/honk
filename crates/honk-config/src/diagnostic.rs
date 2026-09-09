use tracing::warn;

/// A non-fatal configuration diagnostic, appended as encountered even if loading fails.
/// Plain entry points log diagnostics instead of returning them.
/// Node skips and legacy NFQUEUE migration still print to stderr; an empty vector
/// does not imply a warning-free load.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigDiagnostic {
    pub setting: String,
    /// Safe-to-display input: currently timer strings only, never share links or secrets.
    pub value: String,
    pub message: String,
}

/// Log each diagnostic as a structured warning. The plain entry points call this
/// at parse time; the daemon calls it once its subscriber is installed.
pub fn report_diagnostics(diagnostics: &[ConfigDiagnostic]) {
    for d in diagnostics {
        warn!(setting = %d.setting, value = %d.value, "{}", d.message);
    }
}
