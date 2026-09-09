use tracing::warn;

/// A non-fatal configuration diagnostic, appended as encountered even if loading fails.
/// Plain entry points log diagnostics instead of returning them.
/// Node skips and legacy NFQUEUE migration still print to stderr; an empty vector
/// does not imply a warning-free load.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigDiagnostic {
    pub setting: String,
    /// Scalar diagnostics retain the parsed scalar text, including anything typed there.
    /// Filter and policy expressions are never echoed: filters use a node-filter ordinal,
    /// and policies use an empty value.
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
