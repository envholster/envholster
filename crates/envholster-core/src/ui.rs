//! UnlockUi / WrapContext — the frozen callback seam (plan/04-contracts §4.3, c4).
//!
//! `age::Callbacks` is `Clone + Send + Sync + 'static` — not dyn-compatible.
//! The seam is a dyn-compatible trait plus a cloneable adapter; `Vault` never
//! stores callbacks. age callbacks are synchronous — the P1 daemon calls
//! unlock on `spawn_blocking` and bridges to envholster-agent over a channel
//! (plan/05-daemon).

use std::sync::Arc;

use secrecy::SecretString;

/// Dyn-compatible unlock-interaction surface.
pub trait UnlockUi: Send + Sync {
    fn message(&self, message: &str);
    fn confirm(&self, message: &str, yes: &str, no: Option<&str>) -> Option<bool>;
    fn input(&self, description: &str) -> Option<String>;
    fn secret(&self, description: &str) -> Option<SecretString>;
}

/// Cloneable adapter satisfying `age::Callbacks` by 1:1 delegation.
#[derive(Clone)]
pub struct AgeCallbackAdapter(pub Arc<dyn UnlockUi>);

impl age::Callbacks for AgeCallbackAdapter {
    fn display_message(&self, message: &str) {
        self.0.message(message);
    }

    fn confirm(&self, message: &str, yes_string: &str, no_string: Option<&str>) -> Option<bool> {
        self.0.confirm(message, yes_string, no_string)
    }

    fn request_public_string(&self, description: &str) -> Option<String> {
        self.0.input(description)
    }

    fn request_passphrase(&self, description: &str) -> Option<SecretString> {
        self.0.secret(description)
    }
}

/// Carries the interaction surface through wrap/unwrap operations.
#[derive(Clone)]
pub struct WrapContext {
    pub ui: Arc<dyn UnlockUi>,
}

impl WrapContext {
    pub fn new(ui: Arc<dyn UnlockUi>) -> Self {
        WrapContext { ui }
    }

    /// Encrypt-side default: plugin wraps need no interaction; prompts return
    /// `None`.
    pub fn silent() -> Self {
        WrapContext {
            ui: Arc::new(SilentUi),
        }
    }
}

/// Non-interactive `UnlockUi`: messages dropped, prompts answered `None`.
struct SilentUi;

impl UnlockUi for SilentUi {
    fn message(&self, _message: &str) {}

    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    fn input(&self, _description: &str) -> Option<String> {
        None
    }

    fn secret(&self, _description: &str) -> Option<SecretString> {
        None
    }
}
