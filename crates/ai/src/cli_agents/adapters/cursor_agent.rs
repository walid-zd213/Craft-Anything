//! Cursor Agent (`agent acp`).

use super::*;

/// Cursor Agent speaks only ACP; the native prompt runner is not offered.
pub struct CursorAgent;

impl AgentAdapter for CursorAgent {
    fn ids(&self) -> &'static [&'static str] {
        &["agent"]
    }

    fn args(&self, _cx: &ArgsCx) -> Vec<String> {
        Vec::new()
    }

    fn requires_acp(&self) -> bool {
        true
    }

    fn plain_fallback(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_not_plain() {
        assert!(AgentAdapters::built_in().for_agent("agent").ids().contains(&"agent"));
        assert!(CursorAgent.requires_acp() && !CursorAgent.plain_fallback());
    }
}
