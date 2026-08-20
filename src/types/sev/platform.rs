// SPDX-License-Identifier: Apache-2.0

//! First-generation SEV platform lifecycle state.
//!
//! Returned as part of [`Status`](crate::types::sev::Status) from the shared
//! `PLATFORM_STATUS` ioctl. The platform behaves as a state machine — only
//! certain provisioning actions are valid in each state.

/// Platform lifecycle state from the legacy SEV `PLATFORM_STATUS` ioctl.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// The platform is uninitialized.
    Uninitialized,

    /// The platform is initialized, but not currently managing any
    /// guests.
    Initialized,

    /// The platform is initialized and is overseeing execution
    /// of encrypted guests.
    Working,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            State::Uninitialized => "uninitialized",
            State::Initialized => "initialized",
            State::Working => "working",
        };
        write!(f, "{state}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_display() {
        assert_eq!(State::Uninitialized.to_string(), "uninitialized");
        assert_eq!(State::Initialized.to_string(), "initialized");
        assert_eq!(State::Working.to_string(), "working");
    }

    #[test]
    fn test_state_representation() {
        assert_eq!(State::Uninitialized as u8, 0);
        assert_eq!(State::Initialized as u8, 1);
        assert_eq!(State::Working as u8, 2);
    }

    #[test]
    fn test_state_debug() {
        assert_eq!(format!("{:?}", State::Uninitialized), "Uninitialized");
        assert_eq!(format!("{:?}", State::Initialized), "Initialized");
        assert_eq!(format!("{:?}", State::Working), "Working");
    }

    #[test]
    fn test_state_equality() {
        assert_eq!(State::Uninitialized, State::Uninitialized);
        assert_eq!(State::Initialized, State::Initialized);
        assert_eq!(State::Working, State::Working);

        assert_ne!(State::Uninitialized, State::Initialized);
        assert_ne!(State::Initialized, State::Working);
        assert_ne!(State::Working, State::Uninitialized);
    }
}
