// SPDX-License-Identifier: Apache-2.0

//! For operating on SEV certificates.

pub(crate) mod cert;
mod chain;

pub use cert::Certificate;
pub use chain::Chain;

use super::*;

/// Denotes the usage of a SEV certificate.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Usage(u32);

impl Usage {
    /// Owner Certificate Authority.
    pub const OCA: Usage = Usage(super::Usage::OCA.0);

    /// Chip Endorsement Key.
    pub const CEK: Usage = Usage(super::Usage::CEK.0);

    /// Platform Endorsement Key.
    pub const PEK: Usage = Usage(super::Usage::PEK.0);

    /// Platform Diffie-Hellman (PDH).
    pub const PDH: Usage = Usage(super::Usage::PDH.0);
}

impl TryFrom<super::Usage> for Usage {
    type Error = ();

    fn try_from(value: super::Usage) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            super::Usage::OCA => Usage::OCA,
            super::Usage::CEK => Usage::CEK,
            super::Usage::PEK => Usage::PEK,
            super::Usage::PDH => Usage::PDH,
            _ => return Err(()),
        })
    }
}

impl From<Usage> for super::Usage {
    fn from(value: Usage) -> Self {
        Self(value.0)
    }
}

impl PartialEq<super::Usage> for Usage {
    fn eq(&self, other: &super::Usage) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<Usage> for super::Usage {
    fn eq(&self, other: &Usage) -> bool {
        self.0 == other.0
    }
}
