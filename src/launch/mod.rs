// SPDX-License-Identifier: Apache-2.0

//! Everything one needs to launch an AMD SEV encrypted virtual machine.
//!
//! This module contains types for establishing a secure channel with the
//! AMD Secure Processor for purposes of attestation as well as abstractions
//! for navigating the AMD SEV launch process for a virtual machine.

mod launcher;
#[cfg(target_os = "linux")]
mod linux;

pub use launcher::Launcher;

use super::*;
use bitflags::bitflags;

bitflags! {
    /// Configurable SEV Policy options.
    #[derive(Default)]
    pub struct PolicyFlags: u16 {
        /// When set, debugging the guest is forbidden.
        const NO_DEBUG        = 0b00000001u16.to_le();

        /// When set, sharing keys with other guests is prohibited.
        const NO_KEY_SHARING  = 0b00000010u16.to_le();

        /// When set, SEV-ES protections are required.
        const ENCRYPTED_STATE = 0b00000100u16.to_le();

        /// When set, the guest may not be sent to another platform.
        const NO_SEND         = 0b00001000u16.to_le();

        /// When set, the guest may not be transmitted to a platform
        /// that is outside of the domain.
        const DOMAIN          = 0b00010000u16.to_le();

        /// When set, the guest may not be transmitted to another
        /// platform that is not SEV-capable.
        const SEV             = 0b00100000u16.to_le();
    }
}

/// Describes a policy that the AMD Secure Processor will
/// enforce.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// The various policy optons are encoded as bit flags.
    pub flags: PolicyFlags,

    /// The desired minimum platform firmware version.
    pub minfw: Version,
}

/// A secure channel between the tenant and the AMD Secure
/// Processor.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Session {
    /// Used for deriving a shared secret between the tenant
    /// and the AMD SP.
    pub nonce: [u8; 16],

    /// The TEK and TIK concatenated together and wrapped by
    /// the Key Encryption Key and the Key Integrity Key.
    /// (KIK (KEK (TEK|TIK))).
    pub wrap_tk: [u8; 32],

    /// The initialization vector.
    pub wrap_iv: [u8; 16],

    /// Integrity protection for the wrapped keys (see the
    /// `wrap_tk` field of this struct).
    pub wrap_mac: [u8; 32],

    /// The integrity-protected SEV policy.
    pub policy_mac: [u8; 32],
}

/// Used to establish a secure session with the AMD SP.
#[derive(Debug, PartialEq, Eq)]
pub struct Start {
    /// The tenant's policy for this SEV guest.
    pub policy: Policy,

    /// The tenant's Diffie-Hellman certificate.
    pub cert: certs::sev::Certificate,

    /// A secure channel with the AMD SP.
    pub session: Session,
}

bitflags! {
    /// Additional descriptions of the secret header packet.
    #[derive(Default)]
    pub struct HeaderFlags: u32 {
        /// If set, the contents of the packet are compressed and
        /// the AMD SP must decompress them.
        const COMPRESSED = 0b00000001u32.to_le();
    }
}

/// The header for a data packet that contains secret information
/// to be injected into the guest.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Describes the secret packet (for example: if it is
    /// compressed).
    pub flags: HeaderFlags,

    /// The initialization vector.
    pub iv: [u8; 16],

    /// Integrity protection MAC.
    pub mac: [u8; 32],
}

/// A packet containing secret information to be injected
/// into the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    /// The header for this packet.
    pub header: Header,

    /// The encrypted secret to inject.
    pub ciphertext: Vec<u8>,
}

/// A measurement of the SEV guest.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Measurement {
    /// The measurement.
    pub measure: [u8; 32],

    /// A random nonce.
    pub mnonce: [u8; 16],
}
