// SPDX-License-Identifier: Apache-2.0

//! Host-side CPUID helpers for identifying the local EPYC generation.
//!
//! AMD platform ioctls such as [`crate::platform::Firmware::snp_platform_status`]
//! require an explicit [`Generation`](crate::types::shared::Generation)
//! parameter. This module provides a convenience helper to derive that value from
//! the host CPU, but platform APIs do **not** call it automatically — callers
//! choose when CPU identification is appropriate.

use crate::types::shared::Generation;

use std::convert::TryInto;

/// Identify the EPYC processor generation from the CPUID instruction.
///
/// Reads leaf `0x8000_0001` and interprets bytes 2–3 of `EAX` as the generation
/// identifier defined in the AMD SNP firmware specification.
///
/// # Platform
///
/// Compiled only for Linux x86_64. Returns [`std::io::Error`] if the CPUID
/// bytes do not map to a known [`Generation`].
///
/// # Usage
///
/// Pass the result to SNP platform status ioctls when the host CPU generation
/// is needed to decode firmware-specific status fields.
pub(crate) fn identify_host_generation() -> Result<Generation, std::io::Error> {
    unsafe { std::arch::x86_64::__cpuid(0x8000_0001) }
        .eax
        .to_le_bytes()
        .as_slice()
        .try_into()
}
