// SPDX-License-Identifier: Apache-2.0

//! Reserved-byte validation for firmware wire layouts.
//!
//! AMD specifications require many struct padding regions to be zero. Use
//! [`validate_reserved`] when reserved fields are parsed as raw slices rather
//! than consumed via [`ReadExt::skip_bytes`](super::ReadExt::skip_bytes).

use std::io;

/// Verify that a reserved byte range contains only zeros.
///
/// Checks every byte in `reserved` and reports absolute offsets (base `offset`
/// plus index within the slice) for any non-zero values. Used heavily when
/// parsing SNP attestation report bodies and generation-dependent platform
/// status fields.
///
/// # Arguments
///
/// - `reserved` — byte slice of the reserved region within a larger buffer
/// - `offset` — absolute starting offset of `reserved` in that buffer (for error messages)
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::InvalidData`] listing each non-zero byte as
/// `[0xABS_OFFSET]=0xVALUE`.
///
/// # Example
///
/// ```ignore
/// let body = &buffer[0..0x2A0];
/// validate_reserved(&body[0x4C..0x50], 0x4C)?; // errors cite offsets 0x4C..=0x4F
/// ```
pub fn validate_reserved(reserved: &[u8], offset: usize) -> Result<(), io::Error> {
    // Collect indices and values of non-zero bytes
    let non_zero: Vec<(usize, u8)> = reserved
        .iter()
        .enumerate()
        .filter(|(_, &b)| b != 0)
        .map(|(i, &b)| (offset + i, b))
        .collect();

    if !non_zero.is_empty() {
        // Format the non-zero bytes for the error message with absolute offsets
        let details: Vec<String> = non_zero
            .iter()
            .map(|(idx, val)| format!("[0x{:x}]=0x{:02x}", idx, val))
            .collect();

        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("reserved bytes are non-zero: {}", details.join(", ")),
        ));
    }

    Ok(())
}
