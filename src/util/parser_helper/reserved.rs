// SPDX-License-Identifier: Apache-2.0

/// Validates that reserved bytes at a known offset are all zero.
///
/// This function checks that all bytes in the provided slice contain only zeros,
/// which is required by the SNP attestation report specification for reserved fields.
///
/// # Arguments
///
/// * `reserved` - A byte slice containing the reserved bytes to validate
/// * `offset` - The starting offset of the slice in the original buffer (for error messages)
///
/// # Returns
///
/// Returns `Ok(())` if all bytes in the slice are zero, or an `Err` with a descriptive
/// message if any reserved byte is non-zero, including the absolute offset.
///
/// # Errors
///
/// Returns an error if any byte in the slice is non-zero, including the absolute offsets
/// and values of the non-zero bytes.
///
/// # Example
///
/// ```ignore
/// let body = &buffer[0..0x2A0];
/// validate_reserved(&body[0x4C..0x50], 0x4C)?; // Reports absolute offsets 0x4C-0x4F
/// ```
pub fn validate_reserved(reserved: &[u8], offset: usize) -> Result<(), std::io::Error> {
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

        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("reserved bytes are non-zero: {}", details.join(", ")),
        ));
    }

    Ok(())
}
