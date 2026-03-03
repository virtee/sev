// SPDX-License-Identifier: Apache-2.0

/// Validates that reserved bytes in a buffer slice are all zero.
///
/// This function checks that all bytes in the provided slice contain only zeros,
/// which is required by the SNP attestation report specification for reserved fields.
///
/// # Arguments
///
/// * `reserved` - A byte slice containing the reserved bytes to validate
///
/// # Returns
///
/// Returns `Ok(())` if all bytes in the slice are zero, or an `Err` with a descriptive
/// message if any reserved byte is non-zero.
///
/// # Errors
///
/// Returns an error if any byte in the slice is non-zero.
///
/// # Example
///
/// ```ignore
/// let body = &buffer[0..0x2A0];
/// validate_reserved(&buffer[0x4C..0x50])?; // Check bytes 0x4C-0x4F
/// validate_reserved(&buffer[0x1EB..0x1EC])?; // Check byte 0x1EB
/// ```
pub fn validate_reserved(reserved: &[u8]) -> Result<(), std::io::Error> {
    // Check that all bytes in the range are zero
    if !reserved.iter().all(|&b| b == 0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "reserved bytes are non-zero",
        ));
    }

    Ok(())
}
