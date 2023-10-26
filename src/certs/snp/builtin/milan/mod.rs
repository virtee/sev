// SPDX-License-Identifier: Apache-2.0

use super::*;

/// The public Milan ARK certificate (PEM-encoded).
pub const ARK: &[u8] = include_bytes!("ark.pem");

/// The public Milan ASK certificate (PEM-encoded).
pub const ASK: &[u8] = include_bytes!("ask.pem");

/// Get the Milan ARK Certificate.
pub fn ark() -> Result<Certificate> {
    Certificate::from_pem(ARK)
}

/// Get the Milan ASK Certificate.
pub fn ask() -> Result<Certificate> {
    Certificate::from_pem(ASK)
}

mod tests {
    #[test]
    fn ark_self_signed() {
        use super::*;

        let ark = ark().unwrap();

        (&ark, &ark).verify().unwrap();
    }

    #[test]
    fn ark_signs_ask() {
        use super::*;

        let ark = ark().unwrap();
        let ask = ask().unwrap();

        (&ark, &ask).verify().unwrap();
    }
}
