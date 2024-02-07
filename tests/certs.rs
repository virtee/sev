// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "sev")]
mod naples;

#[cfg(feature = "sev")]
mod rome;

#[cfg(all(feature = "openssl", feature = "sev"))]
mod sev {
    use super::*;

    #[test]
    fn test_for_verify_false_positive() {
        use ::sev::certs::sev::*;
        use codicon::Decoder;

        // https://github.com/enarx/enarx/issues/520
        let naples_cek = sev::Certificate::decode(&mut &naples::CEK[..], ()).unwrap();
        let rome_ask = ca::Certificate::decode(&mut &builtin::rome::ASK[..], ()).unwrap();
        assert!((&rome_ask, &naples_cek).verify().is_err());
    }
}

#[cfg(all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")))]
mod snp {
    use sev::certs::snp::{builtin::milan, ca, Certificate, Chain, Verifiable};

    const TEST_MILAN_VCEK_DER: &[u8] = include_bytes!("certs_data/vcek_milan.der");

    const TEST_MILAN_ATTESTATION_REPORT: &[u8] = include_bytes!("certs_data/report_milan.hex");

    #[test]
    fn milan_chain() {
        let ark = milan::ark().unwrap();
        let ask = milan::ask().unwrap();
        let vcek = Certificate::from_der(TEST_MILAN_VCEK_DER).unwrap();

        let ca = ca::Chain { ark, ask };

        let chain = Chain {
            ca,
            vek: vcek.clone(),
        };

        assert_eq!(chain.verify().ok(), Some(&vcek));
    }

    #[test]
    fn milan_chain_invalid() {
        let ark = milan::ark().unwrap();
        let ask = milan::ask().unwrap();
        let vcek = {
            let mut buf = TEST_MILAN_VCEK_DER.to_vec();
            buf[40] ^= 0xff;
            Certificate::from_der(&buf).unwrap()
        };

        let ca = ca::Chain { ark, ask };

        let chain = Chain { ca, vek: vcek };

        assert_eq!(chain.verify().ok(), None);
    }

    #[test]
    fn milan_report() {
        use sev::firmware::guest::AttestationReport;

        let ark = milan::ark().unwrap();
        let ask = milan::ask().unwrap();
        let vcek = Certificate::from_der(TEST_MILAN_VCEK_DER).unwrap();

        let ca = ca::Chain { ark, ask };

        let chain = Chain { ca, vek: vcek };

        let report_bytes = hex::decode(TEST_MILAN_ATTESTATION_REPORT).unwrap();
        let report: AttestationReport =
            unsafe { std::ptr::read(report_bytes.as_ptr() as *const _) };

        assert_eq!((&chain, &report).verify().ok(), Some(()));
    }

    #[test]
    fn milan_report_invalid() {
        use sev::firmware::guest::AttestationReport;

        let ark = milan::ark().unwrap();
        let ask = milan::ask().unwrap();
        let vcek = Certificate::from_der(TEST_MILAN_VCEK_DER).unwrap();

        let ca = ca::Chain { ark, ask };

        let chain = Chain { ca, vek: vcek };

        let mut report_bytes = hex::decode(TEST_MILAN_ATTESTATION_REPORT).unwrap();
        report_bytes[0] ^= 0x80;
        let report: AttestationReport =
            unsafe { std::ptr::read(report_bytes.as_ptr() as *const _) };

        assert_eq!((&chain, &report).verify().ok(), None);
    }
}
