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
        use ::sev::parser::Decoder;

        // https://github.com/enarx/enarx/issues/520
        let naples_cek = sev::Certificate::decode(&mut &naples::CEK[..], ()).unwrap();
        let rome_ask = ca::Certificate::decode(&mut &builtin::rome::ASK[..], ()).unwrap();
        assert!((&rome_ask, &naples_cek).verify().is_err());
    }
}

#[cfg(all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")))]
mod snp {

    use sev::certs::snp::{builtin::milan, ca, Certificate, Chain, Verifiable};
    use sev::parser::ByteParser;

    const TEST_MILAN_VCEK_DER: &[u8] = include_bytes!("certs_data/vcek_milan.der");

    #[cfg(feature = "openssl")]
    const TEST_TURIN_VCEK_DER: &[u8] = include_bytes!("certs_data/vcek_turin.der");

    const TEST_MILAN_ATTESTATION_REPORT: &[u8] = include_bytes!("certs_data/report_milan.hex");

    #[cfg(feature = "openssl")]
    const TEST_MILAN_CA: &[u8] = include_bytes!("certs_data/cert_chain_milan");

    #[cfg(feature = "openssl")]
    const TEST_TURIN_CA: &[u8] = include_bytes!("certs_data/cert_chain_turin");

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
        let report = AttestationReport::from_bytes(report_bytes.as_slice()).unwrap();

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
        report_bytes[21] ^= 0x80;
        let report = AttestationReport::from_bytes(report_bytes.as_slice()).unwrap();

        assert_eq!((&chain, &report).verify().ok(), None);
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn milan_ca_stack() {
        let vcek = Certificate::from_der(TEST_MILAN_VCEK_DER).unwrap();

        let ca = ca::Chain::from_pem_bytes(TEST_MILAN_CA).unwrap();

        let chain = Chain {
            ca,
            vek: vcek.clone(),
        };

        assert_eq!(chain.verify().ok(), Some(&vcek));
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn turin_ca_stack() {
        let vcek = Certificate::from_der(TEST_TURIN_VCEK_DER).unwrap();

        let ca = ca::Chain::from_pem_bytes(TEST_TURIN_CA).unwrap();

        let chain = Chain {
            ca,
            vek: vcek.clone(),
        };

        assert_eq!(chain.verify().ok(), Some(&vcek));
    }
}
