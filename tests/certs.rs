// SPDX-License-Identifier: Apache-2.0

//! Certificate chain integration tests (require attestation role features).

#[cfg(all(
    feature = "sev",
    feature = "crypto-openssl",
    any(
        feature = "evidence",
        feature = "reference",
        feature = "verifier",
        feature = "endorser",
        feature = "attester"
    )
))]
mod naples;

#[cfg(all(
    feature = "sev",
    feature = "crypto-openssl",
    any(
        feature = "evidence",
        feature = "reference",
        feature = "verifier",
        feature = "endorser",
        feature = "attester"
    )
))]
mod rome;

#[cfg(all(
    feature = "snp",
    any(feature = "crypto-openssl", feature = "crypto-rust"),
    any(
        feature = "evidence",
        feature = "reference",
        feature = "verifier",
        feature = "endorser",
        feature = "attester"
    )
))]
mod builtin;

#[cfg(all(
    feature = "crypto-openssl",
    feature = "sev",
    any(
        feature = "evidence",
        feature = "reference",
        feature = "verifier",
        feature = "endorser",
        feature = "attester"
    )
))]
mod sev {
    use super::*;

    #[test]
    fn test_for_verify_false_positive() {
        use ::sev::attestation::endorser::sev::*;
        use ::sev::attestation::verifier::Verifiable;
        use ::sev::parser::Decoder;

        // https://github.com/enarx/enarx/issues/520
        let naples_cek = cert::Certificate::decode(&mut &naples::CEK[..], ()).unwrap();
        let rome_ask = ca::Certificate::decode(&mut &builtin::rome::ASK[..], ()).unwrap();
        assert!((&rome_ask, &naples_cek).verify().is_err());
    }
}

#[cfg(all(
    feature = "snp",
    any(feature = "crypto-openssl", feature = "crypto-rust"),
    any(
        feature = "evidence",
        feature = "reference",
        feature = "verifier",
        feature = "endorser",
        feature = "attester"
    )
))]
mod snp {

    use std::convert::TryFrom;

    use super::builtin::snp::milan;
    use sev::attestation::endorser::snp::{ca::CaChain, Certificate, Chain};
    use sev::attestation::verifier::Verifiable;

    const TEST_MILAN_VCEK_DER: &[u8] = include_bytes!("certs_data/vcek_milan.der");

    #[cfg(feature = "crypto-openssl")]
    const TEST_TURIN_VCEK_DER: &[u8] = include_bytes!("certs_data/vcek_turin.der");

    const TEST_MILAN_ATTESTATION_REPORT: &[u8] = include_bytes!("certs_data/report_milan.hex");

    #[cfg(feature = "crypto-openssl")]
    const TEST_MILAN_CA: &[u8] = include_bytes!("certs_data/cert_chain_milan");

    #[cfg(feature = "crypto-openssl")]
    const TEST_TURIN_CA: &[u8] = include_bytes!("certs_data/cert_chain_turin");

    #[test]
    fn milan_chain() {
        let ark = milan::ark().unwrap();
        let ask = milan::ask().unwrap();
        let vcek = Certificate::from_der(TEST_MILAN_VCEK_DER).unwrap();

        let ca = CaChain { ark, ask };

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

        let ca = CaChain { ark, ask };

        let chain = Chain { ca, vek: vcek };

        assert_eq!(chain.verify().ok(), None);
    }

    #[test]
    fn milan_report() {
        use sev::attestation::{Report, ReportBody};

        let ark = milan::ark().unwrap();
        let ask = milan::ask().unwrap();
        let vcek = Certificate::from_der(TEST_MILAN_VCEK_DER).unwrap();

        let ca = CaChain { ark, ask };

        let chain = Chain { ca, vek: vcek };

        let report_bytes = hex::decode(TEST_MILAN_ATTESTATION_REPORT).unwrap();
        let report = Report::from_bytes(report_bytes.as_slice()).unwrap();
        let _body = ReportBody::try_from((&report, &chain))
            .map_err(|e| {
                println!("report verification failed: {e}");
                e
            })
            .unwrap();
    }

    #[test]
    fn milan_report_invalid() {
        use sev::attestation::{Report, ReportBody};

        let ark = milan::ark().unwrap();
        let ask = milan::ask().unwrap();
        let vcek = Certificate::from_der(TEST_MILAN_VCEK_DER).unwrap();

        let ca = CaChain { ark, ask };

        let chain = Chain { ca, vek: vcek };

        let mut report_bytes = hex::decode(TEST_MILAN_ATTESTATION_REPORT).unwrap();
        report_bytes[21] ^= 0x80;
        let report = Report::from_bytes(report_bytes.as_slice()).unwrap();
        assert!(ReportBody::try_from((&report, &chain)).is_err());
    }

    #[cfg(feature = "crypto-openssl")]
    #[test]
    fn milan_ca_stack() {
        let vcek = Certificate::from_der(TEST_MILAN_VCEK_DER).unwrap();

        let ca = CaChain::from_pem_bytes(TEST_MILAN_CA).unwrap();

        let chain = Chain {
            ca,
            vek: vcek.clone(),
        };

        assert_eq!(chain.verify().ok(), Some(&vcek));
    }

    #[cfg(feature = "crypto-openssl")]
    #[test]
    fn turin_ca_stack() {
        let vcek = Certificate::from_der(TEST_TURIN_VCEK_DER).unwrap();

        let ca = CaChain::from_pem_bytes(TEST_TURIN_CA).unwrap();

        let chain = Chain {
            ca,
            vek: vcek.clone(),
        };

        assert_eq!(chain.verify().ok(), Some(&vcek));
    }
}
