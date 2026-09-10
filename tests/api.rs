// SPDX-License-Identifier: Apache-2.0

#[cfg(all(
    feature = "sev",
    feature = "platform",
    feature = "endorser",
    feature = "verifier",
    target_os = "linux"
))]
mod sev {
    #[cfg(feature = "dangerous_hw_tests")]
    use serial_test::serial;
    #[cfg(feature = "dangerous_hw_tests")]
    use sev::cached_chain;
    use sev::{
        attestation::endorser::sev::cert::Usage, platform::Firmware, types::shared::FirmwareVersion,
    };

    #[cfg(feature = "dangerous_hw_tests")]
    #[cfg_attr(not(host), ignore)]
    #[test]
    #[serial]
    fn platform_reset() {
        let mut fw = Firmware::open().unwrap();
        fw.platform_reset().unwrap();
        cached_chain::rm_cached_chain();
    }

    #[cfg_attr(not(host), ignore)]
    #[test]
    fn platform_status() {
        let mut fw = Firmware::open().unwrap();
        let status = fw.platform_status().unwrap();
        assert!(status.firmware_version > FirmwareVersion::new(0, 14, 0));
    }

    #[cfg(feature = "dangerous_hw_tests")]
    #[cfg_attr(not(host), ignore)]
    #[test]
    #[serial]
    fn pek_generate() {
        let mut fw = Firmware::open().unwrap();
        fw.pek_generate().unwrap();
        cached_chain::rm_cached_chain();
    }

    #[cfg_attr(not(host), ignore)]
    #[test]
    fn pek_csr() {
        let mut fw = Firmware::open().unwrap();
        let pek = fw.pek_csr().unwrap();
        assert_eq!(pek, Usage::PEK);
    }

    #[cfg(feature = "dangerous_hw_tests")]
    #[cfg_attr(not(host), ignore)]
    #[test]
    #[serial]
    fn pdh_generate() {
        let mut fw = Firmware::open().unwrap();
        fw.pdh_generate().unwrap();
        cached_chain::rm_cached_chain();
    }

    #[cfg(feature = "crypto-openssl")]
    #[cfg_attr(not(host), ignore)]
    #[test]
    fn pdh_cert_export() {
        use sev::attestation::verifier::Verifiable;

        let mut fw = Firmware::open().unwrap();
        let chain = fw.pdh_cert_export().unwrap();

        assert_eq!(chain.pdh, Usage::PDH);
        assert_eq!(chain.pek, Usage::PEK);
        assert_eq!(chain.oca, Usage::OCA);
        assert_eq!(chain.cek, Usage::CEK);

        chain.verify().unwrap();
    }

    #[cfg(all(feature = "crypto-openssl", feature = "dangerous_hw_tests"))]
    #[cfg_attr(not(host), ignore)]
    #[test]
    #[serial]
    fn pek_cert_import() {
        use sev::attestation::endorser::sev::{cert::Certificate, Signer};
        use sev::attestation::verifier::Verifiable;

        let mut fw = Firmware::open().unwrap();

        let (mut oca, key) = Certificate::generate(Usage::OCA).unwrap();
        key.sign(&mut oca).unwrap();

        let mut pek = fw.pek_csr().unwrap();
        key.sign(&mut pek).unwrap();

        fw.pek_cert_import(&pek, &oca).unwrap();

        let chain = fw.pdh_cert_export().unwrap();
        assert_eq!(oca, chain.oca);
        chain.verify().unwrap();

        fw.platform_reset().unwrap();
    }

    #[cfg_attr(not(host), ignore)]
    #[test]
    fn get_identifier() {
        let mut fw = Firmware::open().unwrap();
        let id = fw.get_identifier().unwrap();
        assert_ne!(Vec::from(id), vec![0u8; 64]);
    }
}

#[cfg(all(feature = "snp", feature = "platform", target_os = "linux"))]
mod snp {
    use serial_test::serial;
    use sev::platform::{
        snp::{Config, MaskId, SnpPlatformStatus, TcbVersion},
        Firmware,
    };
    use sev::types::shared::Generation;

    fn host_generation() -> Generation {
        #[cfg(all(target_arch = "x86_64", feature = "snp"))]
        {
            Generation::identify_host_generation().expect("host CPUID")
        }
        #[cfg(not(all(target_arch = "x86_64", feature = "snp")))]
        {
            Generation::Milan
        }
    }

    #[cfg_attr(not(host), ignore)]
    #[test]
    fn get_identifier() {
        let mut fw = Firmware::open().unwrap();
        let id = fw.get_identifier().unwrap();
        assert_ne!(Vec::from(id), vec![0u8; 64]);
    }

    #[cfg_attr(not(host), ignore)]
    #[test]
    fn platform_status() {
        let mut fw: Firmware = Firmware::open().unwrap();
        let status: SnpPlatformStatus = fw.snp_platform_status(host_generation()).unwrap();

        println!(
            "Platform status ioctl results:
              version (major, minor): {}.{}
              build id: {}
              guests: {}
              platform tcb microcode version: {}
              platform tcb snp version: {}
              platform tcb tee version: {}
              platform tcb bootloader version: {}
              reported tcb microcode version: {}
              reported tcb snp version: {}
              reported tcb tee version: {}
              reported tcb bootloader version: {}
              state: {}",
            status.version.0,
            status.version.1,
            status.build_id,
            status.guest_count,
            status.platform_tcb_version.microcode,
            status.platform_tcb_version.snp,
            status.platform_tcb_version.tee,
            status.platform_tcb_version.bootloader,
            status.reported_tcb_version.microcode,
            status.reported_tcb_version.snp,
            status.reported_tcb_version.tee,
            status.reported_tcb_version.bootloader,
            status.state
        );
    }

    #[cfg_attr(not(all(host, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn commit_snp() {
        let mut fw: Firmware = Firmware::open().unwrap();
        fw.snp_commit().unwrap();
    }

    #[cfg_attr(not(all(host, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn set_config_generation() {
        let mut fw: Firmware = Firmware::open().unwrap();

        fw.snp_set_config(Config::default(), host_generation())
            .unwrap();
    }

    #[cfg_attr(not(all(host, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn test_host_fw_error() {
        let mut fw: Firmware = Firmware::open().unwrap();
        let invalid_config = Config::new(TcbVersion::new(None, 100, 100, 100, 100), MaskId(31));
        let fw_error = fw
            .snp_set_config(invalid_config, host_generation())
            .unwrap_err()
            .to_string();
        assert_eq!(fw_error, "Firmware Error Encountered: Known SEV FW Error: Status Code: 0x16: Given parameter is invalid.")
    }
}
