// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "sev")]
mod sev {
    use sev::cached_chain;
    use sev::{certs::sev::sev::Usage, firmware::host::Firmware, Build, Version};

    use serial_test::serial;

    #[inline(always)]
    fn rm_cached_chain() {
        let paths = cached_chain::path();
        if let Some(path) = paths.first() {
            if path.exists() {
                std::fs::remove_file(path).unwrap();
            }
        }
    }

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn platform_reset() {
        let mut fw = Firmware::open().unwrap();
        fw.platform_reset().unwrap();
        rm_cached_chain();
    }

    #[cfg_attr(not(has_sev), ignore)]
    #[test]
    fn platform_status() {
        let mut fw = Firmware::open().unwrap();
        let status = fw.platform_status().unwrap();
        assert!(
            status.build
                > Build {
                    version: Version {
                        major: 0,
                        minor: 14
                    },
                    ..Default::default()
                }
        );
    }

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn pek_generate() {
        let mut fw = Firmware::open().unwrap();
        fw.pek_generate().unwrap();
        rm_cached_chain();
    }

    #[cfg_attr(not(has_sev), ignore)]
    #[test]
    fn pek_csr() {
        let mut fw = Firmware::open().unwrap();
        let pek = fw.pek_csr().unwrap();
        assert_eq!(pek, Usage::PEK);
    }

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn pdh_generate() {
        let mut fw = Firmware::open().unwrap();
        fw.pdh_generate().unwrap();
        rm_cached_chain();
    }

    #[cfg_attr(not(has_sev), ignore)]
    #[cfg(feature = "openssl")]
    #[test]
    fn pdh_cert_export() {
        use sev::certs::sev::Verifiable;

        let mut fw = Firmware::open().unwrap();
        let chain = fw.pdh_cert_export().unwrap();

        assert_eq!(chain.pdh, Usage::PDH);
        assert_eq!(chain.pek, Usage::PEK);
        assert_eq!(chain.oca, Usage::OCA);
        assert_eq!(chain.cek, Usage::CEK);

        chain.verify().unwrap();
    }

    #[cfg(feature = "openssl")]
    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn pek_cert_import() {
        use sev::certs::sev::{sev::Certificate, Signer, Verifiable};

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

    #[cfg_attr(not(has_sev), ignore)]
    #[test]
    fn get_identifier() {
        let mut fw = Firmware::open().unwrap();
        let id = fw.get_identifier().unwrap();
        assert_ne!(Vec::from(id), vec![0u8; 64]);
    }
}

#[cfg(feature = "snp")]
mod snp {
    use sev::firmware::host::{Config, Firmware, SnpPlatformStatus, TcbVersion};

    use serial_test::serial;

    #[cfg_attr(not(has_sev), ignore)]
    #[test]
    fn get_identifier() {
        let mut fw = Firmware::open().unwrap();
        let id = fw.get_identifier().unwrap();
        assert_ne!(Vec::from(id), vec![0u8; 64]);
    }

    #[cfg_attr(not(has_sev), ignore)]
    #[test]
    fn platform_status() {
        let mut fw: Firmware = Firmware::open().unwrap();
        let status: SnpPlatformStatus = fw.snp_platform_status().unwrap();

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
            status.version.major,
            status.version.minor,
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

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn commit_snp() {
        let mut fw: Firmware = Firmware::open().unwrap();
        fw.snp_commit().unwrap();
    }

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn set_config() {
        let mut fw: Firmware = Firmware::open().unwrap();
        let new_config = Config::new(TcbVersion::new(1, 0, 1, 1), 31);
        fw.snp_set_config(new_config).unwrap();
    }
}
