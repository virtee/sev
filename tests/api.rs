// SPDX-License-Identifier: Apache-2.0

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

mod snp {
    use sev::firmware::host::{
        CertTableEntry, CertType, Config, ExtConfig, Firmware, SnpPlatformStatus, TcbVersion,
    };

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

    fn build_ext_config(cert: bool, cfg: bool) -> ExtConfig {
        let test_cfg: Config = Config::new(TcbVersion::new(1, 0, 1, 1), 31);

        let cert_table: Vec<CertTableEntry> = vec![
            CertTableEntry::new(CertType::ARK, vec![1; 28]),
            CertTableEntry::new(CertType::ASK, vec![1; 28]),
        ];

        match (cert, cfg) {
            (true, true) => ExtConfig::new(test_cfg, cert_table),
            (true, false) => ExtConfig::new_certs_only(cert_table),
            (false, true) => ExtConfig::new_config_only(test_cfg),
            (false, false) => ExtConfig::default(),
        }
    }

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn snp_snp_set_ext_config_std() {
        let mut fw: Firmware = Firmware::open().unwrap();
        let new_config: ExtConfig = build_ext_config(true, true);
        fw.snp_set_ext_config(new_config).unwrap();
        fw.snp_reset_config().unwrap();
    }

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn snp_snp_set_ext_config_certs_only() {
        let mut fw: Firmware = Firmware::open().unwrap();
        let new_config: ExtConfig = build_ext_config(true, false);
        fw.snp_set_ext_config(new_config).unwrap();
        fw.snp_reset_config().unwrap();
    }

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn snp_snp_set_ext_config_cfg_only() {
        let mut fw: Firmware = Firmware::open().unwrap();
        let new_config: ExtConfig = build_ext_config(false, true);
        fw.snp_set_ext_config(new_config).unwrap();
        fw.snp_reset_config().unwrap();
    }

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn snp_snp_set_ext_invalid_config_std() {
        let mut fw: Firmware = Firmware::open().unwrap();
        let platform_status: SnpPlatformStatus = fw.snp_platform_status().unwrap();

        // Using Current TCB as Committed TCB is not available at the moment,
        // but ideally we would like to check Reported TCB <= Committed TCB, only.
        let mut invalid_tcb: TcbVersion = platform_status.platform_tcb_version;
        invalid_tcb.snp += 1;
        fw.snp_set_ext_config(ExtConfig::new_config_only(Config::new(invalid_tcb, 0)))
            .unwrap();
        fw.snp_reset_config().unwrap();
    }

    #[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
    #[test]
    #[serial]
    fn snp_snp_get_ext_config_std() {
        let mut fw: Firmware = Firmware::open().unwrap();
        let hw_config: ExtConfig = fw.snp_get_ext_config().unwrap();
        println!("{:?}", hw_config);
    }
}
