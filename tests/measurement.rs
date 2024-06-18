// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

#[cfg(all(target_os = "linux", feature = "snp"))]
mod snp_tests {
    use sev::measurement::{
        snp::*,
        vcpu_types::CpuType,
        vmsa::{GuestFeatures, VMMType},
    };

    // Test if we can compute a full LD from a pre generated hash using snp only kernel
    #[test]
    fn test_snp_ovmf_hash_gen_snp_only() {
        let ovmf_hash = "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74";

        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: Some(ovmf_hash),
            vmm_type: Some(VMMType::QEMU),
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "ddc5224521617a536ee7ce9dd6224d1b58a8d4fda1c741f3ac99fc4bfa04ba6e9fc98646d4a07a9079397fa3852819b5";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test if we can compute a full LD from a pre generated hash using the default kernel setting
    #[test]
    fn test_snp_ovmf_hash_gen_default() {
        let ovmf_hash = "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74";

        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: Some(ovmf_hash),
            vmm_type: Some(VMMType::QEMU),
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "329c8ce0972ae52343b64d34a434a86f245dfd74f5ed7aae15d22efc78fb9683632b9b50e4e1d7fa41179ef98a7ef198";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test if we can compute a full LD from the OVMF hash usin snp only kernel
    #[test]
    fn test_snp_ovmf_hash_full_snp_only() {
        let ovmf_hash = calc_snp_ovmf_hash("./tests/measurement/ovmf_AmdSev_suffix.bin".into())
            .unwrap()
            .get_hex_ld();

        let exp_hash = "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74";

        assert_eq!(ovmf_hash.as_str(), exp_hash);

        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: Some("console=ttyS0 loglevel=7"),
            ovmf_hash_str: Some(ovmf_hash.as_str()),
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "6d287813eb5222d770f75005c664e34c204f385ce832cc2ce7d0d6f354454362f390ef83a92046c042e706363b4b08fa";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test if we can compute a full LD from the OVMF hash using default kernel
    #[test]
    fn test_snp_ovmf_hash_full_default() {
        let ovmf_hash = calc_snp_ovmf_hash("./tests/measurement/ovmf_AmdSev_suffix.bin".into())
            .unwrap()
            .get_hex_ld();

        let exp_hash = "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74";

        assert_eq!(ovmf_hash.as_str(), exp_hash);

        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: Some("console=ttyS0 loglevel=7"),
            ovmf_hash_str: Some(ovmf_hash.as_str()),
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "803f691094946e42068aaa3a8f9e26a5c89f36f7b73ecfb28c653360fe4b3aba7e534442e7e1e17895dfe778d0228977";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test EC2 vmm type with SNP only kernel
    #[test]
    fn test_snp_ec2_snp_only() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: None,
            vmm_type: Some(VMMType::EC2),
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "7d3756157c805bf6adf617064c8552e8c1688fa1c8756f11cbf56ba5d25c9270fb69c0505c1cbe1c5c66c0e34c6ed3be";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test EC2 vmm type with default kernel
    #[test]
    fn test_snp_ec2_default() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: None,
            vmm_type: Some(VMMType::EC2),
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "6ae80856486b1396af8c82a40351d6ed76a20c785e9c7fa4ffa27c22d5d6313b4b3b458cd3c9968e6f89fb5d8450d7a6";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test a regular snp type with snp only kernel
    #[test]
    fn test_sev_snp_only() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: Some("console=ttyS0 loglevel=7"),
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "6d287813eb5222d770f75005c664e34c204f385ce832cc2ce7d0d6f354454362f390ef83a92046c042e706363b4b08fa";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test a regular snp type with default kernel
    #[test]
    fn test_snp_default() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: Some("console=ttyS0 loglevel=7"),
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "803f691094946e42068aaa3a8f9e26a5c89f36f7b73ecfb28c653360fe4b3aba7e534442e7e1e17895dfe778d0228977";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test a regular snp without specified kernel using an snp only guest kernel
    #[test]
    fn test_snp_without_kernel_snp_only() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: None,
            initrd_file: None,
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "19358ba9a7615534a9a1e2f0dfc29384dcd4dcb7062ff9c6013b26869a5fc6ecabe033c48dd6f6db5d6d76e7c5df632d";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test a regular snp without specified kernel using a default guest kernel
    #[test]
    fn test_snp_without_kernel_default() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: None,
            initrd_file: None,
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "e1e1ca029dd7973ab9513295be68198472dcd4fc834bd9af9b63f6e8a1674dbf281a9278a4a2ebe0eed9f22adbcd0e2b";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test snp with multiple cpus with an snp only guest kernel
    #[test]
    fn test_snp_with_multiple_vcpus_snp_only() {
        let arguments = SnpMeasurementArgs {
            vcpus: 4,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "5061fffb019493a903613d56d54b94912a1a2f9e4502385f5c194616753720a92441310ba6c4933de877c36e23046ad5";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test snp with multiple cpus with a default guest kernel
    #[test]
    fn test_snp_with_multiple_vcpus_default() {
        let arguments = SnpMeasurementArgs {
            vcpus: 4,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "4953b1fb416fa874980e8442b3706d345926d5f38879134e00813c5d7abcbe78eafe7b422907be0b4698e2414a631942";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test snp with with ovmf64 and no kernel using a snp only guest kernel
    #[test]
    fn test_snp_with_ovmfx64_without_kernel_snp_only() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_OvmfX64_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: None,
            initrd_file: None,
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "da0296de8193586a5512078dcd719eccecbd87e2b825ad4148c44f665dc87df21e5b49e21523a9ad993afdb6a30b4005";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test snp with with ovmf64 and no kernel using a default guest kernel
    #[test]
    fn test_snp_with_ovmfx64_without_kernel_default() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_OvmfX64_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: None,
            initrd_file: None,
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let exp_result = "28797ae0afaba4005a81e629acebfb59e6687949d6be44007cd5506823b0dd66f146aaae26ff291eed7b493d8a64c385";

        assert_eq!(ld.get_hex_ld().as_str(), exp_result);
    }

    // Test non-SNP OVMF and SNP measure should fail
    #[test]
    #[should_panic(
        expected = "Kernel specified but OVMF metadata doesn't include SNP_KERNEL_HASHES section"
    )]
    fn test_snp_with_ovmfx64_and_kernel_should_fail() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_OvmfX64_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        panic!(
            "{}",
            snp_calc_launch_digest(arguments).unwrap_err().to_string()
        );
    }
}

#[cfg(all(target_os = "linux", feature = "sev"))]
mod sev_tests {
    use sev::measurement::{sev::*, vcpu_types::CpuType};
    // test regular sev-es
    #[test]
    fn test_seves() {
        let arguments = SevEsMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            vmm_type: None,
        };

        let ld = seves_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "13810ae661ea11e2bb205621f582fee268f0367c8f97bc297b7fadef3e12002c";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // test sev-es with multiple vcpus
    #[test]
    fn test_seves_with_multiple_vcpus() {
        let arguments = SevEsMeasurementArgs {
            vcpus: 4,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            vmm_type: None,
        };

        let ld = seves_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "0dccbcaba8e90b261bd0d2e1863a2f9da714768b7b2a19363cd6ae35aa90de91";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test that kernel specified doesn't work with OVMF
    #[test]
    #[should_panic(
        expected = "Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"
    )]
    fn test_seves_with_ovmfx64_and_kernel_should_fail() {
        let arguments = SevEsMeasurementArgs {
            vcpus: 1,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: "./tests/measurement/ovmf_OvmfX64_suffix.bin".into(),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            vmm_type: None,
        };

        panic!(
            "{}",
            seves_calc_launch_digest(arguments).unwrap_err().to_string()
        );
    }

    // test regular sev
    #[test]
    fn test_sev() {
        let arguments = SevMeasurementArgs {
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: Some("console=ttyS0 loglevel=7"),
        };

        let ld = sev_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "82a3ee5d537c3620628270c292ae30cb40c3c878666a7890ee7ef2a08fb535ff";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // test sev kernel with no initrd or append
    #[test]
    fn test_sev_with_kernel_without_initrd_and_append() {
        let arguments = SevMeasurementArgs {
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            kernel_file: Some("/dev/null".into()),
            initrd_file: None,
            append: None,
        };

        let ld = sev_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "77f613d7bbcdf12a73782ea9e88b0172aeda50d1a54201cb903594ff52846898";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // test sev with ovmfx64
    #[test]
    fn test_sev_with_ovmfx64_without_kernel() {
        let arguments = SevMeasurementArgs {
            ovmf_file: "./tests/measurement/ovmf_OvmfX64_suffix.bin".into(),
            kernel_file: None,
            initrd_file: None,
            append: None,
        };

        let ld = sev_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "b4c021e085fb83ceffe6571a3d357b4a98773c83c474e47f76c876708fe316da";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test that kernel specified doesn't work with OVMF
    #[test]
    #[should_panic(
        expected = "Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"
    )]
    fn test_sev_with_ovmfx64_and_kernel_should_fail() {
        let arguments = SevMeasurementArgs {
            ovmf_file: "./tests/measurement/ovmf_OvmfX64_suffix.bin".into(),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
        };

        panic!(
            "{}",
            sev_calc_launch_digest(arguments).unwrap_err().to_string()
        );
    }
}
