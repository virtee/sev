// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

#[cfg(all(target_os = "linux", feature = "snp"))]
mod snp_tests {
    use sev::measurement::{
        snp::*,
        vmsa::{GuestFeatures, VMMType},
    };
    // Test if we can compute a full LD from a pre generated hash using snp only kernel
    #[test]
    fn test_snp_ovmf_hash_gen_snp_only() {
        let ovmf_hash = "cab7e085874b3acfdbe2d96dcaa3125111f00c35c6fc9708464c2ae74bfdb048a198cb9a9ccae0b3e5e1a33f5f249819";

        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: Some(ovmf_hash),
            vmm_type: Some(VMMType::QEMU),
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "db06fb267824b1ccb56edbe2a9c2ce88841bca5090dc6dac91d9cd30f3c2c0bf42daccb30d55d6625bfbf0dae5c50c6d";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test if we can compute a full LD from a pre generated hash using the default kernel setting
    #[test]
    fn test_snp_ovmf_hash_gen_default() {
        let ovmf_hash = "cab7e085874b3acfdbe2d96dcaa3125111f00c35c6fc9708464c2ae74bfdb048a198cb9a9ccae0b3e5e1a33f5f249819";

        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: Some(ovmf_hash),
            vmm_type: Some(VMMType::QEMU),
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "a076e1b0e6cf55fd94c82e2c25245f8c15f76690b941ba379b31527f82eafe7ad489777ff510d080bac9cd14d41bc205";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test if we can compute a full LD from the OVMF hash usin snp only kernel
    #[test]
    fn test_snp_ovmf_hash_full_snp_only() {
        let ovmf_hash = hex::encode(
            calc_snp_ovmf_hash("./tests/measurement/ovmf_AmdSev_suffix.bin".into()).unwrap(),
        );

        let exp_hash = "edcf6d1c57ce868a167c990f58c8667c698269ef9e0803246419eea914186343054d557e1f17acd93b032c106bc70d25";

        assert_eq!(ovmf_hash.as_str(), exp_hash);

        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: Some("console=ttyS0 loglevel=7"),
            ovmf_hash_str: Some(ovmf_hash.as_str()),
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "f07864303ad8243132029e8110b92805c78d1135a15da75f67abb9a711d78740347f24ee76f603e650ec4adf3611cc1e";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test if we can compute a full LD from the OVMF hash using default kernel
    #[test]
    fn test_snp_ovmf_hash_full_default() {
        let ovmf_hash = hex::encode(
            calc_snp_ovmf_hash("./tests/measurement/ovmf_AmdSev_suffix.bin".into()).unwrap(),
        );

        let exp_hash = "edcf6d1c57ce868a167c990f58c8667c698269ef9e0803246419eea914186343054d557e1f17acd93b032c106bc70d25";

        assert_eq!(ovmf_hash.as_str(), exp_hash);

        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: Some("console=ttyS0 loglevel=7"),
            ovmf_hash_str: Some(ovmf_hash.as_str()),
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "314e4f0794187ffef05702a36546ea5fe02698041b7f7f17d9f418da2d5e4d5cff25256cef9d34888a0dd64dea438780";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test EC2 vmm type with SNP only kernel
    #[test]
    fn test_snp_ec2_snp_only() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: None,
            vmm_type: Some(VMMType::EC2),
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "760b6e51039d2d6c1fc6d38ca5c387967d158e0294883e4522c36f89bd61bfc9cdb975cd1ceedffbe1b23b1daf4e3f42";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test EC2 vmm type with default kernel
    #[test]
    fn test_snp_ec2_default() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: None,
            vmm_type: Some(VMMType::EC2),
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "cd4a4690a1f679ac8f3d6e446aab8d0061d535cc94615d98c7d7dbe4b16dbceeaf7fc7944e7874b202e27041f179e7e6";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test a regular snp type with snp only kernel
    #[test]
    fn test_snp_snp_only() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: Some("console=ttyS0 loglevel=7"),
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "f07864303ad8243132029e8110b92805c78d1135a15da75f67abb9a711d78740347f24ee76f603e650ec4adf3611cc1e";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test a regular snp type with default kernel
    #[test]
    fn test_snp_default() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: Some("console=ttyS0 loglevel=7"),
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "314e4f0794187ffef05702a36546ea5fe02698041b7f7f17d9f418da2d5e4d5cff25256cef9d34888a0dd64dea438780";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test a regular snp without specified kernel using an snp only guest kernel
    #[test]
    fn test_snp_without_kernel_snp_only() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: None,
            initrd_file: None,
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "e5e6be5a8fa6256f0245666bb237e2d028b7928148ce78d51b8a64dc9506c377709a5b5d7ab75554593bced304fcff93";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test a regular snp without specified kernel using a default guest kernel
    #[test]
    fn test_snp_without_kernel_default() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: None,
            initrd_file: None,
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "6d9054ed9872a64c968cfbcfa1247cafa792e3f9a395306d95c9937aaa081c643d25f369ccbd34409dafcae90bff55f3";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test snp with multiple cpus with an snp only guest kernel
    #[test]
    fn test_snp_with_multiple_vcpus_snp_only() {
        let arguments = SnpMeasurementArgs {
            vcpus: 4,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "1c784beb8c49aa604b7fd57fbc73b36ec53a3f5fb48a2b895ad6cc2ea15d18ee7cc15e3e57c792766b45f944c3e81cfe";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test snp with multiple cpus with a default guest kernel
    #[test]
    fn test_snp_with_multiple_vcpus_default() {
        let arguments = SnpMeasurementArgs {
            vcpus: 4,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "3aa1bdf5a87fad15960f099e82a09e428901c590f2b68d71aa246c168db5e75daf4819d017a9530c56bed2da5c0cdbd7";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test snp with with ovmf64 and no kernel using a snp only guest kernel
    #[test]
    fn test_snp_with_ovmfx64_without_kernel_snp_only() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_OvmfX64_suffix.bin".into(),
            guest_features: GuestFeatures(0x1),
            kernel_file: None,
            initrd_file: None,
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "7ef631fa7f659f7250de96c456a0eb7354bd3b9461982f386a41c6a6aede87870ad020552a5a0716672d5d6e5b86b8f9";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test snp with with ovmf64 and no kernel using a default guest kernel
    #[test]
    fn test_snp_with_ovmfx64_without_kernel_default() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_OvmfX64_suffix.bin".into(),
            guest_features: GuestFeatures(0x21),
            kernel_file: None,
            initrd_file: None,
            append: None,
            ovmf_hash_str: None,
            vmm_type: None,
        };

        let ld = snp_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "37a9efc939f360a9ccfaaf1a7702137b81ea00c38d0361c8523285fad1b10e94ad8c1ecd7c82ff589cb120670be74a99";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test non-SNP OVMF and SNP measure should fail
    #[test]
    #[should_panic(
        expected = "Kernel specified but OVMF metadata doesn't include SNP_KERNEL_HASHES section"
    )]
    fn test_snp_with_ovmfx64_and_kernel_should_fail() {
        let arguments = SnpMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
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
    use sev::measurement::sev::*;
    // test regular sev-es
    #[test]
    fn test_seves() {
        let arguments = SevEsMeasurementArgs {
            vcpus: 1,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            vmm_type: None,
        };

        let ld = seves_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "2e91d54814445ad178180af09f881efe4079fc54bfddd0ec1179ecd3cdbdf772";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // test sev-es with multiple vcpus
    #[test]
    fn test_seves_with_multiple_vcpus() {
        let arguments = SevEsMeasurementArgs {
            vcpus: 4,
            vcpu_type: "EPYC-v4".into(),
            ovmf_file: "./tests/measurement/ovmf_AmdSev_suffix.bin".into(),
            kernel_file: Some("/dev/null".into()),
            initrd_file: Some("/dev/null".into()),
            append: None,
            vmm_type: None,
        };

        let ld = seves_calc_launch_digest(arguments).unwrap();

        let ld_hex = hex::encode(ld);

        let exp_result = "c05d37600072dc5ff24bafc49410f0369ba3a37c130a7bb7055ac6878be300f7";

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
            vcpu_type: "EPYC-v4".into(),
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

        let exp_result = "f0d92a1fda00249e008820bd40def6abbed2ee65fea8a8bc47e532863ca0cc6a";

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

        let exp_result = "7332f6ef294f79919b46302e4541900a2dfc96714e2b7b4b5ccdc1899b78a195";

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

        let exp_result = "af9d6c674b1ff04937084c98c99ca106b25c37b2c9541ac313e6e0c54426314f";

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
