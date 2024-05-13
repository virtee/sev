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
        let ovmf_hash = "cab7e085874b3acfdbe2d96dcaa3125111f00c35c6fc9708464c2ae74bfdb048a198cb9a9ccae0b3e5e1a33f5f249819";

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

        let ld_hex = hex::encode(ld);

        let exp_result = "3c018b826531c5f625f10004d51ee51ab5dbfaf1fdd79998ab649cff11b4afbdb2f50941d2a23b5d77fe00cf988242e7";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test if we can compute a full LD from a pre generated hash using the default kernel setting
    #[test]
    fn test_snp_ovmf_hash_gen_default() {
        let ovmf_hash = "cab7e085874b3acfdbe2d96dcaa3125111f00c35c6fc9708464c2ae74bfdb048a198cb9a9ccae0b3e5e1a33f5f249819";

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

        let ld_hex = hex::encode(ld);

        let exp_result = "aa6f24465c304e3ad553a18069510996fc92a84f48ae2140cb95dfbd422cdb14087588fb6eec89ef0a65e6d376d9a300";

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

        let ld_hex = hex::encode(ld);

        let exp_result = "72b3f3c1ed0df9e5279eb2317a9861be3b878537e8513b318b49c1e184f6228e3ff367d133a8688f430e412ba66f558f";

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

        let ld_hex = hex::encode(ld);

        let exp_result = "2b9ca4d24c46845280fdca6f0ca0edf0f704bf179243e5c1b139acf3668ce7bc040e12d16b2ee8738aeaa39faddc8912";

        assert_eq!(ld_hex.as_str(), exp_result);
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

        let ld_hex = hex::encode(ld);

        let exp_result = "760b6e51039d2d6c1fc6d38ca5c387967d158e0294883e4522c36f89bd61bfc9cdb975cd1ceedffbe1b23b1daf4e3f42";

        assert_eq!(ld_hex.as_str(), exp_result);
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

        let ld_hex = hex::encode(ld);

        let exp_result = "cd4a4690a1f679ac8f3d6e446aab8d0061d535cc94615d98c7d7dbe4b16dbceeaf7fc7944e7874b202e27041f179e7e6";

        assert_eq!(ld_hex.as_str(), exp_result);
    }

    // Test a regular snp type with snp only kernel
    #[test]
    fn test_snp_snp_only() {
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

        let ld_hex = hex::encode(ld);

        let exp_result = "72b3f3c1ed0df9e5279eb2317a9861be3b878537e8513b318b49c1e184f6228e3ff367d133a8688f430e412ba66f558f";

        assert_eq!(ld_hex.as_str(), exp_result);
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

        let ld_hex = hex::encode(ld);

        let exp_result = "2b9ca4d24c46845280fdca6f0ca0edf0f704bf179243e5c1b139acf3668ce7bc040e12d16b2ee8738aeaa39faddc8912";

        assert_eq!(ld_hex.as_str(), exp_result);
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

        let ld_hex = hex::encode(ld);

        let exp_result = "c4ee889e2ca38dc7137f5a448c56960a1eb5c08919fd2107a1249eb899afda42be9ba11e417530938cfa8d62a5890557";

        assert_eq!(ld_hex.as_str(), exp_result);
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

        let ld_hex = hex::encode(ld);

        let exp_result = "d35ca073e73701aa476d9d1b2feeee9efd935b7ec9dc43a0105857f506addb48ba3a1d443e5c10db430ad1a436ac5b2c";

        assert_eq!(ld_hex.as_str(), exp_result);
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

        let ld_hex = hex::encode(ld);

        let exp_result = "74b2f532253c8214df9998ba8df305aa98eb1733c0010014c5ed728b8d1a9fa83df0a0caf047e9cee14087cc79bbc7c9";

        assert_eq!(ld_hex.as_str(), exp_result);
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

        let ld_hex = hex::encode(ld);

        let exp_result = "6258fc4d3c60d6964de64811587a903f309b9391efdccd448bb8bc39b78c1d153378077ca37e32d06d6ead319a5c7bce";

        assert_eq!(ld_hex.as_str(), exp_result);
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

        let ld_hex = hex::encode(ld);

        let exp_result = "6ea57de00ffc6f159c6b799f9c053cd165a021efed1614678b1a0ae24c6b0374387f52ace64e0fbc08d1129a857a0b0c";

        assert_eq!(ld_hex.as_str(), exp_result);
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

        let ld_hex = hex::encode(ld);

        let exp_result = "7b30bdd3f3124ccfceaa882f4b3ab2ff3641bb421bb9bc6df6b9be0d8ecde33e6fba86505808ab5257e3e620a2006e53";

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

        let exp_result = "c9c378be09902e3d5927a93b73ed383620eea5387e1d16416807cfc949b7f834";

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

        let exp_result = "2806971adf7a9d5bdef59d007f0200af685dec6721781fe1d6efa9236b3361f1";

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
