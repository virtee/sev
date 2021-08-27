// SPDX-License-Identifier: Apache-2.0

use sev::firmware::Firmware;
use sev::launch::*;
use sev::Version;

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::Kvm;
use mmarinus::{perms, Kind, Map};

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[test]
fn snp() {
    let mut sev = Firmware::open().unwrap();

    let kvm = Kvm::new().unwrap();
    let mut vm = kvm.create_vm().unwrap();

    let status = sev.snp_platform_status().unwrap();

    const MEM_SIZE: usize = 0x1000;
    let address_space = Map::map(MEM_SIZE)
        .anywhere()
        .anonymously()
        .known::<perms::ReadWrite>(Kind::Private)
        .unwrap();

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: address_space.size() as _,
        userspace_addr: address_space.addr() as _,
        flags: 0,
    };

    unsafe {
        vm.set_user_memory_region(mem_region).unwrap();
    }

    let launcher = Launcher::snp_new(&mut vm, &mut sev).unwrap();

    let x: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let policy = SnpPolicy {
        flags: SnpPolicyFlags::SMT,
        minfw: Version {
            major: status.build.version.major,
            minor: status.build.version.minor,
        },
    };

    let start = SnpStart::new(Some(address_space.as_ref()), policy, false, x);

    let mut launcher = launcher.snp_start(start).unwrap();

    let dp = VmplPerms::default();
    let update = SnpUpdate::new(
        address_space.as_ref(),
        false,
        SnpPageType::Normal,
        (dp, dp, dp),
    );

    launcher.snp_update_data(update).unwrap();

    let hd: [u8; 32] = [0; 32];

    let finish = SnpFinish::new(None, None, hd);

    launcher.snp_finish(finish).unwrap();
}
