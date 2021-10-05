// SPDX-License-Identifier: Apache-2.0

use sev::firmware::Firmware;
use sev::launch::snp::*;

pub use kvm_bindings::kvm_segment as KvmSegment;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuExit};
use mmarinus::{perms, Kind, Map};

// one page of `hlt`
const CODE: &[u8; 4096] = &[
    0xf4; 4096 // hlt
];

#[cfg_attr(not(has_sev), ignore)]
#[test]
fn snp() {
    let kvm_fd = Kvm::new().unwrap();
    let vm_fd = kvm_fd.create_vm().unwrap();

    const MEM_ADDR: u64 = 0x1000;

    let mut address_space = Map::map(CODE.len())
        .anywhere()
        .anonymously()
        .known::<perms::ReadWrite>(Kind::Private)
        .unwrap();

    address_space[..CODE.len()].copy_from_slice(&CODE[..]);

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: MEM_ADDR,
        memory_size: address_space.size() as _,
        userspace_addr: address_space.addr() as _,
        flags: 0,
    };

    unsafe {
        vm_fd.set_user_memory_region(mem_region).unwrap();
    }

    let sev = Firmware::open().unwrap();
    let launcher = Launcher::new(vm_fd, sev).unwrap();

    let start = SnpStart {
        policy: SnpPolicy {
            flags: SnpPolicyFlags::SMT,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut launcher = launcher.start(start).unwrap();

    // If VMPL is not enabled, perms must be zero
    let dp = VmplPerms::empty();

    let update = SnpUpdate::new(
        mem_region.guest_phys_addr >> 12,
        address_space.as_ref(),
        false,
        SnpPageType::Normal,
        (dp, dp, dp),
    );

    launcher.update_data(update).unwrap();

    let finish = SnpFinish::new(None, None, [0u8; 32]);

    let vcpu_fd = launcher.as_mut().create_vcpu(0).unwrap();

    let mut regs = vcpu_fd.get_regs().unwrap();
    regs.rip = MEM_ADDR;
    regs.rflags = 2;
    vcpu_fd.set_regs(&regs).unwrap();

    let mut sregs = vcpu_fd.get_sregs().unwrap();
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu_fd.set_sregs(&sregs).unwrap();

    let (_vm_fd, _sev) = launcher.finish(finish).unwrap();

    let ret = vcpu_fd.run();

    assert!(matches!(ret, Ok(VcpuExit::Hlt)));
}
