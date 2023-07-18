// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "snp")]
use std::slice::from_raw_parts_mut;

#[cfg(feature = "snp")]
use sev::firmware::host::Firmware;

#[cfg(feature = "snp")]
use sev::launch::snp::*;

#[cfg(feature = "snp")]
use kvm_bindings::kvm_userspace_memory_region;

#[cfg(feature = "snp")]
use kvm_ioctls::{Kvm, VcpuExit};

// one page of `hlt`
#[cfg(feature = "snp")]
const CODE: &[u8; 4096] = &[
    0xf4; 4096 // hlt
];

#[cfg(feature = "snp")]
#[cfg_attr(not(has_sev), ignore)]
#[test]
fn snp() {
    let kvm_fd = Kvm::new().unwrap();
    let vm_fd = kvm_fd.create_vm().unwrap();

    const MEM_ADDR: u64 = 0x1000;

    // Allocate a 1kB page of memory for the address space of the VM.
    let address_space = unsafe { libc::mmap(0 as _, CODE.len(), 3, 34, -1, 0) };

    if address_space == libc::MAP_FAILED {
        panic!("mmap() failed");
    }

    let address_space: &mut [u8] =
        unsafe { from_raw_parts_mut(address_space as *mut u8, CODE.len()) };

    address_space[..CODE.len()].copy_from_slice(&CODE[..]);

    let userspace_addr = address_space as *const [u8] as *const u8 as u64;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: MEM_ADDR,
        memory_size: CODE.len() as _,
        userspace_addr,
        flags: 0,
    };

    unsafe {
        vm_fd.set_user_memory_region(mem_region).unwrap();
    }

    let sev = Firmware::open().unwrap();
    let launcher = Launcher::new(vm_fd, sev).unwrap();

    let start = Start::new(
        None,
        Policy {
            flags: PolicyFlags::SMT,
            ..Default::default()
        },
        false,
        [0; 16],
    );

    let mut launcher = launcher.start(start).unwrap();

    // If VMPL is not enabled, perms must be zero
    let dp = VmplPerms::empty();

    let update = Update::new(
        mem_region.guest_phys_addr >> 12,
        address_space.as_ref(),
        false,
        PageType::Normal,
        (dp, dp, dp),
    );

    launcher.update_data(update).unwrap();

    let finish = Finish::new(None, None, [0u8; 32]);

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
