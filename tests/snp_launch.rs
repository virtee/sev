// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "snp", target_os = "linux"))]

use kvm_bindings::{kvm_create_guest_memfd, kvm_userspace_memory_region2, KVM_MEM_GUEST_MEMFD};
use kvm_ioctls::{Kvm, VcpuExit};
use sev::firmware::{guest::GuestPolicy, host::Firmware};
use sev::launch::{snp::*, PageType};
use std::os::fd::RawFd;
use std::slice::from_raw_parts_mut;

// one page of `hlt
const CODE: &[u8; 4096] = &[
    0xf4; 4096 // hlt
];

const KVM_X86_SNP_VM: u64 = 4;

#[cfg_attr(not(host), ignore)]
#[test]
fn snp_launch_test() {
    let kvm_fd = Kvm::new().unwrap();

    // Create VM-fd with SEV-SNP type
    let vm_fd = kvm_fd.create_vm_with_type(KVM_X86_SNP_VM).unwrap();

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

    // Create KVM guest_memfd struct
    let gmem = kvm_create_guest_memfd {
        size: 0x1000,
        flags: 0,
        reserved: [0; 6],
    };

    // Create KVM guest_memfd
    let fd: RawFd = vm_fd.create_guest_memfd(gmem).unwrap();

    // Create memory region
    let mem_region = kvm_userspace_memory_region2 {
        slot: 0,
        flags: KVM_MEM_GUEST_MEMFD,
        guest_phys_addr: 0x1000_u64,
        memory_size: 0x1000_u64,
        userspace_addr,
        guest_memfd_offset: 0,
        guest_memfd: fd as u32,
        pad1: 0,
        pad2: [0; 14],
    };

    unsafe {
        vm_fd.set_user_memory_region2(mem_region).unwrap();
    };

    let sev = Firmware::open().unwrap();
    let launcher = Launcher::new(vm_fd, sev).unwrap();

    let mut policy = GuestPolicy(0);
    policy.set_smt_allowed(true);
    let start = Start::new(policy, [0; 16]);

    let mut launcher = launcher.start(start).unwrap();

    let update = Update::new(
        mem_region.guest_phys_addr >> 12,
        address_space,
        PageType::Normal,
    );

    launcher
        .update_data(update, mem_region.guest_phys_addr, mem_region.memory_size)
        .unwrap();

    let finish = Finish::new(None, None, [0u8; 32]);

    let mut vcpu_fd = launcher.as_mut().create_vcpu(0).unwrap();

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
